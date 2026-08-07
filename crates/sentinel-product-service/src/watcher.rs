use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy)]
pub enum WatchProfile {
    Downloads,
    PersistenceMacos,
}
pub fn roots(profile: WatchProfile) -> Vec<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    match profile {
        WatchProfile::Downloads => vec![home.join("Downloads")],
        WatchProfile::PersistenceMacos => vec![
            home.join("Library/LaunchAgents"),
            PathBuf::from("/Library/LaunchAgents"),
            PathBuf::from("/Library/LaunchDaemons"),
        ],
    }
}

pub struct FileWatcher {
    _watcher: RecommendedWatcher,
    events: Receiver<notify::Result<Event>>,
}
impl FileWatcher {
    pub fn start(profile: WatchProfile) -> notify::Result<Self> {
        Self::start_root(
            roots(profile)
                .into_iter()
                .find(|p| p.is_dir())
                .unwrap_or_else(|| PathBuf::from(".")),
        )
    }
    pub fn start_root(root: PathBuf) -> notify::Result<Self> {
        let (sender, events) = mpsc::sync_channel(256);
        let mut watcher = RecommendedWatcher::new(
            move |event| {
                let _ = sender.try_send(event);
            },
            Config::default().with_poll_interval(Duration::from_millis(250)),
        )?;
        watcher.watch(&root, RecursiveMode::NonRecursive)?;
        Ok(Self {
            _watcher: watcher,
            events,
        })
    }
    pub fn try_next(&self) -> Option<notify::Result<Event>> {
        self.events.try_recv().ok()
    }
}

#[derive(Debug, Clone)]
pub struct IntakeEvent {
    pub id: u64,
    pub path: PathBuf,
    pub kind: EventKind,
    pub generation: u64,
}
#[derive(Debug, Default, Clone)]
pub struct WatchCounters {
    pub accepted: u64,
    pub coalesced: u64,
    pub dropped: u64,
    pub rejected: u64,
    pub scanned: u64,
    pub matched: u64,
    pub failed: u64,
    pub cancelled: u64,
}

pub struct BoundedIntake {
    tx: SyncSender<IntakeEvent>,
    counters: Arc<Mutex<WatchCounters>>,
    next_id: Arc<Mutex<u64>>,
    last: Arc<Mutex<HashMap<PathBuf, Instant>>>,
    debounce: Duration,
    root: PathBuf,
}
impl BoundedIntake {
    pub fn new(
        capacity: usize,
        debounce: Duration,
    ) -> (Self, Receiver<IntakeEvent>, Arc<Mutex<WatchCounters>>) {
        Self::new_with_root(capacity, debounce, PathBuf::new())
    }
    pub fn new_with_root(
        capacity: usize,
        debounce: Duration,
        root: PathBuf,
    ) -> (Self, Receiver<IntakeEvent>, Arc<Mutex<WatchCounters>>) {
        let (tx, rx) = mpsc::sync_channel(capacity.max(1));
        let counters = Arc::new(Mutex::new(WatchCounters::default()));
        (
            Self {
                tx,
                counters: counters.clone(),
                next_id: Arc::new(Mutex::new(0)),
                last: Arc::new(Mutex::new(HashMap::new())),
                debounce,
                root,
            },
            rx,
            counters,
        )
    }
    pub fn submit(&self, path: PathBuf, kind: EventKind, generation: u64) -> bool {
        if !self.root.as_os_str().is_empty() && !path.starts_with(&self.root) {
            self.counters.lock().unwrap().rejected += 1;
            return false;
        }
        let now = Instant::now();
        {
            let mut last = self.last.lock().unwrap();
            last.retain(|_, t| now.duration_since(*t) < self.debounce);
            if last
                .get(&path)
                .is_some_and(|t| now.duration_since(*t) < self.debounce)
            {
                self.counters.lock().unwrap().coalesced += 1;
                return false;
            }
        }
        let mut id = self.next_id.lock().unwrap();
        *id += 1;
        let event = IntakeEvent {
            id: *id,
            path,
            kind,
            generation,
        };
        let accepted_path = event.path.clone();
        match self.tx.try_send(event) {
            Ok(()) => {
                self.last.lock().unwrap().insert(accepted_path, now);
                self.counters.lock().unwrap().accepted += 1;
                true
            }
            Err(TrySendError::Full(_)) => {
                self.counters.lock().unwrap().dropped += 1;
                false
            }
            Err(TrySendError::Disconnected(_)) => {
                self.counters.lock().unwrap().dropped += 1;
                false
            }
        }
    }
}

pub fn event_kind(kind: &EventKind) -> bool {
    matches!(kind, EventKind::Create(_) | EventKind::Modify(_))
}
pub fn stable_file(path: &Path, deadline: Instant) -> std::io::Result<std::fs::Metadata> {
    let mut previous: Option<std::fs::Metadata> = None;
    let interval = Duration::from_millis(20);
    loop {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "candidate is not a regular non-symlink file",
            ));
        }
        if let Some(old) = &previous {
            if old.len() == metadata.len() && old.modified().ok() == metadata.modified().ok() {
                return Ok(metadata);
            }
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "file did not stabilize before deadline",
            ));
        }
        previous = Some(metadata);
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        std::thread::sleep(interval.min(remaining));
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "file did not stabilize before deadline",
    ))
}

pub fn identity_changed(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || before.file_type().is_symlink() != after.file_type().is_symlink()
}

pub fn reconcile_root(
    root: &Path,
    snapshot: &mut HashMap<PathBuf, (u64, Option<std::time::SystemTime>)>,
    budget: usize,
) -> Vec<PathBuf> {
    let mut discovered = Vec::new();
    let mut observed = HashMap::new();
    let mut seen = 0usize;
    let Ok(entries) = std::fs::read_dir(root) else {
        return discovered;
    };
    for item in entries.flatten() {
        if seen >= budget {
            break;
        }
        let path = item.path();
        seen += 1;
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.file_type().is_file() || meta.file_type().is_symlink() {
            continue;
        }
        let state = (meta.len(), meta.modified().ok());
        if snapshot.get(&path) != Some(&state) {
            discovered.push(path.clone());
        }
        observed.insert(path, state);
    }
    *snapshot = observed;
    discovered
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_duplicate_is_coalesced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x");
        std::fs::write(&path, b"x").unwrap();
        let (q, rx, counters) = BoundedIntake::new(1, Duration::from_secs(5));
        assert!(q.submit(
            path.clone(),
            EventKind::Create(notify::event::CreateKind::File),
            1
        ));
        assert!(!q.submit(path, EventKind::Modify(notify::event::ModifyKind::Any), 1));
        assert_eq!(rx.try_recv().unwrap().id, 1);
        assert_eq!(counters.lock().unwrap().coalesced, 1);
    }

    #[test]
    fn dropped_event_can_retry_after_queue_frees() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        let (q, rx, counters) = BoundedIntake::new(1, Duration::from_secs(5));
        assert!(q.submit(a, EventKind::Create(notify::event::CreateKind::File), 1));
        assert!(!q.submit(
            b.clone(),
            EventKind::Create(notify::event::CreateKind::File),
            1
        ));
        assert_eq!(counters.lock().unwrap().dropped, 1);
        let _ = rx.try_recv();
        assert!(q.submit(b, EventKind::Create(notify::event::CreateKind::File), 2));
    }

    #[test]
    fn pre_post_identity_change_is_not_clean() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity");
        std::fs::write(&path, b"before").unwrap();
        let before = std::fs::symlink_metadata(&path).unwrap();
        std::fs::write(&path, b"after-with-different-size").unwrap();
        let after = std::fs::symlink_metadata(&path).unwrap();
        assert!(identity_changed(&before, &after));
    }
}

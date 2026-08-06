use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::{
    path::PathBuf,
    sync::mpsc::{self, Receiver},
    time::Duration,
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
        let (sender, events) = mpsc::channel();
        let mut watcher = RecommendedWatcher::new(
            sender,
            Config::default().with_poll_interval(Duration::from_millis(250)),
        )?;
        for root in roots(profile).into_iter().filter(|path| path.is_dir()) {
            watcher.watch(&root, RecursiveMode::NonRecursive)?;
        }
        Ok(Self {
            _watcher: watcher,
            events,
        })
    }

    pub fn try_next(&self) -> Option<notify::Result<Event>> {
        self.events.try_recv().ok()
    }
}

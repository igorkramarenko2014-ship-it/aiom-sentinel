-- Lookup indexes for the lane 1 registry. Forward-only and non-destructive.

CREATE INDEX fingerprints_digest_idx
    ON fingerprints (algorithm, digest);

CREATE INDEX fingerprint_sets_revoked_idx
    ON fingerprint_sets (revoked_at);

-- Sentinel fingerprint registry lane 1.
-- Forward-only migration. No ingestion_runs or lookup telemetry is persisted.

CREATE TABLE fingerprint_sets (
    id UUID PRIMARY KEY,
    source_name TEXT NOT NULL,
    source_version TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    authority_state TEXT GENERATED ALWAYS AS (
        CASE WHEN revoked_at IS NULL THEN 'ACTIVE' ELSE 'REVOKED' END
    ) STORED,
    CONSTRAINT fingerprint_sets_authority_state_check
        CHECK (authority_state IN ('ACTIVE', 'REVOKED'))
);

CREATE TABLE source_artifacts (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    fingerprint_set_id UUID NOT NULL REFERENCES fingerprint_sets(id),
    sha256 BYTEA NOT NULL,
    artifact_name TEXT NOT NULL,
    source_uri TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT source_artifacts_sha256_length_check
        CHECK (octet_length(sha256) = 32),
    CONSTRAINT source_artifacts_set_sha256_unique
        UNIQUE (fingerprint_set_id, sha256),
    CONSTRAINT source_artifacts_id_set_unique
        UNIQUE (id, fingerprint_set_id)
);

CREATE TABLE fingerprints (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    fingerprint_set_id UUID NOT NULL REFERENCES fingerprint_sets(id),
    source_artifact_id BIGINT NOT NULL,
    algorithm TEXT NOT NULL,
    digest BYTEA NOT NULL,
    classification TEXT NOT NULL,
    asserted_by TEXT NOT NULL,
    assertion_source TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fingerprints_source_artifact_set_fk
        FOREIGN KEY (source_artifact_id, fingerprint_set_id)
        REFERENCES source_artifacts(id, fingerprint_set_id),
    CONSTRAINT fingerprints_algorithm_check
        CHECK (algorithm IN ('MD5', 'SHA1', 'SHA256')),
    CONSTRAINT fingerprints_classification_check
        CHECK (classification IN (
            'KNOWN_MALICIOUS',
            'KNOWN_SUSPICIOUS',
            'KNOWN_BENIGN',
            'TEST_FIXTURE'
        )),
    CONSTRAINT fingerprints_digest_length_check
        CHECK (
            (algorithm = 'MD5' AND octet_length(digest) = 16)
            OR (algorithm = 'SHA1' AND octet_length(digest) = 20)
            OR (algorithm = 'SHA256' AND octet_length(digest) = 32)
        ),
    CONSTRAINT fingerprints_set_algorithm_digest_unique
        UNIQUE (fingerprint_set_id, algorithm, digest)
);

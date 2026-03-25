-- ZeroTrustOps Database Schema

-- Organizations (companies using the platform)
CREATE TABLE IF NOT EXISTS organizations (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    slug        VARCHAR(100) UNIQUE NOT NULL,
    created_at  TIMESTAMP DEFAULT NOW()
);

-- Repositories connected to the platform
CREATE TABLE IF NOT EXISTS repositories (
    id              SERIAL PRIMARY KEY,
    org_id          INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    full_name       VARCHAR(500) NOT NULL UNIQUE,  -- "owner/repo"
    clone_url       TEXT NOT NULL,
    github_webhook_id BIGINT,
    branch          VARCHAR(100) DEFAULT 'main',
    enabled         BOOLEAN DEFAULT true,
    created_at      TIMESTAMP DEFAULT NOW()
);

-- Scan runs — one per push/trigger
CREATE TABLE IF NOT EXISTS scans (
    id              SERIAL PRIMARY KEY,
    repo_id         INTEGER REFERENCES repositories(id) ON DELETE CASCADE,
    commit_sha      VARCHAR(64),
    branch          VARCHAR(100),
    triggered_by    VARCHAR(255),
    commit_message  TEXT,
    status          VARCHAR(20) DEFAULT 'pending',  -- pending, running, pass, fail, error
    gate_decision   VARCHAR(10),                    -- PASS or FAIL
    started_at      TIMESTAMP DEFAULT NOW(),
    finished_at     TIMESTAMP,
    duration_ms     INTEGER
);

-- Individual findings from each scan
CREATE TABLE IF NOT EXISTS findings (
    id              SERIAL PRIMARY KEY,
    scan_id         INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    tool            VARCHAR(50) NOT NULL,   -- sectl, trivy, gitleaks
    rule_id         VARCHAR(50),
    severity        VARCHAR(20) NOT NULL,   -- CRITICAL, HIGH, MEDIUM, LOW
    category        VARCHAR(50),
    title           TEXT NOT NULL,
    description     TEXT,
    file_path       TEXT,
    line_number     INTEGER,
    remediation     TEXT,
    created_at      TIMESTAMP DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_scans_repo_id ON scans(repo_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

-- Default organization
INSERT INTO organizations (name, slug)
VALUES ('Default', 'default')
ON CONFLICT (slug) DO NOTHING;

"""
ZeroTrustOps Platform — Backend API
FastAPI application that:
  - Receives GitHub webhooks
  - Triggers SecTL scans
  - Stores results in PostgreSQL
  - Serves REST API for dashboard
"""

import asyncio
import json
import os
import subprocess
import tempfile
import shutil
from datetime import datetime
from typing import Optional, List

import databases
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ─── Config ───────────────────────────────────────────────────────────────────

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://zerotrust:zerotrust123@db:5432/zerotrust")
SECTL_PATH   = os.getenv("SECTL_PATH", "/usr/local/bin/sectl")
WORKSPACE    = os.getenv("WORKSPACE", "/workspace")

# ─── Database — asyncpg only, no psycopg2 ────────────────────────────────────

DB_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")
database = databases.Database(DB_URL)

# ─── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="ZeroTrustOps Platform API",
    description="Security enforcement platform — scan before deploy",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Startup / Shutdown ───────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    await database.connect()
    os.makedirs(WORKSPACE, exist_ok=True)
    print("✅ Database connected")
    print(f"✅ SecTL: {SECTL_PATH}")

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# ─── Models ───────────────────────────────────────────────────────────────────

class RepoAdd(BaseModel):
    full_name: str        # "owner/repo"
    clone_url: str
    branch: str = "main"

class TriggerScan(BaseModel):
    repo_full_name: str
    commit_sha: str = "manual"
    branch: str = "main"
    triggered_by: str = "manual"
    commit_message: str = "Manual trigger"

# ─── Health ───────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "sectl": os.path.exists(SECTL_PATH),
        "version": "1.0.0"
    }

# ─── Repositories ─────────────────────────────────────────────────────────────

@app.get("/api/repos")
async def list_repos():
    """List all connected repositories."""
    rows = await database.fetch_all("""
        SELECT r.*, 
               COUNT(s.id) as total_scans,
               MAX(s.started_at) as last_scan,
               (SELECT gate_decision FROM scans 
                WHERE repo_id = r.id 
                ORDER BY started_at DESC LIMIT 1) as last_gate
        FROM repositories r
        LEFT JOIN scans s ON s.repo_id = r.id
        GROUP BY r.id
        ORDER BY r.created_at DESC
    """)
    return [dict(r) for r in rows]

@app.post("/api/repos")
async def add_repo(data: RepoAdd):
    """Add a new repository to scan."""
    # Check if already exists
    existing = await database.fetch_one(
        "SELECT id FROM repositories WHERE full_name = :full_name",
        {"full_name": data.full_name}
    )
    if existing:
        raise HTTPException(status_code=400, detail="Repository already connected")

    repo_id = await database.execute("""
        INSERT INTO repositories (org_id, name, full_name, clone_url, branch)
        VALUES (1, :name, :full_name, :clone_url, :branch)
        RETURNING id
    """, {
        "name": data.full_name.split("/")[-1],
        "full_name": data.full_name,
        "clone_url": data.clone_url,
        "branch": data.branch
    })
    return {"id": repo_id, "message": "Repository connected", "full_name": data.full_name}

@app.delete("/api/repos/{repo_id}")
async def remove_repo(repo_id: int):
    await database.execute("DELETE FROM repositories WHERE id = :id", {"id": repo_id})
    return {"message": "Repository removed"}

# ─── Scans ────────────────────────────────────────────────────────────────────

@app.get("/api/scans")
async def list_scans(repo_id: Optional[int] = None, limit: int = 20):
    """List recent scans."""
    where = "WHERE s.repo_id = :repo_id" if repo_id else ""
    params = {"repo_id": repo_id, "limit": limit} if repo_id else {"limit": limit}

    rows = await database.fetch_all(f"""
        SELECT s.*, r.full_name as repo_name,
               COUNT(f.id) as finding_count,
               COUNT(CASE WHEN f.severity = 'CRITICAL' THEN 1 END) as critical_count,
               COUNT(CASE WHEN f.severity = 'HIGH' THEN 1 END) as high_count
        FROM scans s
        JOIN repositories r ON r.id = s.repo_id
        LEFT JOIN findings f ON f.scan_id = s.id
        {where}
        GROUP BY s.id, r.full_name
        ORDER BY s.started_at DESC
        LIMIT :limit
    """, params)
    return [dict(r) for r in rows]

@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: int):
    """Get scan details with all findings."""
    scan = await database.fetch_one("""
        SELECT s.*, r.full_name as repo_name
        FROM scans s
        JOIN repositories r ON r.id = s.repo_id
        WHERE s.id = :id
    """, {"id": scan_id})

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = await database.fetch_all(
        "SELECT * FROM findings WHERE scan_id = :id ORDER BY severity DESC",
        {"id": scan_id}
    )

    return {**dict(scan), "findings": [dict(f) for f in findings]}

@app.post("/api/scans/trigger")
async def trigger_scan(data: TriggerScan, background_tasks: BackgroundTasks):
    """Manually trigger a scan."""
    repo = await database.fetch_one(
        "SELECT * FROM repositories WHERE full_name = :full_name",
        {"full_name": data.repo_full_name}
    )
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not connected. Add it first.")

    scan_id = await database.execute("""
        INSERT INTO scans (repo_id, commit_sha, branch, triggered_by, commit_message, status)
        VALUES (:repo_id, :commit_sha, :branch, :triggered_by, :commit_message, 'pending')
        RETURNING id
    """, {
        "repo_id": repo["id"],
        "commit_sha": data.commit_sha,
        "branch": data.branch,
        "triggered_by": data.triggered_by,
        "commit_message": data.commit_message
    })

    background_tasks.add_task(run_scan, scan_id, dict(repo))
    return {"scan_id": scan_id, "status": "queued", "message": "Scan started"}

# ─── GitHub Webhook ───────────────────────────────────────────────────────────

@app.post("/webhook/github")
async def github_webhook(request: Request, background_tasks: BackgroundTasks,
                          x_github_event: str = Header(None)):
    """Receive GitHub push webhook and trigger scan."""
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Only handle push events
    if x_github_event != "push":
        return {"message": f"Event '{x_github_event}' ignored — only push events trigger scans"}

    # Extract info from webhook payload
    ref         = payload.get("ref", "")
    branch      = ref.replace("refs/heads/", "")
    commit_sha  = payload.get("after", "unknown")
    clone_url   = payload.get("repository", {}).get("clone_url", "")
    full_name   = payload.get("repository", {}).get("full_name", "")
    pusher      = payload.get("pusher", {}).get("name", "unknown")
    head_commit = payload.get("head_commit", {})
    commit_msg  = head_commit.get("message", "") if head_commit else ""

    if not full_name:
        raise HTTPException(status_code=400, detail="Repository info missing from payload")

    # Find or auto-register repo
    repo = await database.fetch_one(
        "SELECT * FROM repositories WHERE full_name = :full_name",
        {"full_name": full_name}
    )

    if not repo:
        # Auto-register repo on first webhook
        repo_id = await database.execute("""
            INSERT INTO repositories (org_id, name, full_name, clone_url, branch)
            VALUES (1, :name, :full_name, :clone_url, :branch)
            RETURNING id
        """, {
            "name": full_name.split("/")[-1],
            "full_name": full_name,
            "clone_url": clone_url,
            "branch": branch
        })
        repo = await database.fetch_one(
            "SELECT * FROM repositories WHERE id = :id", {"id": repo_id}
        )

    # Create scan record
    scan_id = await database.execute("""
        INSERT INTO scans (repo_id, commit_sha, branch, triggered_by, commit_message, status)
        VALUES (:repo_id, :commit_sha, :branch, :triggered_by, :commit_message, 'pending')
        RETURNING id
    """, {
        "repo_id": repo["id"],
        "commit_sha": commit_sha[:8] if commit_sha else "unknown",
        "branch": branch,
        "triggered_by": pusher,
        "commit_message": commit_msg[:200] if commit_msg else "",
        "status": "pending"
    })

    # Run scan in background
    background_tasks.add_task(run_scan, scan_id, dict(repo))

    return {
        "scan_id": scan_id,
        "repo": full_name,
        "branch": branch,
        "commit": commit_sha[:8] if commit_sha else "unknown",
        "pusher": pusher,
        "status": "scan_queued"
    }

# ─── Dashboard Stats ──────────────────────────────────────────────────────────

@app.get("/api/stats")
async def get_stats():
    """Dashboard overview statistics."""
    stats = await database.fetch_one("""
        SELECT
            (SELECT COUNT(*) FROM repositories WHERE enabled = true) as total_repos,
            (SELECT COUNT(*) FROM scans) as total_scans,
            (SELECT COUNT(*) FROM scans WHERE gate_decision = 'PASS') as passed_scans,
            (SELECT COUNT(*) FROM scans WHERE gate_decision = 'FAIL') as failed_scans,
            (SELECT COUNT(*) FROM findings WHERE severity = 'CRITICAL') as total_critical,
            (SELECT COUNT(*) FROM findings WHERE severity = 'HIGH') as total_high,
            (SELECT COUNT(*) FROM scans WHERE status = 'running') as running_scans
    """)
    return dict(stats)

# ─── Core Scan Engine ─────────────────────────────────────────────────────────

async def run_scan(scan_id: int, repo: dict):
    """
    Main scan function — runs in background:
    1. Clone repo
    2. Run SecTL scan
    3. Store findings in DB
    4. Update scan status
    """
    started = datetime.now()
    work_dir = os.path.join(WORKSPACE, f"scan_{scan_id}")

    try:
        # Mark as running
        await database.execute(
            "UPDATE scans SET status = 'running' WHERE id = :id",
            {"id": scan_id}
        )

        # Step 1: Clone repository
        clone_url = repo["clone_url"]
        branch = repo.get("branch", "main")

        print(f"[Scan {scan_id}] Cloning {clone_url}...")
        result = subprocess.run(
            ["git", "clone", "--depth=1", f"--branch={branch}", clone_url, work_dir],
            capture_output=True, text=True, timeout=120
        )

        if result.returncode != 0:
            # Try without branch spec
            result = subprocess.run(
                ["git", "clone", "--depth=1", clone_url, work_dir],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode != 0:
                raise Exception(f"Git clone failed: {result.stderr}")

        # Step 2: Run SecTL K8s scan
        k8s_findings = []
        manifests_dir = None
        for candidate in ["manifests", "k8s", "kubernetes", "deploy", "."]:
            candidate_path = os.path.join(work_dir, candidate)
            if os.path.exists(candidate_path):
                manifests_dir = candidate_path
                break

        if manifests_dir:
            print(f"[Scan {scan_id}] Running SecTL K8s scan on {manifests_dir}...")
            k8s_findings = await run_sectl(scan_id, manifests_dir, "k8s")

        # Step 3: Run SecTL Terraform scan
        tf_findings = []
        for candidate in ["infra", "terraform", "tf", "infrastructure"]:
            tf_path = os.path.join(work_dir, candidate)
            if os.path.exists(tf_path) and any(f.endswith(".tf") for f in _walk_files(tf_path)):
                print(f"[Scan {scan_id}] Running SecTL Terraform scan on {tf_path}...")
                tf_findings = await run_sectl(scan_id, tf_path, "terraform")
                break

        # Also check root for .tf files
        if not tf_findings and any(f.endswith(".tf") for f in os.listdir(work_dir)):
            tf_findings = await run_sectl(scan_id, work_dir, "terraform")

        # Step 4: Run Gitleaks secrets scan
        secrets_findings = await run_gitleaks(scan_id, work_dir)

        # Step 5: Collect all findings
        all_findings = k8s_findings + tf_findings + secrets_findings

        # Step 6: Store findings in DB
        for finding in all_findings:
            await database.execute("""
                INSERT INTO findings
                    (scan_id, tool, rule_id, severity, category, title, description, file_path, remediation)
                VALUES
                    (:scan_id, :tool, :rule_id, :severity, :category, :title, :description, :file_path, :remediation)
            """, {
                "scan_id": scan_id,
                "tool": finding.get("tool", "sectl"),
                "rule_id": finding.get("rule_id", ""),
                "severity": finding.get("severity", "INFO"),
                "category": finding.get("category", ""),
                "title": finding.get("title", "")[:500],
                "description": finding.get("description", "")[:1000],
                "file_path": finding.get("file", "")[:500],
                "remediation": finding.get("remediation", "")[:1000]
            })

        # Step 7: Make PASS/FAIL decision
        critical = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
        high     = sum(1 for f in all_findings if f.get("severity") == "HIGH")
        gate     = "FAIL" if (critical > 0 or high > 0) else "PASS"

        duration = int((datetime.now() - started).total_seconds() * 1000)

        # Step 8: Update scan record
        await database.execute("""
            UPDATE scans SET
                status = :status,
                gate_decision = :gate,
                finished_at = NOW(),
                duration_ms = :duration
            WHERE id = :id
        """, {
            "status": "fail" if gate == "FAIL" else "pass",
            "gate": gate,
            "duration": duration,
            "id": scan_id
        })

        print(f"[Scan {scan_id}] ✅ Complete — Gate: {gate} | Findings: {len(all_findings)} | Duration: {duration}ms")

    except Exception as e:
        print(f"[Scan {scan_id}] ❌ Error: {e}")
        await database.execute("""
            UPDATE scans SET status = 'error', finished_at = NOW()
            WHERE id = :id
        """, {"id": scan_id})

    finally:
        # Cleanup cloned repo
        if os.path.exists(work_dir):
            shutil.rmtree(work_dir, ignore_errors=True)


async def run_sectl(scan_id: int, path: str, scan_type: str) -> list:
    """Run SecTL and return findings list."""
    try:
        result = subprocess.run(
            [SECTL_PATH, "scan", path,
             "--type", scan_type,
             "--severity", "low",
             "--output", "json",
             "--quiet"],
            capture_output=True, text=True, timeout=120
        )

        if not result.stdout.strip():
            return []

        data = json.loads(result.stdout)
        findings = data.get("findings", [])

        # Tag with tool name
        for f in findings:
            f["tool"] = "SecTL"

        return findings

    except Exception as e:
        print(f"[Scan {scan_id}] SecTL error ({scan_type}): {e}")
        return []


async def run_gitleaks(scan_id: int, path: str) -> list:
    """Run Gitleaks secrets scan."""
    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        result = subprocess.run(
            ["docker", "run", "--rm",
             "-v", f"{path}:/repo",
             "-v", f"{os.path.dirname(tmp_path)}:/report",
             "zricethezav/gitleaks:latest",
             "detect", "--source=/repo",
             "--report-format=json",
             f"--report-path=/report/{os.path.basename(tmp_path)}",
             "--exit-code=0"],
            capture_output=True, text=True, timeout=120
        )

        if os.path.exists(tmp_path):
            with open(tmp_path) as f:
                secrets = json.load(f)
            os.unlink(tmp_path)

            findings = []
            for s in (secrets if isinstance(secrets, list) else []):
                findings.append({
                    "tool": "Gitleaks",
                    "rule_id": s.get("RuleID", "SECRET"),
                    "severity": "CRITICAL",
                    "category": "SECRETS",
                    "title": s.get("Description", "Secret detected"),
                    "description": f"Secret found in {s.get('File', '')}",
                    "file": s.get("File", "") + ":" + str(s.get("StartLine", "")),
                    "remediation": "Remove secret, rotate credentials, use environment variables."
                })
            return findings
    except Exception as e:
        print(f"[Scan {scan_id}] Gitleaks error: {e}")

    return []


def _walk_files(path: str):
    """Walk directory and yield file names."""
    for root, dirs, files in os.walk(path):
        for f in files:
            yield f

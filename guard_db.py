"""
NeuronX Guard — Database & Pricing Engine

Handles: installations, review history, pricing tiers, rate limiting, badges.
"""

import os
import sqlite3
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pathlib import Path

DB_PATH = Path(__file__).parent / "guard_data.db"

# --- Pricing Tiers ---

TIERS = {
    "free": {
        "name": "Free",
        "price": 0,
        "reviews_per_day": 20,
        "repos": 999,       # unlimited
        "checks": ["security", "bare_except", "complexity", "patterns", "llm_review"],
        "features": ["All 4 review layers", "Unlimited repos", "20 reviews/day"],
    },
    "pro": {
        "name": "Pro",
        "price": 10,
        "reviews_per_day": 200,
        "repos": 999,
        "checks": ["security", "bare_except", "complexity", "patterns", "llm_review"],
        "features": ["All 4 review layers", "200 reviews/day", "Priority review", "Custom rules", "Email notifications"],
    },
    "team": {
        "name": "Team",
        "price": 30,
        "reviews_per_day": 1000,
        "repos": 999,
        "checks": ["security", "bare_except", "complexity", "patterns", "llm_review"],
        "features": ["All 4 review layers", "1000 reviews/day", "Team dashboard", "Slack integration", "Analytics"],
    },
}


def init_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS installations (
            id INTEGER PRIMARY KEY,
            installation_id INTEGER UNIQUE,
            owner TEXT,
            repos TEXT DEFAULT '[]',
            tier TEXT DEFAULT 'free',
            reviews_today INTEGER DEFAULT 0,
            total_reviews INTEGER DEFAULT 0,
            total_issues INTEGER DEFAULT 0,
            last_review TEXT,
            installed_at TEXT,
            active INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            installation_id INTEGER,
            repo TEXT,
            pr_number INTEGER,
            files_reviewed INTEGER DEFAULT 0,
            issues_found INTEGER DEFAULT 0,
            checks_run TEXT DEFAULT '[]',
            review_time_ms INTEGER DEFAULT 0,
            comment_posted INTEGER DEFAULT 0,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS issues (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            review_id INTEGER,
            repo TEXT,
            filename TEXT,
            severity TEXT,
            check_type TEXT,
            message TEXT,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS daily_limits (
            installation_id INTEGER,
            date TEXT,
            reviews_used INTEGER DEFAULT 0,
            PRIMARY KEY (installation_id, date)
        );
    """)
    conn.commit()
    conn.close()


init_db()


# --- Installation Management ---

def record_installation(installation_id: int, owner: str, repos: list):
    conn = sqlite3.connect(str(DB_PATH))
    import json
    conn.execute(
        "INSERT OR REPLACE INTO installations (installation_id, owner, repos, installed_at) VALUES (?, ?, ?, ?)",
        (installation_id, owner, json.dumps(repos), datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


def remove_installation(installation_id: int):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("UPDATE installations SET active = 0 WHERE installation_id = ?", (installation_id,))
    conn.commit()
    conn.close()


def get_installation(installation_id: int) -> Optional[Dict]:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM installations WHERE installation_id = ?", (installation_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_installation_tier(installation_id: int) -> str:
    inst = get_installation(installation_id)
    return inst.get("tier", "free") if inst else "free"


# --- Rate Limiting ---

def check_rate_limit(installation_id: int) -> Dict:
    """Check if installation has reviews remaining today."""
    tier_name = get_installation_tier(installation_id)
    tier = TIERS.get(tier_name, TIERS["free"])
    today = datetime.now().strftime("%Y-%m-%d")

    conn = sqlite3.connect(str(DB_PATH))
    row = conn.execute(
        "SELECT reviews_used FROM daily_limits WHERE installation_id = ? AND date = ?",
        (installation_id, today)
    ).fetchone()
    used = row[0] if row else 0
    conn.close()

    limit = tier["reviews_per_day"]
    return {
        "allowed": used < limit,
        "used": used,
        "limit": limit,
        "remaining": max(0, limit - used),
        "tier": tier_name,
    }


def increment_usage(installation_id: int):
    today = datetime.now().strftime("%Y-%m-%d")
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        "INSERT INTO daily_limits (installation_id, date, reviews_used) VALUES (?, ?, 1) "
        "ON CONFLICT(installation_id, date) DO UPDATE SET reviews_used = reviews_used + 1",
        (installation_id, today)
    )
    conn.execute(
        "UPDATE installations SET reviews_today = reviews_today + 1, "
        "total_reviews = total_reviews + 1, last_review = ? WHERE installation_id = ?",
        (datetime.now().isoformat(), installation_id)
    )
    conn.commit()
    conn.close()


# --- Review History ---

def record_review(installation_id: int, repo: str, pr_number: int,
                  files: int, issues: int, checks: list, time_ms: int, posted: bool) -> int:
    import json
    conn = sqlite3.connect(str(DB_PATH))
    cur = conn.execute(
        "INSERT INTO reviews (installation_id, repo, pr_number, files_reviewed, issues_found, "
        "checks_run, review_time_ms, comment_posted, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (installation_id, repo, pr_number, files, issues,
         json.dumps(checks), time_ms, 1 if posted else 0, datetime.now().isoformat())
    )
    review_id = cur.lastrowid
    conn.execute(
        "UPDATE installations SET total_issues = total_issues + ? WHERE installation_id = ?",
        (issues, installation_id)
    )
    conn.commit()
    conn.close()
    return review_id


def record_issue(review_id: int, repo: str, filename: str, severity: str, check: str, message: str):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        "INSERT INTO issues (review_id, repo, filename, severity, check_type, message, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (review_id, repo, filename, severity, check, message, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


# --- Analytics ---

def get_stats() -> Dict:
    conn = sqlite3.connect(str(DB_PATH))
    total_installs = conn.execute("SELECT COUNT(*) FROM installations WHERE active = 1").fetchone()[0]
    total_reviews = conn.execute("SELECT COUNT(*) FROM reviews").fetchone()[0]
    total_issues = conn.execute("SELECT COUNT(*) FROM issues").fetchone()[0]
    today = datetime.now().strftime("%Y-%m-%d")
    today_reviews = conn.execute(
        "SELECT COUNT(*) FROM reviews WHERE created_at LIKE ?", (today + "%",)
    ).fetchone()[0]

    top_repos = conn.execute(
        "SELECT repo, COUNT(*) as cnt, SUM(issues_found) FROM reviews GROUP BY repo ORDER BY cnt DESC LIMIT 10"
    ).fetchall()

    top_issues = conn.execute(
        "SELECT check_type, COUNT(*) as cnt FROM issues GROUP BY check_type ORDER BY cnt DESC LIMIT 10"
    ).fetchall()

    conn.close()
    return {
        "installations": total_installs,
        "total_reviews": total_reviews,
        "total_issues": total_issues,
        "reviews_today": today_reviews,
        "top_repos": [{"repo": r[0], "reviews": r[1], "issues": r[2]} for r in top_repos],
        "top_issue_types": [{"type": r[0], "count": r[1]} for r in top_issues],
        "pricing": TIERS,
    }


def get_repo_reviews(repo: str, limit: int = 20) -> List[Dict]:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM reviews WHERE repo = ? ORDER BY created_at DESC LIMIT ?",
        (repo, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# --- Badge Generation ---

def get_badge_data(repo: str) -> Dict:
    """Get data for shield.io badge."""
    conn = sqlite3.connect(str(DB_PATH))
    row = conn.execute(
        "SELECT COUNT(*), SUM(issues_found) FROM reviews WHERE repo = ?", (repo,)
    ).fetchone()
    conn.close()
    reviews = row[0] or 0
    issues = row[1] or 0
    if reviews == 0:
        return {"label": "NeuronX Guard", "message": "not reviewed", "color": "lightgrey"}
    elif issues == 0:
        return {"label": "NeuronX Guard", "message": "passing", "color": "brightgreen"}
    else:
        avg = issues / reviews
        color = "green" if avg < 2 else "yellow" if avg < 5 else "orange" if avg < 10 else "red"
        return {"label": "NeuronX Guard", "message": f"{issues} issues", "color": color}

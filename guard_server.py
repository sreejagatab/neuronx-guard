"""
NeuronX Guard — AI Code Review Server

Standalone server that receives GitHub webhooks and reviews PRs
using the NeuronX Platform API as the backend brain.

Can run independently or alongside the NeuronX Platform.
"""

import os
import sys
import json
import time
import hmac
import hashlib
import logging
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse, JSONResponse
import uvicorn

# Load .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s [GUARD] %(message)s")
logger = logging.getLogger("guard")

# --- Config ---
GITHUB_APP_ID = os.getenv("GITHUB_APP_ID", "")
GITHUB_PRIVATE_KEY_PATH = os.getenv("GITHUB_APP_PRIVATE_KEY_PATH", "neuronx-guard.pem")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")
NEURONX_API = os.getenv("NEURONX_API_URL", "https://neuronx.jagatab.uk")
NEURONX_KEY = os.getenv("NEURONX_API_KEY", "")
GUARD_PORT = int(os.getenv("GUARD_PORT", "9000"))
MAX_DIFF_SIZE = int(os.getenv("MAX_DIFF_SIZE", "50000"))
MAX_FILES = int(os.getenv("MAX_FILES_PER_REVIEW", "20"))
MAX_COMMENTS = int(os.getenv("MAX_REVIEW_COMMENTS", "15"))

# --- Stats ---
stats = {
    "reviews_completed": 0,
    "issues_found": 0,
    "repos_installed": set(),
    "started_at": datetime.now().isoformat(),
}

# --- GitHub App JWT Auth ---
_jwt_cache = {"token": None, "expires": 0}


def _generate_jwt():
    """Generate JWT for GitHub App authentication."""
    if time.time() < _jwt_cache["expires"]:
        return _jwt_cache["token"]

    key_path = Path(GITHUB_PRIVATE_KEY_PATH)
    if not key_path.exists() or not GITHUB_APP_ID:
        return None

    try:
        import jwt as pyjwt
        with open(key_path) as f:
            private_key = f.read()

        now = int(time.time())
        payload = {
            "iat": now - 60,
            "exp": now + (10 * 60),  # 10 min
            "iss": GITHUB_APP_ID,
        }
        token = pyjwt.encode(payload, private_key, algorithm="RS256")
        _jwt_cache["token"] = token
        _jwt_cache["expires"] = now + 500
        return token
    except ImportError:
        logger.warning("PyJWT not installed. Install: pip install PyJWT cryptography")
        return None
    except Exception as e:
        logger.error(f"JWT generation failed: {e}")
        return None


def _get_installation_token(installation_id: int) -> str:
    """Get an installation access token for a specific repo installation."""
    jwt = _generate_jwt()
    if not jwt:
        # Fallback to personal token
        return os.getenv("GITHUB_TOKEN", "")

    try:
        req = urllib.request.Request(
            f"https://api.github.com/app/installations/{installation_id}/access_tokens",
            method="POST",
            headers={
                "Authorization": f"Bearer {jwt}",
                "Accept": "application/vnd.github.v3+json",
            },
        )
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read())
        return data.get("token", "")
    except Exception as e:
        logger.error(f"Installation token failed: {e}")
        return os.getenv("GITHUB_TOKEN", "")


# --- NeuronX API Client ---

def neuronx_api(endpoint: str, data: dict = None, method: str = "GET") -> dict:
    """Call the NeuronX Platform API."""
    url = NEURONX_API + endpoint
    headers = {"Content-Type": "application/json"}
    if NEURONX_KEY:
        headers["X-API-Key"] = NEURONX_KEY

    try:
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        resp = urllib.request.urlopen(req, timeout=15)
        return json.loads(resp.read())
    except Exception as e:
        logger.debug(f"NeuronX API error ({endpoint}): {e}")
        return {"error": str(e)}


# --- Code Review Engine ---

def review_file(filename: str, diff: str, repo_config: dict) -> list:
    """Review a single file's diff using NeuronX capabilities."""
    issues = []

    if len(diff) > MAX_DIFF_SIZE:
        return [{"severity": "info", "message": "File too large for detailed review", "line": 0}]

    # Skip ignored files
    ignore = repo_config.get("ignore_files", [])
    for pattern in ignore:
        if pattern.endswith("*") and filename.startswith(pattern[:-1]):
            return []
        if filename.endswith(pattern.lstrip("*")):
            return []

    checks = repo_config.get("checks", {})

    # 1. AST Check (local — fast)
    if checks.get("bare_except", True):
        if "except:" in diff and "except Exception" not in diff:
            issues.append({
                "severity": "warning",
                "message": "Bare `except:` — use `except Exception:` to avoid catching SystemExit/KeyboardInterrupt",
                "check": "bare_except",
            })

    # 2. Security Scan (local — fast)
    if checks.get("security", True):
        import re
        secret_patterns = [
            (r'password\s*=\s*["\'][^"\']{5,}', "Possible hardcoded password"),
            (r'api[_-]?key\s*=\s*["\'][^"\']{10,}', "Possible hardcoded API key"),
            (r'secret\s*=\s*["\'][^"\']{5,}', "Possible hardcoded secret"),
            (r'sk-[a-zA-Z0-9]{20,}', "Possible OpenAI API key"),
            (r'ghp_[a-zA-Z0-9]{36}', "Possible GitHub token"),
        ]
        for pattern, msg in secret_patterns:
            if re.search(pattern, diff, re.IGNORECASE):
                issues.append({"severity": "error", "message": msg, "check": "security"})

    # 3. Complexity Check (via NeuronX — if enabled)
    if checks.get("complexity", True) and filename.endswith(".py"):
        added_lines = [l[1:] for l in diff.split("\n") if l.startswith("+") and not l.startswith("+++")]
        code = "\n".join(added_lines)
        if len(code) > 50:
            try:
                import ast
                tree = ast.parse(code)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        # Simple cyclomatic complexity
                        complexity = sum(1 for n in ast.walk(node)
                                        if isinstance(n, (ast.If, ast.For, ast.While, ast.ExceptHandler,
                                                         ast.With, ast.BoolOp, ast.IfExp)))
                        if complexity > 15:
                            issues.append({
                                "severity": "warning",
                                "message": f"Function `{node.name}` has high complexity ({complexity}). Consider breaking it down.",
                                "check": "complexity",
                            })
            except SyntaxError:
                pass

    # 4. Pattern Search (via NeuronX API)
    if checks.get("patterns", True) and len(issues) < 3:
        words = [w for w in filename.replace("/", " ").replace("_", " ").replace(".", " ").split() if len(w) > 3][:3]
        if words:
            result = neuronx_api(f"/api/patterns/search?q={'+'.join(words)}&limit=1")
            patterns = result.get("patterns", [])
            if patterns and patterns[0].get("quality", 0) > 0.9:
                issues.append({
                    "severity": "info",
                    "message": f"Similar high-quality pattern exists: `{patterns[0].get('name', '?')}` (quality={patterns[0].get('quality', 0):.2f}). Consider comparing your implementation.",
                    "check": "patterns",
                })

    # 5. LLM Deep Review + Fix Suggestions (via NeuronX API)
    if checks.get("llm_review", True) and len(issues) < 5:
        result = neuronx_api("/api/llm/chat", {
            "message": (
                f"Review this code diff for {filename}. For each issue:\n"
                f"1. State the issue with severity [High/Medium/Low]\n"
                f"2. Suggest a fix with before/after code\n"
                f"Max 3 issues. Format:\n"
                f"- [severity] Issue description\n"
                f"  Fix: `old code` -> `new code`\n\n"
                f"```diff\n{diff[:3000]}\n```"
            ),
        }, "POST")
        response = result.get("response", "")
        if response and result.get("model") != "template_fallback":
            for line in response.strip().split("\n"):
                line = line.strip()
                if line.startswith("- ") or line.startswith("* "):
                    msg = line[2:]
                    severity = "warning"
                    if "[high]" in msg.lower() or "[error]" in msg.lower() or "[critical]" in msg.lower():
                        severity = "error"
                    elif "[info]" in msg.lower() or "[low]" in msg.lower():
                        severity = "info"
                    # Clean severity tags
                    for tag in ["[high]", "[medium]", "[low]", "[error]", "[critical]", "[info]", "[warning]"]:
                        msg = msg.replace(tag, "").replace(tag.upper(), "").replace(tag.title(), "")
                    msg = msg.strip()
                    if msg and len(msg) > 10:
                        issues.append({"severity": severity, "message": msg, "check": "llm"})
                elif line.strip().startswith("Fix:") and issues:
                    # Append fix suggestion to the last issue
                    issues[-1]["message"] += "\n  " + line.strip()

    return issues[:MAX_COMMENTS]


def parse_diff(diff_text: str) -> list:
    """Parse a unified diff into per-file diffs."""
    files = []
    current_file = ""
    current_diff = ""

    for line in diff_text.split("\n"):
        if line.startswith("diff --git"):
            if current_file and current_diff:
                files.append((current_file, current_diff))
            parts = line.split(" b/")
            current_file = parts[-1] if len(parts) > 1 else ""
            current_diff = ""
        else:
            current_diff += line + "\n"

    if current_file and current_diff:
        files.append((current_file, current_diff))

    return files[:MAX_FILES]


def get_repo_config(repo: str, token: str) -> dict:
    """Read .neuronx-guard.yml from the repo."""
    default = {
        "enabled": True,
        "checks": {
            "security": True,
            "complexity": True,
            "bare_except": True,
            "patterns": True,
            "llm_review": True,
        },
        "ignore_files": ["*.md", "*.txt", "*.json", "*.yml", "*.yaml", "LICENSE", "*.lock"],
        "severity_threshold": "warning",
    }
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{repo}/contents/.neuronx-guard.yml",
            headers={"Authorization": f"token {token}", "Accept": "application/vnd.github.v3.raw"},
        )
        resp = urllib.request.urlopen(req, timeout=5)
        import yaml
        config = yaml.safe_load(resp.read())
        if config:
            default.update(config)
    except Exception:
        pass
    return default


def format_review_comment(repo: str, files_reviewed: int, all_issues: list) -> str:
    """Format the review comment with markdown."""
    if not all_issues:
        return (
            "## NeuronX Guard Review\n\n"
            f"Reviewed {files_reviewed} files. No issues found.\n\n"
            "*Powered by [NeuronX](https://neuronx.jagatab.uk) — 22K+ code patterns + AI*"
        )

    icons = {"error": "x", "warning": "warning", "info": "information_source"}
    body = f"## NeuronX Guard Review\n\n"
    body += f"Reviewed **{files_reviewed}** files, found **{len(all_issues)}** issues:\n\n"

    for filename, issue in all_issues[:MAX_COMMENTS]:
        icon = icons.get(issue["severity"], "bulb")
        check = f" `{issue.get('check', '')}`" if issue.get("check") else ""
        body += f"- :{icon}: **{filename}**{check}: {issue['message']}\n"

    body += f"\n---\n*Reviewed by [NeuronX Guard](https://neuronx.jagatab.uk/guard) | "
    body += f"{datetime.now().strftime('%Y-%m-%d %H:%M')} | "
    body += f"[NeuronX Platform](https://neuronx.jagatab.uk)*"
    return body


def post_review(repo: str, pr_number: int, comment: str, token: str,
                all_issues: list = None, commit_sha: str = ""):
    """Post review: summary comment + inline line comments on specific files."""
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json",
    }

    # 1. Post inline review with file-level comments (if we have issues + commit SHA)
    if all_issues and commit_sha:
        try:
            review_comments = []
            for filename, issue in all_issues[:10]:  # Max 10 inline comments
                review_comments.append({
                    "path": filename,
                    "body": f"**{issue.get('severity', 'warning').upper()}** ({issue.get('check', 'guard')}): {issue['message']}",
                    "side": "RIGHT",
                    "line": 1,  # First line of file (GitHub requires a line)
                })
            if review_comments:
                review_body = {
                    "body": comment,
                    "event": "COMMENT",
                    "comments": review_comments,
                }
                req = urllib.request.Request(
                    f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews",
                    method="POST",
                    data=json.dumps(review_body).encode(),
                    headers=headers,
                )
                urllib.request.urlopen(req, timeout=15)
                logger.info(f"Posted inline review on {repo}#{pr_number} ({len(review_comments)} comments)")
                return
        except Exception as e:
            logger.debug(f"Inline review failed ({e}), falling back to issue comment")

    # 2. Fallback: post as issue comment (always works)
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments",
            method="POST",
            data=json.dumps({"body": comment}).encode(),
            headers=headers,
        )
        urllib.request.urlopen(req, timeout=15)
        logger.info(f"Posted review on {repo}#{pr_number}")
    except Exception as e:
        logger.error(f"Failed to post review: {e}")


# --- FastAPI App ---

app = FastAPI(title="NeuronX Guard", version="3.0.0")

# Stripe billing routes
try:
    from stripe_billing import router as billing_router
    app.include_router(billing_router)
    logger.info("Stripe billing routes loaded")
except Exception as e:
    logger.debug(f"Stripe billing not available: {e}")


@app.get("/")
async def landing():
    """Redirect to main landing page on NeuronX Platform."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse("https://neuronx.jagatab.uk/guard")


@app.get("/favicon.ico")
@app.get("/favicon.svg")
async def favicon():
    fav = Path(__file__).parent / "favicon.svg"
    if fav.exists():
        return FileResponse(fav, media_type="image/svg+xml")
    return JSONResponse({}, status_code=204)


@app.get("/test-results")
async def test_results():
    """Show real test results from PR #1 review."""
    p = Path(__file__).parent / "test-results.html"
    if p.exists():
        return FileResponse(p)
    return JSONResponse({"message": "See /stats for review data"})


@app.get("/dashboard-ui")
async def dashboard_ui():
    """Interactive dashboard page."""
    return FileResponse(Path(__file__).parent / "dashboard.html")


@app.get("/health")
async def health():
    from guard_db import get_stats as db_stats
    db = db_stats()
    return {
        "status": "healthy",
        "reviews": stats["reviews_completed"] + db.get("total_reviews", 0),
        "issues_found": stats["issues_found"] + db.get("total_issues", 0),
        "repos": len(stats["repos_installed"]),
        "installations": db.get("installations", 0),
        "uptime": stats["started_at"],
    }


@app.get("/pricing")
async def pricing():
    """Show pricing tiers."""
    from guard_db import TIERS
    return {"tiers": TIERS}


@app.get("/badge/{owner}/{repo}.svg")
async def badge(owner: str, repo: str):
    """Generate shield.io compatible badge for repo."""
    from guard_db import get_badge_data
    data = get_badge_data(f"{owner}/{repo}")
    # Redirect to shields.io
    import urllib.parse
    url = f"https://img.shields.io/badge/{urllib.parse.quote(data['label'])}-{urllib.parse.quote(data['message'])}-{data['color']}"
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url)


@app.get("/dashboard/{owner}/{repo}")
async def repo_dashboard(owner: str, repo: str):
    """Review history for a repo."""
    from guard_db import get_repo_reviews, get_badge_data
    reviews = get_repo_reviews(f"{owner}/{repo}", limit=50)
    badge = get_badge_data(f"{owner}/{repo}")
    return {
        "repo": f"{owner}/{repo}",
        "badge": badge,
        "reviews": reviews,
        "total": len(reviews),
    }


@app.get("/rate-limit/{installation_id}")
async def rate_limit_check(installation_id: int):
    """Check rate limit for an installation."""
    from guard_db import check_rate_limit
    return check_rate_limit(installation_id)


@app.get("/stats")
async def get_stats_endpoint():
    from guard_db import get_stats as db_stats
    db = db_stats()
    return {
        "reviews_completed": stats["reviews_completed"] + db.get("total_reviews", 0),
        "issues_found": stats["issues_found"] + db.get("total_issues", 0),
        "repos_installed": len(stats["repos_installed"]),
        "started_at": stats["started_at"],
        "neuronx_api": NEURONX_API,
        "neuronx_connected": bool(neuronx_api("/health").get("status")),
    }


@app.post("/webhook")
async def webhook(request: Request):
    """Receive GitHub webhook events."""
    body = await request.body()

    # Verify signature
    if GITHUB_WEBHOOK_SECRET:
        signature = request.headers.get("X-Hub-Signature-256", "")
        expected = "sha256=" + hmac.new(
            GITHUB_WEBHOOK_SECRET.encode(), body, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise HTTPException(status_code=401, detail="Invalid signature")

    event = request.headers.get("X-GitHub-Event", "")
    payload = json.loads(body)

    # Handle installation events
    if event == "installation":
        action = payload.get("action")
        repos = payload.get("repositories", [])
        owner = payload.get("installation", {}).get("account", {}).get("login", "")
        inst_id = payload.get("installation", {}).get("id", 0)
        repo_names = [r.get("full_name", "") for r in repos]
        for r in repo_names:
            stats["repos_installed"].add(r)

        from guard_db import record_installation, remove_installation
        if action in ("created", "added"):
            record_installation(inst_id, owner, repo_names)
        elif action == "deleted":
            remove_installation(inst_id)
        logger.info(f"Installation {action}: {owner} ({len(repos)} repos)")
        return {"status": "installation_recorded", "action": action, "repos": len(repos)}

    # Handle PR events
    if event == "pull_request" and payload.get("action") in ("opened", "synchronize"):
        pr = payload.get("pull_request", {})
        repo = payload.get("repository", {}).get("full_name", "")
        pr_number = pr.get("number")
        installation_id = payload.get("installation", {}).get("id", 0)

        # Rate limit check
        from guard_db import check_rate_limit, increment_usage
        rate = check_rate_limit(installation_id)
        if not rate["allowed"]:
            logger.warning(f"Rate limited: {repo} ({rate['used']}/{rate['limit']} today, tier={rate['tier']})")
            return {
                "status": "rate_limited",
                "tier": rate["tier"],
                "used": rate["used"],
                "limit": rate["limit"],
                "upgrade_url": "https://neuronx.jagatab.uk/guard#pricing",
            }

        logger.info(f"Reviewing PR #{pr_number} on {repo} (tier={rate['tier']}, {rate['remaining']} remaining)")
        stats["repos_installed"].add(repo)
        review_start = time.time()

        # Get auth token
        if installation_id:
            token = _get_installation_token(installation_id)
        else:
            token = os.getenv("GITHUB_TOKEN", "")

        if not token:
            return {"status": "error", "message": "No auth token available"}

        # Fetch diff
        try:
            diff_url = pr.get("diff_url", "")
            req = urllib.request.Request(diff_url, headers={"Authorization": f"token {token}"})
            diff_text = urllib.request.urlopen(req, timeout=20).read().decode()
        except Exception as e:
            return {"status": "error", "message": f"Cannot fetch diff: {e}"}

        # Get repo config
        config = get_repo_config(repo, token)
        if not config.get("enabled", True):
            return {"status": "skipped", "reason": "disabled in .neuronx-guard.yml"}

        # Review each file
        files = parse_diff(diff_text)
        all_issues = []
        for filename, diff in files:
            issues = review_file(filename, diff, config)
            all_issues.extend([(filename, i) for i in issues])

        # Post review
        comment = format_review_comment(repo, len(files), all_issues)
        commit_sha = pr.get("head", {}).get("sha", "")
        post_review(repo, pr_number, comment, token, all_issues, commit_sha)

        stats["reviews_completed"] += 1
        stats["issues_found"] += len(all_issues)

        # Record to database
        review_time = int((time.time() - review_start) * 1000)
        from guard_db import record_review, record_issue, increment_usage
        checks_used = list(set(i.get("check", "unknown") for _, i in all_issues))
        review_id = record_review(installation_id, repo, pr_number,
                                  len(files), len(all_issues), checks_used, review_time, True)
        for filename, issue in all_issues:
            record_issue(review_id, repo, filename,
                        issue.get("severity", "warning"), issue.get("check", "unknown"),
                        issue.get("message", ""))
        increment_usage(installation_id)

        return {
            "status": "reviewed",
            "repo": repo,
            "pr": pr_number,
            "files_reviewed": len(files),
            "issues_found": len(all_issues),
            "review_time_ms": review_time,
            "tier": rate["tier"],
            "remaining_today": rate["remaining"] - 1,
        }

    return {"status": "ignored", "event": event}


# --- Main ---

if __name__ == "__main__":
    logger.info(f"NeuronX Guard starting on port {GUARD_PORT}")
    logger.info(f"NeuronX API: {NEURONX_API}")
    logger.info(f"Webhook: http://0.0.0.0:{GUARD_PORT}/webhook")
    uvicorn.run(app, host="0.0.0.0", port=GUARD_PORT, log_level="info")

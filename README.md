# NeuronX Guard

**AI-powered code review for every GitHub Pull Request.**

[![Install](https://img.shields.io/badge/Install-GitHub%20App-orange)](https://github.com/apps/neuronx-guard)
[![Tests](https://img.shields.io/badge/Tests-17%20passing-green)]()
[![License](https://img.shields.io/badge/License-MIT-yellow)]()

22,000+ code patterns + LLM analysis + AST checking. Zero configuration. Free.

**[Install Now](https://github.com/apps/neuronx-guard)** | **[Landing Page](https://neuronx.jagatab.uk/guard)** | **[Live PR Review](https://github.com/sreejagatab/neuronx-platform/pull/1)**

---

## How It Works

```
Developer opens PR -> GitHub webhook -> NeuronX Guard reviews
  |-- Pattern matching (22K+ patterns)
  |-- AST analysis (syntax, complexity)
  |-- Security scan (secrets, SQL injection)
  |-- LLM deep review + fix suggestions (Groq/HuggingFace)
       -> Posts review comment on PR (inline + summary)
```

1. **Install** NeuronX Guard on your repo — [one click](https://github.com/apps/neuronx-guard)
2. **Open** a Pull Request
3. **Guard reviews** automatically using 4 layers
4. **See issues** inline on your PR with fix suggestions

---

## Features

| Feature | Description |
|---------|-------------|
| **4 Review Layers** | Pattern matching, AST analysis, security scan, LLM review |
| **Fix Suggestions** | Before/after code using GitHub suggested changes format |
| **Auto-Fix PRs** | Auto-commit safe fixes (bare excepts, etc.) via `/auto-fix` endpoint |
| **Custom Rules** | Define your own regex rules in `.neuronx-guard.yml` |
| **15 Languages** | Python, JavaScript, TypeScript, Go, Rust, Java, Ruby, PHP, and more |
| **Slack Integration** | Review summaries sent to your Slack channel (Team tier) |
| **Rate Limiting** | Per-installation daily limits by pricing tier |
| **Dashboard** | Review history, repo stats, badges per repo |
| **CLI Tool** | Review code locally before pushing |
| **Background Queue** | Webhook returns instantly, review runs in background |
| **Deduplication** | Marks updated reviews, avoids duplicate comments |
| **17 Unit Tests** | Config, diff parsing, review engine, formatting, rate limiting |

---

## Install

### GitHub App (recommended)
[**Install NeuronX Guard**](https://github.com/apps/neuronx-guard) — select repositories, done.

### CLI (local review)
```bash
git clone https://github.com/sreejagatab/neuronx-guard.git
cd neuronx-guard
pip install -r requirements.txt
python guard_cli.py src/          # Review a directory
python guard_cli.py --staged      # Review git staged files
python guard_cli.py api/main.py   # Review a single file
```

---

## Configuration

Add `.neuronx-guard.yml` to your repo root (optional — all checks enabled by default):

```yaml
enabled: true
checks:
  security: true
  complexity: true
  bare_except: true
  patterns: true
  llm_review: true
ignore_files:
  - "*.md"
  - "tests/*"
  - "docs/*"
severity_threshold: warning

# Custom rules (Pro feature)
custom_rules:
  - pattern: "TODO|FIXME|HACK"
    message: "Found TODO comment - resolve before merging"
    severity: info
  - pattern: "print\\("
    message: "Debug print() found - remove before production"
    severity: warning
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Redirect to landing page |
| GET | `/health` | Server health + review count |
| GET | `/stats` | Full analytics (installs, reviews, issues, top repos) |
| GET | `/pricing` | Pricing tiers (Free/Pro/Team) |
| GET | `/dashboard-ui` | Interactive dashboard page |
| GET | `/dashboard/{owner}/{repo}` | Review history for a repo (JSON) |
| GET | `/badge/{owner}/{repo}.svg` | Shields.io badge for repo |
| GET | `/rate-limit/{id}` | Check rate limit for installation |
| GET | `/billing/status` | Stripe billing status |
| GET | `/checkout/pro` | Stripe checkout for Pro tier |
| GET | `/checkout/team` | Stripe checkout for Team tier |
| POST | `/webhook` | GitHub webhook (main endpoint) |
| POST | `/backup` | Create DB backup |
| POST | `/auto-fix/{owner}/{repo}/{pr}` | Auto-commit fixes for a PR |
| POST | `/stripe/webhook` | Stripe payment webhook |

---

## Architecture

```
GitHub PR Event
       |
  POST /webhook (returns 200 immediately)
       |
       v (background thread)
  _process_pr_review()
       |
  +----+--------+------------+--------------+
  |    |        |            |              |
  v    v        v            v              v
Bare  Security  Complexity   Custom       LLM Review
Except Scan     Check (AST)  Rules        (NeuronX API)
  |    |        |            |              |
  +----+--------+------------+--------------+
       |
  Dedup check -> Format comment -> Post review -> Record DB -> Slack
```

---

## Pricing

| Tier | Price | Reviews/Day | Features |
|------|-------|------------|----------|
| **Free** | $0 | 20 | All 4 layers, unlimited repos, fix suggestions |
| **Pro** | $10/mo | 200 | Priority review, custom rules, email notifications, analytics |
| **Team** | $30/mo | 1,000 | Team dashboard, Slack integration, priority support |

---

## Badge

Add a NeuronX Guard badge to your README:

```markdown
![NeuronX Guard](https://your-guard-server/badge/owner/repo.svg)
```

Colors: green (no issues) | yellow | orange | red (many issues)

---

## Dashboard

- **Repo dashboard**: `/dashboard/{owner}/{repo}` — review history per repo
- **Analytics**: `/stats` — top repos, issue types, daily counts
- **Interactive UI**: `/dashboard-ui` — full dashboard page
- **Rate limits**: `/rate-limit/{installation_id}` — check usage

---

## Self-Hosted

```bash
git clone https://github.com/sreejagatab/neuronx-guard.git
cd neuronx-guard
cp .env.example .env
# Edit .env with your GitHub App credentials
pip install -r requirements.txt
python guard_server.py
```

Windows: double-click `START_GUARD.bat`

### Environment Variables
```
GITHUB_APP_ID=your_app_id
GITHUB_APP_PRIVATE_KEY_PATH=neuronx-guard.pem
GITHUB_WEBHOOK_SECRET=your_secret
NEURONX_API_URL=http://localhost:8000
STRIPE_SECRET_KEY=sk_live_xxx (optional)
SENTRY_DSN=https://xxx (optional)
```

---

## Test Results

Tested on [PR #1](https://github.com/sreejagatab/neuronx-platform/pull/1): **6 files, 21 issues found**

| File | Issues | Findings |
|------|--------|----------|
| test_guard_pr/example_code.py | 6 | Hardcoded password, API key, bare except, SQL injection |
| api/multi_source_collector.py | 3 | SQL injection, broad exception |
| engine/folder_engine.py | 3 | Insecure object reference |
| meta_evolution/*.py | 6 | Attribute errors, data loss |
| self_modification/*.py | 3 | Information disclosure |

All 4 layers fired. [View the live review](https://github.com/sreejagatab/neuronx-platform/pull/1#issuecomment-4170062869).

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Run tests (`python -m pytest tests/ -v`)
4. Commit changes
5. Open a Pull Request

---

## License

MIT License

---

**Built by [SreeJagatab](https://jagatab.uk)** | **[NeuronX Platform](https://neuronx.jagatab.uk)** | **sreejagatab@yahoo.com**

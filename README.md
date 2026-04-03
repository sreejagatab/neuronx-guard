# NeuronX Guard

**AI-powered code review for every GitHub Pull Request.**

[![Install](https://img.shields.io/badge/Install-GitHub%20App-orange)](https://github.com/apps/neuronx-guard)
[![Live](https://img.shields.io/badge/Live-neuronx.jagatab.uk%2Fguard-blue)](https://neuronx.jagatab.uk/guard)
![Guard](https://neuronx.jagatab.uk/api/github/badge/sreejagatab/neuronx-platform.svg)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

19 security patterns. 62 language rules. 14 languages. Multi-model LLM consensus. Dependency CVE scanning. Zero config. Free.

**[Install Now](https://github.com/apps/neuronx-guard)** | **[Homepage](https://neuronx.jagatab.uk/guard)** | **[Dashboard](https://neuronx.jagatab.uk/guard/dashboard)** | **[Live PR Review](https://github.com/sreejagatab/ClawdSaaS/pull/8)**

---

## How It Works

```
Developer opens PR -> GitHub webhook -> Redis queue -> Guard reviews
  |-- Security scan (19 rules: secrets, SQL injection, XSS, eval, pickle)
  |-- Language rules (62 rules across 14 languages)
  |-- AST complexity analysis
  |-- Multi-model LLM consensus (2-3 models vote)
  |-- Cross-file analysis (broken imports, duplicates)
  |-- Dependency CVE scan (OSV.dev — PyPI, npm, Go, Cargo, Gems, Packagist)
       -> Inline comments on exact lines + Check Run badge
```

1. **Install** NeuronX Guard on your repos — [one click](https://github.com/apps/neuronx-guard)
2. **Open** a Pull Request
3. **Guard reviews** automatically in seconds (6 review layers)
4. **See issues** inline on exact lines with consensus scores

---

## 6 Review Layers

| Layer | What It Catches |
|-------|----------------|
| **Security Scan** | Hardcoded secrets (OpenAI `sk-`, GitHub `ghp_`), SQL injection, eval/exec, pickle, timing attacks, command injection |
| **Language Rules** | 62 rules: JS (innerHTML, ==, var), Go (panic, unsafe), Rust (unwrap, transmute), Java, Ruby, PHP, Shell, C/C++, Kotlin, Swift |
| **LLM Consensus** | 2-3 free LLMs review independently — only reports issues 2+ models agree on. Near-zero false positives |
| **AST Analysis** | Python cyclomatic complexity, bare `except:` blocks, structural issues |
| **Cross-File** | Broken imports (function removed but still imported), duplicate definitions across files |
| **Dependency CVE** | Checks requirements.txt, package.json, go.mod, Cargo.toml against OSV.dev vulnerability database |

---

## Enhancements (E1-E15)

| # | Enhancement | Description |
|---|------------|-------------|
| E1 | LLM Consensus | 2-3 models vote, only report agreements |
| E2 | Dismiss Learning | Auto-suppress issues dismissed 3+ times |
| E3 | Exact Lines | Inline comments on the exact changed line |
| E4 | Cross-File | Detect broken imports + duplicate functions |
| E5 | Language Rules | 62 rules across 14 languages |
| E6 | CVE Scan | OSV.dev vulnerability check for 6 ecosystems |
| E7 | PR Quality | Flag empty descriptions, missing test plans |
| E8 | Suggested Reviewers | Recommend reviewers from git history |
| E9 | GitHub Actions CI | `POST /api/guard/ci-review` — no webhook needed |
| E10 | VS Code Extension | Real-time diagnostics on save |
| E11 | Reaction Feedback | Thumbs up/down trains quality scores |
| E12 | Redis Queue | Crash-resilient with 3x auto-retry |
| E13 | httpx Pooling | Connection pooling for GitHub API calls |
| E14 | SHA Cache | Skip duplicate reviews on same commit |
| E15 | Auto-Retry | Failed jobs retried every 5 minutes |

---

## PR Commands

| Command | Action |
|---------|--------|
| `/guard dismiss` | Dismiss review + feed dismiss learning |
| `/guard re-review` | Trigger fresh review |
| `/guard explain` | Detailed explanations with OWASP/CWE references |
| `/guard quality` | Show quality score (0-100, grade A-F) |
| `/guard leaderboard` | Developer ranking by cleanest code |
| `/guard report` | Compliance-ready markdown report |
| `/guard config` | Show current repo configuration |

---

## Integrations

### GitHub App (Recommended)
Install once, reviews happen on every PR automatically.

```
https://github.com/apps/neuronx-guard
```

### GitHub Actions CI
```yaml
- name: NeuronX Guard Review
  run: |
    DIFF=$(git diff origin/main...HEAD)
    curl -X POST https://neuronx.jagatab.uk/api/guard/ci-review \
      -H "Content-Type: application/json" \
      -d "{\"diff\": \"$DIFF\", \"repo\": \"$GITHUB_REPOSITORY\"}"
```

### API (Authenticated)
```bash
curl -X POST https://neuronx.jagatab.uk/api/guard/review \
  -H "X-Guard-Key: nxg_your_key" \
  -d '{"diff": "...", "repo": "owner/repo"}'
```

### VS Code Extension
```bash
cd vscode-extension && npm install && npx vsce package
code --install-extension neuronx-guard-1.0.0.vsix
```

---

## Pricing

| Tier | Price | Reviews/Day | Features |
|------|-------|------------|----------|
| **Free** | £0 | 20 | All 6 layers, unlimited repos, all PR commands |
| **Pro** | £10/mo | 200 | Custom rules, priority queue, compliance reports, analytics |
| **Team** | £30/mo | 1,000 | Team dashboard, Slack integration, org-wide analytics, priority support |

Payment powered by Stripe. Cancel anytime.

---

## Badge

Add a quality badge to your README:

```markdown
![Guard](https://neuronx.jagatab.uk/api/github/badge/OWNER/REPO.svg)
```

Shows live quality grade (A-F) with score. Updates on every review.

---

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/github/badge/{owner}/{repo}.svg` | Quality badge (SVG) |
| `GET /api/github/quality/{owner}/{repo}` | Quality score + trend |
| `GET /api/github/leaderboard/{owner}/{repo}` | Developer leaderboard |
| `GET /api/github/analytics/{owner}/{repo}` | Review history + averages |
| `GET /api/github/report/{owner}/{repo}/{pr}` | Compliance report |
| `POST /api/guard/ci-review` | CI review (public) |
| `POST /api/guard/review` | Authenticated review (API key) |
| `GET /api/guard/queue` | Queue status |
| `GET /api/github/status` | Guard integration status |

---

## Test Results

Tested on [ClawdSaaS PR #8](https://github.com/sreejagatab/ClawdSaaS/pull/8): **14 files, 10 languages, 84 issues found, 0 false positives**

| Check | Issues | Details |
|-------|--------|---------|
| Security patterns | 17 | Hardcoded creds, SQL injection, eval/exec, pickle, timing |
| Language rules | 37 | All 10 languages triggered (C, Go, Java, JS, Kotlin, PHP, Ruby, Rust, Shell, Swift) |
| Dependency CVEs | 28 | All 10 packages have known vulnerabilities |
| Cross-file | 1 | Duplicate function detected across files |
| PR quality | 2 | Missing test plan, no linked issue |
| AST complexity | 1 | Function with complexity=7 flagged |

---

## Architecture

```
GitHub PR Event
     |
  Webhook -> Redis Queue -> Queue Worker
                               |
                +--------------+--------------+
                |              |              |
          Security Scan   Lang Rules    LLM Consensus
          AST Analysis    Cross-File    Dep CVE Scan
          PR Quality      Dismiss       Line Mapping
                |              |              |
                +--------------+--------------+
                               |
                      Post to GitHub
                      Record in DB
                      Cache SHA
```

**Stack:** FastAPI, PostgreSQL (SQLite fallback), Redis, httpx, 19 free LLM providers

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

---

## License

MIT License

---

**Built by [SreeJagatab](https://jagatab.uk)** | **[NeuronX Platform](https://neuronx.jagatab.uk)** | **[LinkedIn](https://www.linkedin.com/in/sreejagatab/)** | **[X](https://x.com/SavingBargain)**

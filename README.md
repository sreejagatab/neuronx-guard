# NeuronX Guard

AI-powered code review for every GitHub Pull Request.

22,000+ code patterns + LLM analysis + AST checking — zero configuration.

## Install

1. Go to [GitHub App Install Page](https://github.com/apps/neuronx-guard)
2. Select repositories
3. Done — every PR gets AI review

## How It Works

```
Developer opens PR -> GitHub webhook -> NeuronX Guard -> Review comment on PR
```

NeuronX Guard reviews your code using:
- **22K+ real code patterns** from GitHub, HuggingFace, StackOverflow
- **AST analysis** for syntax, complexity, bare excepts
- **Security scan** for hardcoded secrets, SQL injection
- **LLM deep review** via Groq/HuggingFace (free)

## Configuration

Add `.neuronx-guard.yml` to your repo root (optional):

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
severity_threshold: warning
```

## Self-Hosted

```bash
# Clone and configure
git clone https://github.com/sreejagatab/neuronx-guard.git
cd neuronx-guard
cp .env.example .env
# Edit .env with your GitHub App credentials

# Run
python guard_server.py
```

## Test Results — Real PR Review

NeuronX Guard was tested on a [real Pull Request](https://github.com/sreejagatab/neuronx-platform/pull/1) with intentional code issues.

### Results: 6 files reviewed, 21 issues found

| File | Issues | Key Findings |
|------|--------|-------------|
| test_guard_pr/example_code.py | 6 | Hardcoded password, API key, bare except, SQL injection, div by zero |
| api/multi_source_collector.py | 3 | SQL injection in stats logging, broad exception handling |
| engine/folder_engine.py | 3 | Insecure object reference, data loss risk |
| meta_evolution/autonomous_code_model.py | 3 | Attribute error, documentation tracking |
| meta_evolution/autonomous_evolution_loop.py | 3 | Data loss, inconsistent error handling |
| self_modification/self_repair_engine.py | 3 | Information disclosure, broad exception |

### All 4 review layers fired:
- **AST Check**: Detected bare `except:` blocks
- **Security Scan**: Found hardcoded password (`DATABASE_PASSWORD`) and API key (`sk-proj-*`)
- **Pattern Search**: Found similar high-quality pattern (quality=1.00)
- **LLM Review**: Identified SQL injection, division by zero, complexity issues

[View the live review comment on GitHub](https://github.com/sreejagatab/neuronx-platform/pull/1#issuecomment-4170062869)

---

## Powered by NeuronX

NeuronX Guard is powered by the [NeuronX Platform](https://github.com/sreejagatab/neuronx-platform) — a self-evolving AI that learns from code 24/7.

---

Built by [SreeJagatab](https://jagatab.uk)(https://github.com/sreejagatab) | [neuronx.jagatab.uk](https://neuronx.jagatab.uk)

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

## Powered by NeuronX

NeuronX Guard is powered by the [NeuronX Platform](https://github.com/sreejagatab/neuronx-platform) — a self-evolving AI that learns from code 24/7.

---

Built by [Ganesh Jagatab](https://github.com/sreejagatab) | [neuronx.jagatab.uk](https://neuronx.jagatab.uk)

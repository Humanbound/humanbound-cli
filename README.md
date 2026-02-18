# Humanbound CLI

> CLI-first security testing for AI agents and chatbots. Adversarial attacks, behavioral QA, posture scoring, and guardrails export — from your terminal to your CI/CD pipeline.

[![PyPI](https://img.shields.io/pypi/v/humanbound-cli)](https://pypi.org/project/humanbound-cli/)
[![License](https://img.shields.io/badge/license-proprietary-blue)]()
[![Version](https://img.shields.io/badge/version-0.4.0-green)]()

```
pip install humanbound-cli
```

---

## Overview

Humanbound runs automated adversarial attacks against your bot's live endpoint, evaluates responses using LLM-as-a-judge, and produces structured findings aligned with the [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) and the [OWASP Agentic AI Threats](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/).

### Platform Services

| Service | Description |
|---------|-------------|
| **CLI Tool** | Full-featured command line interface. Initialize projects, run tests, check posture, export guardrails. |
| **pytest Plugin** | Native pytest integration with markers, fixtures, and baseline comparison. Run security tests alongside unit tests. |
| **Adversarial Testing** | OWASP-aligned attack scenarios: single-turn, multi-turn, adaptive, and agentic. |
| **Behavioral Testing** | Validate intent boundaries, response quality, and functional correctness. |
| **Posture Scoring** | Quantified 0-100 security score with breakdown by findings, coverage, and resilience. Track over time. |
| **Shadow AI Discovery** | Scan cloud tenants for AI services, assess risk with 15 SAI threat classes, and govern your AI inventory. |
| **Guardrails Export** | Generate protection rules from test findings. Export to OpenAI, Azure AI Content Safety, AWS Bedrock, or Humanbound format. |

### Why Humanbound?

Manual red-teaming doesn't scale. Static analysis can't catch runtime behavior. Generic pentesting tools don't understand LLM-specific attack vectors like prompt injection, jailbreaks, or tool abuse.

Humanbound is built for this. Point it at your bot's endpoint, define the scope (or let it extract one from your system prompt), and get a structured security report with actionable findings — all mapped to OWASP LLM and Agentic AI categories.

Testing feeds into hardening: export guardrails, track posture across releases, and catch regressions before they reach production. Works with any chatbot or agent, cloud or on-prem.

---

## Get Started

### 1. Install & authenticate

```bash
pip install humanbound-cli
hb login
```

### 2. Scan your bot & create a project

`hb init` scans your bot, extracts its scope and risk profile, and creates a project — all in one step. Point it at one or more sources:

```bash
# From a system prompt file
hb init -n "My Bot" --prompt ./system_prompt.txt

# From a live bot endpoint (API probing)
hb init -n "My Bot" -e ./bot-config.json

# From a live URL (browser discovery)
hb init -n "My Bot" -u https://my-bot.example.com

# Combine sources for better analysis
hb init -n "My Bot" --prompt ./system.txt -e ./bot-config.json
```

The `--endpoint/-e` flag accepts a JSON config (file or inline string) matching the experiment integration shape:

```json
{
  "streaming": false,
  "thread_auth": {"endpoint": "", "headers": {}, "payload": {}},
  "thread_init": {"endpoint": "https://bot.com/threads", "headers": {}, "payload": {}},
  "chat_completion": {"endpoint": "https://bot.com/chat", "headers": {"Authorization": "Bearer token"}, "payload": {"content": "$PROMPT"}}
}
```

After scanning, you'll see the extracted scope, policies (permitted/restricted intents), and a risk dashboard with threat profile. Confirm to create the project.

### 3. Run a security test

```bash
# Run against your bot (uses project's default integration if configured during init)
hb test

# Or specify an endpoint directly
hb test -e ./bot-config.json

# Choose test category and depth
hb test -t humanbound/adversarial/owasp_multi_turn -l system
```

### 4. Review results

```bash
# Watch experiment progress
hb status --watch

# View logs
hb logs

# Check posture score
hb posture

# Export guardrails
hb guardrails --vendor openai -o guardrails.json
```

---

## Test Categories

| Category | Mode | Description |
|----------|------|-------------|
| `owasp_single_turn` | Adversarial | Single-prompt attacks: prompt injection, jailbreaks, data exfiltration. Fast coverage of basic vulnerabilities. |
| `owasp_multi_turn` | Adversarial | Conversational attacks that build context over multiple turns. Tests context manipulation and gradual escalation. |
| `owasp_agentic_multi_turn` | Adversarial | Targets tool-using agents. Tests goal hijacking, tool misuse, and privilege escalation. |
| `behavioral` | QA | Intent boundary validation and response quality testing. Ensures agent behaves within defined scope. |

**Adaptive mode:** Both `owasp_multi_turn` and `owasp_agentic_multi_turn` support an adaptive flag that enables evolutionary search — the attack strategy adapts based on bot responses instead of following scripted prompts.

### Testing Levels

| Level | Description |
|-------|-------------|
| `unit` | Standard coverage (~20 min) — default |
| `system` | Deep testing (~45 min) |
| `acceptance` | Full coverage (~90 min) |

---

## pytest Integration

Run security tests alongside your existing test suite with native pytest markers and fixtures.

```python
# test_security.py
import pytest

@pytest.mark.hb
def test_prompt_injection(hb):
    """Test prompt injection defenses."""
    result = hb.test("llm001")
    assert result.passed, f"Failed: {result.findings}"

@pytest.mark.hb
def test_posture_threshold(hb_posture):
    """Ensure posture meets minimum."""
    assert hb_posture["score"] >= 70

@pytest.mark.hb
def test_no_regressions(hb, hb_baseline):
    """Compare against baseline."""
    result = hb.test("llm001")
    if hb_baseline:
        regressions = result.compare(hb_baseline)
        assert not regressions
```

```bash
# Run with Humanbound enabled
pytest --hb tests/

# Filter by category
pytest --hb --hb-category=adversarial

# Set failure threshold
pytest --hb --hb-fail-on=high

# Compare to baseline
pytest --hb --hb-baseline=baseline.json

# Save new baseline
pytest --hb --hb-save-baseline=baseline.json
```

---

## CI/CD Integration

Block insecure deployments automatically with exit codes.

```
Build -> Unit Tests -> AI Security (hb test) -> Deploy
```

```yaml
# .github/workflows/security.yml
name: AI Security Tests
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install humanbound-cli
      - name: Run Security Tests
        env:
          HUMANBOUND_API_KEY: ${{ secrets.HUMANBOUND_API_KEY }}
        run: |
          hb test --wait --fail-on=high
```

---

## Usage

```
hb [--base-url URL] COMMAND [OPTIONS] [ARGS]
```

### Authentication

| Command | Description |
|---------|-------------|
| `login` | Authenticate via browser (OAuth PKCE) |
| `logout` | Clear stored credentials |
| `whoami` | Show current authentication status |

### Organisation Management

| Command | Description |
|---------|-------------|
| `orgs list` | List available organisations |
| `orgs current` | Show current organisation |
| `switch <id>` | Switch to organisation |

### Provider Management

Providers are LLM configurations used for running security tests.

| Command | Description |
|---------|-------------|
| `providers list` | List configured providers |
| `providers add` | Add new provider |
| `providers update <id>` | Update provider config |
| `providers remove <id>` | Remove provider |

<details>
<summary><code>providers add</code> options</summary>

```
--name, -n        Provider name: openai, claude, azureopenai, gemini, grok, custom
--api-key, -k     API key
--endpoint, -e    Endpoint URL (required for azureopenai, custom)
--model, -m       Model name (optional)
--default         Set as default provider
--interactive     Interactive configuration mode
```

</details>

### Project Management

| Command | Description |
|---------|-------------|
| `projects list` | List projects |
| `projects use <id>` | Select project |
| `projects current` | Show current project |
| `projects show [id]` | Show project details |
| `projects update [id]` | Update project name/description |
| `projects delete [id]` | Delete project (with confirmation) |

<details>
<summary><code>init</code> — scan bot & create project</summary>

```
hb init --name NAME [OPTIONS]

Sources (at least one required):
  --prompt, -p PATH       System prompt file (text source)
  --url, -u URL           Live bot URL for browser discovery (url source)
  --endpoint, -e CONFIG   Bot integration config — JSON string or file path (endpoint source)
  --repo, -r PATH         Repository path to scan (agentic or text source)
  --openapi, -o PATH      OpenAPI spec file (text source)

Options:
  --description, -d       Project description
  --timeout, -t SECONDS   Scan timeout (default: 180)
  --yes, -y               Auto-confirm project creation (no interactive prompts)
```

</details>

### Test Execution

<details>
<summary><code>test</code> — run security tests on current project</summary>

```
hb test [OPTIONS]

Test Category:
  --test-category, -t   Test to run (default: owasp_multi_turn)
                        Values: owasp_single_turn, owasp_multi_turn,
                                owasp_agentic_multi_turn, behavioral

Testing Level:
  --testing-level, -l   Depth of testing (default: unit)
                        unit | system | acceptance

Endpoint Override (optional — only needed if no default integration):
  -e, --endpoint        Bot integration config — JSON string or file path.
                        Same shape as 'hb init --endpoint'. Overrides default.

Other:
  --provider-id         Provider to use (default: first available)
  --name, -n            Experiment name (auto-generated if omitted)
  --lang                Language (default: english). Accepts codes: en, de, es...
  --adaptive            Enable adaptive mode (evolutionary attack strategy)
  --no-auto-start       Create without starting (manual mode)
  --wait, -w            Wait for completion
  --fail-on SEVERITY    Exit non-zero if findings >= severity
                        Values: critical, high, medium, low, any
```

</details>

### Experiment Management

| Command | Description |
|---------|-------------|
| `experiments list` | List experiments |
| `experiments show <id>` | Show experiment details |
| `experiments status <id>` | Check status |
| `experiments status <id> --watch` | Watch until completion |
| `experiments wait <id>` | Wait with progressive backoff (30s -> 60s -> 120s -> 300s) |
| `experiments logs <id>` | List experiment logs |
| `experiments terminate <id>` | Stop a running experiment |
| `experiments delete <id>` | Delete experiment (with confirmation) |

`status` is also available as a top-level alias — without an ID it shows the most recent experiment:

```bash
hb status [experiment_id] [--watch]
```

### Findings

Track long-term security vulnerabilities across experiments.

| Command | Description |
|---------|-------------|
| `findings` | List findings (filterable by --status, --severity) |
| `findings update <id>` | Update finding status or severity |

Finding states: **open** → **stale** (30+ days unseen) → **fixed** (resolved). Findings can also **regress** (was fixed, reappeared).

### Coverage

| Command | Description |
|---------|-------------|
| `coverage` | Test coverage summary |
| `coverage --gaps` | Include untested categories |

### Campaigns

Continuous security assurance with automated campaign management (ASCAM).

| Command | Description |
|---------|-------------|
| `campaigns` | Show current campaign plan |
| `campaigns break` | Stop a running campaign |

ASCAM phases: Reconnaissance → Hardening → Red Teaming → Analysis → Monitoring

### Shadow AI Discovery

Discover, assess, and govern AI services across your cloud environment.

| Command | Description |
|---------|-------------|
| `discover` | Scan cloud tenant for AI services |

Options: `--save` (persist to inventory), `--report` (HTML report), `--json` (JSON output), `--verbose` (raw API responses)

### Cloud Connectors

Register cloud connectors for persistent, repeatable discovery.

| Command | Description |
|---------|-------------|
| `connectors` | List registered connectors |
| `connectors add` | Register a new cloud connector |
| `connectors test <id>` | Test connector connectivity |
| `connectors update <id>` | Update connector credentials |
| `connectors remove <id>` | Remove connector |

<details>
<summary><code>connectors add</code> options</summary>

```
--vendor            Cloud vendor (default: microsoft)
--tenant-id         Cloud tenant ID (required)
--client-id         App registration client ID (required)
--client-secret     App registration client secret (prompted)
--name              Display name for the connector
```

</details>

### AI Inventory

View and govern discovered AI assets.

| Command | Description |
|---------|-------------|
| `inventory` | List all inventory assets |
| `inventory view <id>` | View asset details |
| `inventory update <id>` | Update governance fields |
| `inventory posture` | View shadow AI posture score |
| `inventory onboard <id>` | Create security testing project from asset |
| `inventory archive <id>` | Archive an asset |

Options for `inventory`: `--category`, `--risk-level`, `--json`

Options for `inventory update`: `--sanctioned / --unsanctioned`, `--owner`, `--department`, `--business-purpose`, `--has-policy / --no-policy`, `--has-risk-assessment / --no-risk-assessment`

### Upload Conversation Logs

Evaluate real production conversations against security judges.

| Command | Description |
|---------|-------------|
| `upload-logs <file>` | Upload JSON conversation logs |

Options: `--tag`, `--lang`

### API Keys

| Command | Description |
|---------|-------------|
| `api-keys list` | List API keys |
| `api-keys create` | Create new key (--name required, --scopes: admin/write/read) |
| `api-keys update <id>` | Update key name, scopes, or active state |
| `api-keys revoke <id>` | Revoke (delete) an API key |

### Members

| Command | Description |
|---------|-------------|
| `members list` | List organisation members |
| `members invite <email>` | Invite member (--role: admin/developer) |
| `members remove <id>` | Remove member |

### Results & Export

```bash
# View experiment results
hb logs [experiment_id] [--format table|json|html] [--verdict pass|fail] [--page N] [--size N]

# Export branded HTML report
hb logs <experiment_id> --format=html [-o report.html]

# Security posture
hb posture [--json] [--trends]

# Test coverage
hb coverage [--gaps] [--json]

# Findings
hb findings [--status open] [--severity high] [--json]

# Export guardrails configuration
hb guardrails [--vendor humanbound|openai] [--format json|yaml] [-o FILE]
```

### Documentation

```bash
hb docs
```

Opens documentation in browser.

---

## Examples

### End-to-end: scan, create project, test, review

```bash
hb login
hb switch abc123

# Scan bot & create project (uses endpoint config file)
hb init -n "Support Bot" -e ./bot-config.json

# Run adversarial test (uses project's default integration)
hb test -t humanbound/adversarial/owasp_multi_turn -l unit

# Watch and review
hb status --watch
hb logs
hb posture
```

### Multi-source project init

```bash
# Combine system prompt + live endpoint for best scope extraction
hb init \
  --name "Support Bot" \
  --prompt ./prompts/system.txt \
  --endpoint ./bot-config.json

# From repository + OpenAPI spec
hb init \
  --name "API Agent" \
  --repo ./my-agent \
  --openapi ./openapi.yaml
```

### Bot config with auth + thread init

```json
{
  "streaming": false,
  "thread_auth": {
    "endpoint": "https://bot.com/oauth/token",
    "headers": {},
    "payload": {"client_id": "x", "client_secret": "y"}
  },
  "thread_init": {
    "endpoint": "https://bot.com/threads",
    "headers": {"Content-Type": "application/json"},
    "payload": {}
  },
  "chat_completion": {
    "endpoint": "https://bot.com/chat",
    "headers": {"Content-Type": "application/json"},
    "payload": {"messages": [{"role": "user", "content": "$PROMPT"}]}
  }
}
```

```bash
# Use with init or test
hb init -n "My Bot" -e ./bot-config.json
hb test -e ./bot-config.json
```

### Shadow AI discovery & governance

```bash
# Register a cloud connector
hb connectors add --tenant-id abc --client-id def --client-secret

# Scan, save to inventory, and export report
hb discover --save --report

# Review and govern assets
hb inventory
hb inventory update <id> --sanctioned --owner "security@company.com"

# Onboard high-risk asset for security testing
hb inventory onboard <id>
hb test
```

### Export guardrails

```bash
hb guardrails --vendor openai --format json -o guardrails.json
```

---

### On-Premises

```bash
export HUMANBOUND_BASE_URL=https://api.your-domain.com
hb login
```

### Files

| Path | Description |
|------|-------------|
| `~/.humanbound/` | Configuration directory |
| `~/.humanbound/credentials.json` | Auth tokens (mode `600`) |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Error or test failure (with `--fail-on`) |

---

## Links

- [Documentation](https://docs.humanbound.ai)
- [GitHub](https://github.com/Humanbound/humanbound-cli)

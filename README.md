# LogScrub

Pre-scrub sensitive data from text, JSON, and CSV files before feeding them to AI tools, logging systems, or sharing with third parties.

---

## Features

- **20 built-in patterns** — credentials, PII, financial, and network data
  - JWTs, bearer tokens, OpenAI / Anthropic / GitHub / AWS / Stripe / Slack / SendGrid / Google API keys
  - Email, SSN, phone, US passport, IBAN, credit card (Luhn-validated)
  - IPv4, MAC address, URL credentials
- **5 mask styles** — `partial`, `label`, `full`, `redacted`, `token`
- **Confidence threshold** — filter out low-confidence / noisy patterns
- **Token mode** — reversible, consistent pseudonymisation across a document
- **Policy profiles** — GDPR, HIPAA, SOC2, Minimal, or save your own (JSON/YAML)
- **Profile import/export** — share profiles with your team via files
- **Allowlist** — exempt specific values from masking
- **Custom patterns** — add your own regex rules in the GUI or via the CLI
- **Large file support** — handles files up to 256 KB in the editor (full file always scrubbed)
- **Batch scrub** — process entire directory trees with a progress bar and dry-run mode
- **Audit log** — export findings as JSON or CSV
- **Desktop GUI** — PySide6, dark theme, drag-and-drop
- **CLI** — full-featured command-line interface
- **Standalone binary** — distributed as a single executable via PyInstaller

---

## Installation

### pip

```bash
pip install logscrub
```

> Requires Python 3.11+. Installs both the `logscrub` CLI and `logscrub-gui` launcher.

### Headless (CLI only — no PySide6)

```bash
pip install "logscrub[headless]"
```

### Standalone binary

Download the latest release binary from the [Releases](https://github.com/USERNAME/logscrub/releases) page. No Python required.

---

## Quick start

### GUI

```bash
logscrub-gui
# or
logscrub gui
```

Drag and drop a file onto the input area, or open one with **Ctrl+O**. Masked output appears in real time.

### CLI — scrub stdin

```bash
echo "My email is alice@example.com" | logscrub scrub -
```

### CLI — scrub a file

```bash
logscrub scrub secrets.txt -o scrubbed.txt
```

### CLI — dry run (preview findings, write nothing)

```bash
logscrub scrub config.json --dry-run
```

### CLI — batch scrub a directory

```bash
logscrub batch ./logs ./logs-scrubbed --audit audit.json
```

---

## CLI reference

```
logscrub scrub [INPUT] [OPTIONS]
  INPUT                 File path or '-' for stdin (default: stdin)
  -o, --output PATH     Output file or '-' for stdout
  --format              auto|text|json|csv  (default: auto)
  --mask-style          partial|label|full|redacted|token
  --mask-char CHAR      Replacement character (default: *)
  --profile NAME        Apply a named or file-path profile
  --disable PATTERN…    Disable one or more patterns by name
  --allowlist VALUE…    Never mask these literal values
  --min-confidence 0-1  Skip patterns below this confidence level
  --token-map PATH      Read/write token map for --mask-style token
  --audit PATH          Write audit log (.json or .csv)
  --dry-run             Show findings without writing output
  -q, --quiet           Suppress stderr progress messages

logscrub batch SRC DST [OPTIONS]
  (same flags as scrub, plus --audit)

logscrub profiles       List available profiles
logscrub gui            Launch desktop GUI
```

---

## Mask styles

| Style | Example output |
|---|---|
| `partial` | `a***@example.com` |
| `label` | `[EMAIL]` |
| `full` | `*****************` |
| `redacted` | `[REDACTED]` |
| `token` | `<EMAIL_1>` (consistent across document) |

---

## Profiles

Profiles capture a complete set of scrub settings (mask style, mask char, disabled patterns, allowlist). Built-in profiles:

| Profile | Style | Notes |
|---|---|---|
| GDPR | redacted | All patterns enabled |
| HIPAA | token | Consistent pseudonymisation of PHI |
| SOC2 | partial | Credentials + PII, IPv4 off |
| Minimal | partial | High-confidence patterns only |

Save a custom profile from the GUI sidebar, or via the CLI after scrubbing. Import/export profiles as JSON or YAML to share with your team.

---

## Pattern confidence

Patterns that tend to produce false positives carry a confidence score below 1.0. Use `--min-confidence` to exclude them:

| Pattern | Confidence | Reason |
|---|---|---|
| `us_passport` | 0.60 | Matches many 9-character alphanumeric strings |
| `ipv4` | 0.70 | Version numbers, IDs, etc. can look like IPs |
| `iban` | 0.75 | Short uppercase+digit strings are common |
| `generic_credential` | 0.80 | Key=value heuristics have some noise |
| `sendgrid_key` | 0.90 | Long SG.xxx.xxx strings are fairly specific |
| All others | 1.00 | High-specificity patterns |

---

## Development

```bash
git clone https://github.com/USERNAME/logscrub
cd logscrub
python -m venv .venv && source .venv/bin/activate
pip install -e ".[headless]" pyside6 pyyaml pytest
python -m pytest
```

### Build standalone binary

```bash
pip install pyinstaller
pyinstaller logscrub.spec --clean
./dist/logscrub
```

---

## License

MIT

# cli-anything-mobsf — Design, Implementation & Installation Guide

## Table of Contents

1. [Overview](#overview)
2. [Design](#design)
   - [Architecture](#architecture)
   - [Analysis Pipeline](#analysis-pipeline)
   - [Attack Surface Scanner](#attack-surface-scanner)
   - [Intelligent Objection Patcher](#intelligent-objection-patcher)
   - [MobSF API Integration](#mobsf-api-integration)
3. [Implementation](#implementation)
   - [Package Structure](#package-structure)
   - [Module Reference](#module-reference)
   - [Bundled Scripts](#bundled-scripts)
   - [Configuration & Environment](#configuration--environment)
   - [Error Handling](#error-handling)
4. [Installation](#installation)
   - [Prerequisites](#prerequisites)
   - [Core Installation](#core-installation)
   - [System Dependencies](#system-dependencies)
   - [MobSF Setup](#mobsf-setup)
   - [Verification](#verification)
5. [Usage Guide](#usage-guide)
   - [Full Analysis Pipeline](#full-analysis-pipeline)
   - [Standalone Commands](#standalone-commands)
   - [REPL Mode](#repl-mode)
6. [Extending](#extending)

---

## Overview

cli-anything-mobsf is a command-line harness for the Mobile Security Framework (MobSF) that integrates automated static analysis with a local reverse engineering toolchain. It is built using the [CLI-Anything](https://github.com/hkuds/cli-anything) methodology — a stateful Click CLI with one-shot subcommands, REPL mode, JSON output, and session state management.

The tool addresses a common workflow problem in mobile application security testing: the analysis process involves multiple disconnected tools (MobSF, JADX, APKtool, binwalk, APKiD, Objection) that each produce output in different formats and locations. cli-anything-mobsf unifies these into a single pipeline where each stage's output informs the next, culminating in an intelligently configured Objection/Frida-patched APK ready for dynamic analysis.

---

## Design

### Architecture

The system follows a layered architecture:

```
┌─────────────────────────────────────────────────────────┐
│                    CLI Layer (Click)                      │
│  mobsf_cli.py — commands, flags, REPL, output formatting │
├─────────────────────────────────────────────────────────┤
│                   Core Layer                              │
│  analyse.py      — pipeline orchestration                 │
│  attack_surface.py — categorised pattern scanning         │
│  objection_patcher.py — intelligent patching decisions    │
│  session.py      — state management with undo/redo        │
├─────────────────────────────────────────────────────────┤
│                  Backend Layer                             │
│  mobsf_backend.py — MobSF REST API wrapper                │
├─────────────────────────────────────────────────────────┤
│                 Bundled Scripts                            │
│  classcountm.sh, libcount.sh, searchstrings.sh,          │
│  sign-apk.sh, ObjectionPatch.sh, searchstrings.dic       │
└─────────────────────────────────────────────────────────┘
```

**Design principles:**

- **Pipeline composition** — each stage produces artifacts that subsequent stages consume. The objection patcher reads MobSF reports, APKiD fingerprints, and attack surface findings to make patching decisions.
- **Graceful degradation** — missing tools cause individual stage failures, not pipeline failures. Each stage is wrapped in a try/except and recorded in the summary.
- **Self-contained packaging** — all helper scripts and dictionaries are bundled inside the Python package. No external script paths required.
- **Dual-mode operation** — every feature works both as a one-shot CLI command and within the interactive REPL.

### Analysis Pipeline

The `analyse` command orchestrates 8 stages in sequence:

```
 APK File
    │
    ▼
┌──────────┐     ┌────────────┐     ┌──────────┐
│  1. MobSF │────▶│ 2. JADX    │────▶│ 3. APKiD │
│  upload,  │     │ decompile  │     │ fingerpr.│
│  scan,    │     │ to Java    │     │          │
│  report   │     │ source     │     │          │
└──────────┘     └────────────┘     └──────────┘
                       │
                       ▼
              ┌────────────────┐     ┌───────────────┐
              │ 4. Native Libs │────▶│ 5. APKtool    │
              │ readelf,       │     │ smali disasm,  │
              │ binwalk,       │     │ class counts,  │
              │ strings        │     │ API grep,      │
              └────────────────┘     │ ATTACK SURFACE │
                                     └───────────────┘
                                            │
                    ┌───────────────────────┐│
                    ▼                       ▼│
              ┌───────────┐     ┌────────────────────┐
              │6. Repackage│     │ 7. AppShield       │
              │ re-sign    │     │ APK Defender build  │
              │ test       │     │                     │
              └───────────┘     └────────────────────┘
                                            │
                                            ▼
                              ┌──────────────────────┐
                              │ 8. Objection Patch   │
                              │ reads ALL artifacts  │
                              │ auto-generates Frida │
                              │ bypass scripts       │
                              └──────────────────────┘
                                            │
                                            ▼
                                      summary.json
```

**Data flow between stages:**

| Producer | Consumer | Data |
|----------|----------|------|
| MobSF | Objection Patcher | main_activity, target_sdk, package_name, size |
| MobSF | Objection Patcher | APKiD fingerprints (packers, obfuscators) |
| MobSF | Summary | scorecard findings counts |
| JADX | Native Libs | decompiled `res/lib/` directory |
| APKtool | Attack Surface | smali directories for pattern scanning |
| APKtool | Objection Patcher | AndroidManifest.xml for Application class |
| Attack Surface | Objection Patcher | TLS pinning, root detection, anti-debug findings |
| Native Libs | Objection Patcher | available ABIs |
| All stages | Summary | stage status, timing, error details |

### Attack Surface Scanner

The scanner (`attack_surface.py`) replaces the simple grep-based `searchstrings.sh` approach with a categorised, risk-ranked analysis. It is designed around the OWASP Mobile Top 10 and common Android attack vectors.

**Design:**

```
searchstrings.dic (272 patterns, flat)
        │
        ▼  replaced by
CATEGORIES dict (22 categories, 270+ patterns)
Each pattern has:
  - literal search string
  - human-readable description
  - parent category with risk level
```

**22 categories grouped by risk:**

| Risk Level | Categories | Rationale |
|------------|-----------|-----------|
| CRITICAL | Network & TLS, Hardcoded Credentials, Financial & Payment | Direct path to data breach or account compromise |
| HIGH | Cryptography, Authentication, WebView, Data Storage, IPC, PII, Tamper Detection, Cloud Services | Exploitable with moderate effort, significant impact |
| MEDIUM | Root Detection, Emulator Detection, Anti-Debug, Hooking Detection, Logging, Clipboard | Relevant to analysis methodology, moderate direct risk |
| INFO | HTTP Client Libraries, Protection Vendors, Analytics SDKs | Informational for understanding the app's technology stack |

**Output format:**

The scanner produces three files to serve different audiences:

1. `attack_surface_summary.txt` — executive summary with risk distribution table, category ranking, and auto-generated "Key Attack Vectors" section highlighting the most dangerous findings
2. `attack_surface_report.txt` — full detailed report sorted by risk then volume, with every pattern match, file paths, and line numbers
3. `attack_surface.json` — machine-readable JSON for programmatic consumption or further processing

The summary auto-detects and highlights specific dangerous patterns:
- `ALLOW_ALL_HOSTNAME_VERIFIER` or empty `checkServerTrusted` → TLS vulnerability
- `addJavascriptInterface` → WebView RCE vector
- `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` → data exposure
- High counts of logging statements → information leakage

### Intelligent Objection Patcher

The patcher (`objection_patcher.py`) is the key differentiator from running `objection patchapk` manually. It reads all prior analysis artifacts and makes 10 configuration decisions:

**Decision matrix:**

| Decision | Input Artifacts | Logic |
|----------|----------------|-------|
| Architecture | `native/elf/` directories | Pick from ABIs that actually have .so files; prefer arm64-v8a |
| Target class | `AndroidManifest.xml`, MobSF report | Prefer Application subclass (loads earliest) over main activity |
| Network security config | Attack surface (TLS patterns), MobSF report (target SDK) | Enable if CertificatePinner/TrustManager detected OR targetSdk >= 24 |
| Enable debug | Attack surface (anti-debug) | Always enable for analysis; log if anti-debug was detected |
| Use aapt2 | — | Always (modern default) |
| Skip resources | APKiD (packers), MobSF report (APK size), network security config decision | Skip for very large APKs, BUT NOT if network security config is needed (it modifies resources) |
| Gadget config | Script source decision | Set to "script" mode if auto-bypass script was generated |
| Script source | Attack surface (all protection categories) | Generate targeted Frida bypass script based on detected protections |
| Ignore nativelibs | APKiD (DexProtector, DexGuard) | Enable when packers compress native libs (avoids extraction failure) |
| Concurrency | MobSF report (APK size) | Limit to 1 thread for APKs > 100MB to prevent OOM |

**Auto-generated Frida script:**

The patcher generates a startup script (`libfrida-gadget.script.so`) that auto-loads when the patched APK launches. The script contents are determined by what the attack surface scanner found:

| Detection | Bypass Generated |
|-----------|-----------------|
| CertificatePinner, X509TrustManager, checkServerTrusted | SSL pinning bypass: custom TrustManager + OkHttp CertificatePinner hook |
| RootBeer library | RootBeer-specific bypass: hooks all 12 detection methods to return false |
| Generic root checks (su paths, build tags) | Generic root bypass: hooks Runtime.exec, File.exists, Build.TAGS |
| isDebuggerConnected, TracerPid, ptrace | Anti-debug bypass: hooks Debug class and /proc/self/status reader |
| Xposed/Frida detection references | Anti-hooking bypass: hooks debugger connection and TracerPid checks |

All decisions are logged to `objection/patching_decisions.json` with the reasoning, and the exact objection command is saved to `objection/objection_command.txt` for reproducibility.

### MobSF API Integration

The backend wrapper (`mobsf_backend.py`) covers 30+ MobSF REST API endpoints across:

- **Static analysis**: upload, scan, scans, search, delete, logs, tasks
- **Reports**: report_json, scorecard, download_pdf
- **Source & comparison**: view_source, compare
- **Suppressions**: list, add by rule, add by files, delete
- **Android dynamic analysis**: get_apps, start, stop, report, logcat, mobsfy, screenshot, activity_test, tls_tests
- **Frida**: instrument, logs, api_monitor, list_scripts, get_dependencies

**Authentication** is handled automatically:
1. `--api-key` flag (highest priority)
2. `MOBSF_API_KEY` environment variable
3. Auto-derivation from `~/.MobSF/secret` or `~/.mobsf/secret` (SHA-256 of the secret file content)

---

## Implementation

### Package Structure

```
cli-anything-mobsf/
├── setup.py                              # Package installer
├── README.md                             # Project overview
├── MOBSF.md                              # Command reference
├── LICENSE                               # MIT license
├── docs/
│   └── GUIDE.md                          # This document
└── cli_anything/
    └── mobsf/
        ├── __init__.py                   # Namespace package marker
        ├── __main__.py                   # python -m cli_anything.mobsf support
        ├── mobsf_cli.py                  # CLI entry point (Click commands)
        ├── README.md                     # Package readme
        ├── core/
        │   ├── __init__.py
        │   ├── analyse.py               # AnalysisPipeline class
        │   ├── attack_surface.py         # Attack surface scanner
        │   ├── objection_patcher.py      # ObjectionPatcher class
        │   └── session.py                # Session state with undo/redo
        ├── utils/
        │   ├── __init__.py
        │   └── mobsf_backend.py          # MobSFBackend REST API wrapper
        ├── scripts/
        │   ├── __init__.py               # script_path() and dictionary_path()
        │   ├── classcountm.sh            # Smali class counter (excl. framework)
        │   ├── libcount.sh               # Native library counter
        │   ├── searchstrings.sh          # Pattern grep in smali files
        │   ├── searchstringswithfilenames.sh  # Pattern grep with file names
        │   ├── sign-apk.sh              # APK re-signing with custom keystore
        │   ├── ObjectionPatch.sh         # Standalone objection wrapper
        │   └── searchstrings.dic         # 272-entry search pattern dictionary
        └── tests/
            ├── __init__.py
            └── test_core.py              # Unit tests
```

### Module Reference

#### `mobsf_cli.py`

The CLI entry point. Defines a Click group with `invoke_without_command=True` — running without a subcommand enters REPL mode. All subcommands use `@click.pass_context` to share state from the root group (URL, API key, JSON flag).

Key design decisions:
- Root context `obj` dict is shared via `_obj(ctx)` which calls `ctx.find_root().obj`
- Backend and session are lazily initialised on first use via `_get_backend()` and `_get_session()`
- `_require_hash()` resolves hash from the explicit `--hash` flag or falls back to the session's active scan
- `_output()` renders data as human-readable key/value pairs or JSON based on the `--json` flag

Commands: `upload`, `scan`, `scans`, `search`, `delete`, `logs`, `tasks`, `report`, `scorecard`, `pdf`, `compare`, `suppress` (group: list/add/remove), `dynamic` (group: apps/start/stop/report/screenshot/logcat/mobsfy/activity/tls), `frida` (group: instrument/logs/monitor/scripts), `use`, `status`, `undo`, `redo`, `analyse`, `attack-surface`.

#### `core/analyse.py` — `AnalysisPipeline`

Orchestrates the 8-stage pipeline. Constructor accepts:
- `apk_path` — path to the APK file
- `output_dir` — output directory (default: `<apk_name>_analysis/`)
- `sdk_version` — Android SDK Build Tools version for re-signing
- `abis` — target ABIs list
- `backend` — MobSFBackend instance for API calls
- `skip` — set of stage names to skip
- `echo` — output function (default: print, Click passes click.echo)

Each stage method (`_stage_mobsf`, `_stage_jadx`, etc.) is independently try/caught. Failures are recorded in `stage_results` (including per-stage duration) but do not halt the pipeline.

The `_run()` helper executes shell commands via `subprocess.run()` with capture and optional directory context.

**Progress indicator:**

The pipeline displays a visual progress bar, stage counter, and per-stage timing during execution:

```
  Analysing: app.apk
  Output:    /path/to/app_analysis
  Stages:    8/8 (0 skipped)
  ────────────────────────────────────────────────────────

  [██░░░░░░░░░░░░░░░░░░]  13%  1/8  MobSF upload & scan
    Uploading to MobSF...
    Running static analysis...
  ✓ mobsf                2m 14.3s

  [█████░░░░░░░░░░░░░░░]  25%  2/8  JADX decompilation
    Decompiling with JADX...
  ✓ decompiled           1m 47.2s
  ...

  ────────────────────────────────────────────────────────
  Done in 8m 32s  |  7 passed  1 failed  0 skipped
  /path/to/app_analysis
```

Each stage reports a status marker (`✓` passed, `✗` failed) and its duration. The final summary shows total elapsed time and pass/fail/skip counts. Helper methods `_progress_bar()` and `_fmt_duration()` handle rendering — durations are shown as seconds, minutes+seconds, or hours+minutes depending on magnitude.

#### `core/attack_surface.py`

Defines the `CATEGORIES` dictionary — 22 categories, each containing:
- `description` — what the category covers and why it matters
- `risk` — CRITICAL / HIGH / MEDIUM / INFO
- `patterns` — list of `(literal_string, description)` tuples

The `scan_attack_surface()` function:
1. Iterates categories and patterns
2. Runs `grep -rFn` for each pattern against smali files
3. Filters out framework paths (android/, androidx/, kotlin/, javax/)
4. Groups matches by file, sorts by count
5. Writes three output files: summary, full report, JSON

Performance note: runs one grep per pattern (~270 greps). For a typical APK with 10,000 smali files this takes 30-90 seconds. The 30-second per-grep timeout prevents hangs on very large codebases.

#### `core/objection_patcher.py` — `ObjectionPatcher`

Two-phase operation:
1. `plan()` — reads artifacts, makes decisions, prints the plan
2. `patch()` — builds the objection command, writes gadget config and script files, executes

The `_decide_*` methods each follow the same pattern:
- Read relevant artifacts
- Apply decision logic
- Call `_log_decision(key, value, reason)` to record the choice
- Return the decision value

The Frida bypass script is built incrementally — each protection detection adds its bypass block. If no protections are detected, no script is generated and objection runs in default listen mode.

#### `core/session.py` — `Session`

Dataclass tracking the active scan hash, file name, and scan type. Implements undo/redo via snapshot stacks. Used in REPL mode so you can `upload`, then `scan`, then `report` without repeating the hash.

#### `utils/mobsf_backend.py` — `MobSFBackend`

Thin wrapper around `requests.Session`. All API calls go through `_post()` or `_get()` which handle URL joining, headers, and `raise_for_status()`. The API key is set once in the session headers as `X-Mobsf-Api-Key`.

Default URL: `http://127.0.0.1:8030` (configurable via `--url` or `MOBSF_URL`).

#### `scripts/__init__.py`

Provides `script_path(name)` and `dictionary_path()` which resolve to absolute paths inside the installed package. This is how the pipeline finds bundled scripts regardless of where the package is installed.

### Bundled Scripts

| Script | Purpose | Called By |
|--------|---------|-----------|
| `classcountm.sh` | Counts smali classes excluding android/androidx/kotlin/javax/google framework packages | `_stage_apktool` |
| `libcount.sh` | Counts native .so libraries excluding common ABI directories | `_stage_apktool` |
| `searchstrings.sh` | Greps smali files for patterns from the dictionary file | `_stage_apktool` |
| `searchstringswithfilenames.sh` | Same as above but includes file paths in output | `_stage_apktool` |
| `sign-apk.sh` | Re-signs an APK using zipalign + apksigner with a custom keystore | `_stage_repackage` |
| `ObjectionPatch.sh` | Standalone objection wrapper — detects analysis artifacts and delegates to Python patcher, or falls back to manual mode | Standalone use |
| `searchstrings.dic` | 272-entry pattern dictionary covering 22 security categories | `searchstrings.sh`, `searchstringswithfilenames.sh` |

### Configuration & Environment

**Environment variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `MOBSF_URL` | `http://127.0.0.1:8030` | MobSF server URL |
| `MOBSF_API_KEY` | (auto-derived) | MobSF API key |
| `ANDROID_SDK` | (none) | Android SDK path, required for `sign-apk.sh` |

**Files the pipeline expects on the host:**

| File | Required By | Purpose |
|------|------------|---------|
| `~/.MobSF/secret` or `~/.mobsf/secret` | API key auto-derivation | Fallback if `MOBSF_API_KEY` not set |
| `~/.android/attack.jks` | Repackage stage | Attack/test keystore for re-signing |
| `certificate.x509.pem`, `keystore.jks`, `keystoreinfo.json` | AppShield stage | Signing materials (looked for alongside the APK) |

### Error Handling

The pipeline uses three error handling strategies:

1. **Stage-level isolation** — each stage is wrapped in try/except. A failure in one stage is recorded but does not stop subsequent stages.
2. **Command-level tolerance** — within stages, individual tool invocations use `check=False` where the tool might legitimately fail (e.g., binwalk on a stripped binary).
3. **HTTP error propagation** — MobSF API calls use `raise_for_status()`, surfacing HTTP errors immediately since they indicate configuration problems.

---

## Installation

### Prerequisites

**Python 3.9+** is required. Verify with:

```bash
python3 --version
```

### Core Installation

```bash
# Clone the repository
git clone https://github.com/theantlab/cli-anything-mobsf.git
cd cli-anything-mobsf

# Install in editable mode (recommended for development)
pip install -e .

# Or install normally
pip install .
```

This installs the `cli-anything-mobsf` command and the two Python dependencies (click, requests).

### System Dependencies

The full `analyse` pipeline requires external tools. Install what you need based on which stages you plan to use.

#### Debian/Ubuntu

```bash
# Core tools
sudo apt install -y binutils           # readelf, strings
sudo apt install -y default-jdk        # Java runtime for JADX and APKtool

# JADX (DEX decompiler)
# Download latest from https://github.com/skylot/jadx/releases
wget https://github.com/skylot/jadx/releases/latest/download/jadx-*.zip
unzip jadx-*.zip -d /opt/jadx
sudo ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx

# APKtool
sudo apt install -y apktool

# Python tools (install in the same venv as cli-anything-mobsf)
pip install apkid                      # APK fingerprinting
pip install binwalk                    # Binary analysis
pip install objection                  # Frida gadget patcher
pip install frida-tools                # Frida CLI
```

#### macOS

```bash
brew install binutils jadx apktool
pip install apkid binwalk objection frida-tools
```

#### Verification of tools

```bash
# Check which tools are available
for cmd in jadx apktool apkid binwalk objection frida readelf strings; do
    printf "%-12s " "$cmd"
    if command -v $cmd &>/dev/null; then
        echo "OK ($(command -v $cmd))"
    else
        echo "MISSING"
    fi
done
```

#### Optional: Android SDK (for repackage stage)

The repackage stage needs `zipalign` and `apksigner` from the Android SDK Build Tools:

```bash
export ANDROID_SDK=/path/to/android-sdk
# Verify:
ls $ANDROID_SDK/build-tools/*/zipalign
ls $ANDROID_SDK/build-tools/*/apksigner
```

#### Optional: Attack keystore (for repackage stage)

Generate a test keystore for re-signing APKs:

```bash
mkdir -p ~/.android
keytool -genkey -v -keystore ~/.android/attack.jks \
    -alias attack -keyalg RSA -keysize 2048 -validity 10000 \
    -storepass attack -keypass attack \
    -dname "CN=Attack, OU=Test, O=Test, L=Test, ST=Test, C=XX"
```

#### Optional: Verimatrix AppShield (for appshield stage)

The AppShield stage requires the `apkdefender` binary from Verimatrix. This is a commercial tool — skip this stage with `--skip appshield` if not available.

### MobSF Setup

cli-anything-mobsf requires a running MobSF instance.

#### Option 1: Docker (quickest)

```bash
docker run -it --rm -p 8030:8000 opensecurity/mobile-security-framework-mobsf:latest
```

#### Option 2: Local installation

```bash
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
cd Mobile-Security-Framework-MobSF
pip install -r requirements.txt
python manage.py runserver 0.0.0.0:8030
```

#### Configure the CLI

```bash
# Set the MobSF URL
export MOBSF_URL=http://127.0.0.1:8030

# Option A: Set the API key explicitly
export MOBSF_API_KEY=your_api_key_here

# Option B: The CLI auto-derives the key from ~/.MobSF/secret
# (created automatically when MobSF first runs locally)
```

Find your API key in the MobSF web UI under the API documentation page, or derive it:

```bash
python3 -c "import hashlib; print(hashlib.sha256(open('$HOME/.MobSF/secret').read().strip().encode()).hexdigest())"
```

### Verification

Run the test suite:

```bash
cd cli-anything-mobsf
python -m pytest cli_anything/mobsf/tests/test_core.py -v
```

Verify the CLI:

```bash
# Help
cli-anything-mobsf --help

# Test MobSF connection
cli-anything-mobsf scans

# Test analyse help
cli-anything-mobsf analyse --help
```

---

## Usage Guide

### Full Analysis Pipeline

Basic usage:

```bash
cli-anything-mobsf analyse ./app.apk
```

This creates `app_analysis/` with all 8 stages. To customise:

```bash
# Custom output directory
cli-anything-mobsf analyse ./app.apk -o ./my_results

# Skip stages (repeatable)
cli-anything-mobsf analyse ./app.apk --skip appshield --skip repackage

# Specify SDK version for repackage stage
cli-anything-mobsf analyse ./app.apk -v 34.0.0

# Specify target ABIs
cli-anything-mobsf analyse ./app.apk --abi arm64-v8a
```

After completion, key files to review:

```bash
# Executive summary of security findings
cat app_analysis/attack_surface/attack_surface_summary.txt

# Full attack surface report with file locations
cat app_analysis/attack_surface/attack_surface_report.txt

# Objection patching decisions and reasoning
cat app_analysis/objection/patching_decisions.json

# Auto-generated Frida bypass script
cat app_analysis/objection/libfrida-gadget.script.so

# Overall pipeline summary
cat app_analysis/summary.json
```

### Standalone Commands

#### Attack surface scan on an existing apktool directory:

```bash
cli-anything-mobsf attack-surface ./app_apktool/app/ -o ./attack_results
```

#### MobSF API operations:

```bash
# Upload and scan
cli-anything-mobsf upload ./app.apk
cli-anything-mobsf scan --hash <md5>

# Get results
cli-anything-mobsf report --hash <md5>
cli-anything-mobsf --json scorecard --hash <md5>
cli-anything-mobsf pdf --hash <md5> -o report.pdf

# Compare two apps
cli-anything-mobsf compare <hash1> <hash2>

# Dynamic analysis
cli-anything-mobsf dynamic start --hash <md5>
cli-anything-mobsf dynamic stop --hash <md5>
cli-anything-mobsf dynamic report --hash <md5>

# Frida
cli-anything-mobsf frida scripts --device android
cli-anything-mobsf frida instrument --hash <md5> --hooks "ssl_bypass"
```

### REPL Mode

Run without a subcommand to enter the interactive shell:

```bash
$ cli-anything-mobsf
MobSF CLI — interactive mode. Type 'help' for commands, 'quit' to exit.
mobsf> upload ./app.apk
mobsf> scan
mobsf> report
mobsf> scorecard
mobsf> quit
```

Session state persists between commands — after `upload`, the hash is remembered so subsequent commands work without `--hash`.

---

## Extending

### Adding a new attack surface category

Edit `cli_anything/mobsf/core/attack_surface.py` and add an entry to the `CATEGORIES` dict:

```python
"My New Category": {
    "description": "What this category covers and why it matters.",
    "risk": "HIGH",
    "patterns": [
        ("PatternToSearch", "What this pattern indicates"),
        ("AnotherPattern", "Description of what it means"),
    ],
},
```

### Adding a new pipeline stage

1. Add a method `_stage_mystage(self)` to the `AnalysisPipeline` class in `analyse.py`
2. Add it to the `stages` list in `run()`
3. Add the directory to `_setup_dirs()` if needed
4. Add the stage name to `SKIP_CHOICES` in `mobsf_cli.py`

### Adding a new Objection bypass

Edit the `_decide_script_source()` method in `objection_patcher.py`. Add a new detection block:

```python
# Check for your protection
my_cat = self.attack_surface.get("My Category", {})
if my_cat and my_cat.get("total_matches", 0) > threshold:
    has_bypasses = True
    script_parts.extend([
        '// ── My Bypass ──────────────',
        'Java.perform(function() {',
        '    // bypass code here',
        '});',
    ])
```

### Adding a new CLI command

Add a new function decorated with `@cli.command()` in `mobsf_cli.py`:

```python
@cli.command()
@click.argument("some_arg")
@click.pass_context
def mycommand(ctx, some_arg):
    """Description shown in help."""
    obj = _obj(ctx)
    backend = _get_backend(obj)
    result = backend.some_api_call(some_arg)
    _output(result, obj.get("json"))
```

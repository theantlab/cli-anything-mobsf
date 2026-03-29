# MobSF CLI — CLI-Anything Harness

CLI wrapper for the [Mobile Security Framework (MobSF)](https://github.com/MobSF/Mobile-Security-Framework-MobSF) REST API.

## Setup

```bash
cd agent-harness
pip install -e .
```

Set your MobSF server URL and API key:

```bash
export MOBSF_URL=http://localhost:8000
export MOBSF_API_KEY=your_api_key_here
```

Or pass them as flags: `cli-anything-mobsf --url http://... --api-key ...`

The CLI will also attempt to read `~/.MobSF/secret` or `~/.mobsf/secret` to derive the key automatically.

## Usage

### One-shot commands

```bash
# Upload and scan
cli-anything-mobsf upload ./app.apk
cli-anything-mobsf scan --hash <md5>

# List scans
cli-anything-mobsf scans

# Get report
cli-anything-mobsf report --hash <md5>
cli-anything-mobsf pdf --hash <md5> -o report.pdf
cli-anything-mobsf scorecard --hash <md5>

# Compare two scans
cli-anything-mobsf compare <hash1> <hash2>

# Search
cli-anything-mobsf search "com.example.app"

# Dynamic analysis
cli-anything-mobsf dynamic start --hash <md5>
cli-anything-mobsf dynamic stop --hash <md5>
cli-anything-mobsf dynamic report --hash <md5>

# Frida
cli-anything-mobsf frida scripts
cli-anything-mobsf frida instrument --hash <md5> --hooks "ssl_bypass"
cli-anything-mobsf frida logs --hash <md5>

# Suppressions
cli-anything-mobsf suppress list --hash <md5>
cli-anything-mobsf suppress add --hash <md5> --rule android_logging
```

### REPL mode

Run without a subcommand to enter interactive mode:

```bash
cli-anything-mobsf
mobsf> upload ./app.apk
mobsf> scan
mobsf> report
mobsf> quit
```

Session state carries between commands — after `upload`, the hash is remembered so `scan` and `report` work without `--hash`.

### JSON output

Add `--json` to any command for machine-readable output:

```bash
cli-anything-mobsf --json scans
cli-anything-mobsf --json report --hash <md5>
```

## Command Reference

| Command | Description |
|---------|-------------|
| `upload <file>` | Upload mobile app for analysis |
| `scan` | Trigger static analysis |
| `scans` | List recent scans |
| `search <query>` | Search by hash or text |
| `delete --hash` | Delete a scan |
| `logs` | View scan logs |
| `tasks` | Show scan queue |
| `report` | JSON report |
| `scorecard` | Security scorecard |
| `pdf` | Download PDF report |
| `compare <h1> <h2>` | Compare two scans |
| `suppress list/add/remove` | Manage suppressions |
| `dynamic start/stop/report/apps` | Dynamic analysis |
| `dynamic mobsfy/screenshot/logcat/activity/tls` | Device ops |
| `frida instrument/logs/monitor/scripts` | Frida tools |
| `use --hash` | Set active scan |
| `status` | Show session state |
| `undo` / `redo` | Session state undo/redo |

## Resource Limits

The `analyse` command enforces resource limits to prevent the pipeline from consuming all system resources:

| Control | Default | Description |
|---------|---------|-------------|
| `--max-ram` | 8192 | Max heap growth per subprocess via `RLIMIT_DATA` (MB) |
| JADX heap | 4096 MB | Java heap cap via `-Xmx` |
| JADX threads | 2 | Limits JADX parallelism (`--threads-count`) |
| CPU priority | nice 10 | All subprocesses run at reduced priority |
| SDK version | auto-detected | Picks latest installed from `$ANDROID_SDK/build-tools/` |

`RLIMIT_DATA` is used instead of `RLIMIT_AS` because JVM-based tools (JADX, apktool) map far more virtual address space than they actually consume. `RLIMIT_AS` would kill them prematurely.

JADX exit code 1 (non-fatal decompilation errors) is treated as success — this is normal for large or obfuscated APKs.

Example — run analysis with tighter memory limits:

```bash
cli-anything-mobsf analyse ./app.apk --max-ram 4096
```

These defaults can be adjusted via class constants in `AnalysisPipeline` (`JADX_MAX_RAM_MB`, `JADX_THREADS`, `DEFAULT_MAX_RAM_MB`, `NICE_LEVEL`).

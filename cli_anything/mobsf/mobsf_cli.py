"""MobSF CLI — cli-anything harness for Mobile Security Framework."""
import json
import sys

import click

from cli_anything.mobsf.core.analyse import AnalysisPipeline
from cli_anything.mobsf.core.attack_surface import scan_attack_surface
from cli_anything.mobsf.core.session import Session
from cli_anything.mobsf.utils.mobsf_backend import MobSFBackend

# ── Helpers ───────────────────────────────────────────────────────────

def _output(data, as_json=False):
    """Print data as JSON or human-readable."""
    if as_json:
        click.echo(json.dumps(data, indent=2, default=str))
        return
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, (dict, list)):
                click.echo(f"{k}:")
                click.echo(f"  {json.dumps(v, indent=2, default=str)}")
            else:
                click.echo(f"{k}: {v}")
    elif isinstance(data, list):
        for item in data:
            click.echo(item if isinstance(item, str) else json.dumps(item, default=str))
    else:
        click.echo(data)


def _obj(ctx):
    """Get root context obj dict."""
    return ctx.find_root().obj


def _get_backend(obj):
    if "backend" not in obj:
        obj["backend"] = MobSFBackend(
            url=obj.get("url"), api_key=obj.get("api_key"),
        )
    return obj["backend"]


def _get_session(obj):
    if "session" not in obj:
        obj["session"] = Session()
    return obj["session"]


def _require_hash(obj, scan_hash):
    """Resolve hash from arg or session."""
    if scan_hash:
        return scan_hash
    session = _get_session(obj)
    if session.current_hash:
        return session.current_hash
    raise click.UsageError("No scan hash provided and no active scan in session. Use --hash or upload/select a scan first.")

# ── Root group ────────────────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.option("--url", envvar="MOBSF_URL", default=None, help="MobSF server URL.")
@click.option("--api-key", envvar="MOBSF_API_KEY", default=None, help="MobSF API key.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON.")
@click.pass_context
def cli(ctx, url, api_key, as_json):
    """MobSF CLI — Mobile Security Framework from the command line."""
    ctx.ensure_object(dict)
    ctx.obj["url"] = url
    ctx.obj["api_key"] = api_key
    ctx.obj["json"] = as_json
    if ctx.invoked_subcommand is None:
        _repl(ctx)

# ── Static analysis commands ──────────────────────────────────────────

@cli.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.pass_context
def upload(ctx, file_path):
    """Upload a mobile app (APK, IPA, APPX, etc.) for analysis."""
    obj = _obj(ctx)
    backend = _get_backend(obj)
    result = backend.upload(file_path)
    session = _get_session(obj)
    if "hash" in result:
        session.set_scan(result["hash"], file_name=result.get("file_name", ""), scan_type=result.get("scan_type", ""))
    _output(result, obj.get("json"))


@cli.command()
@click.option("--hash", "scan_hash", default=None, help="Scan hash (uses active scan if omitted).")
@click.option("--re-scan", is_flag=True, help="Force re-scan.")
@click.pass_context
def scan(ctx, scan_hash, re_scan):
    """Trigger static analysis on an uploaded file."""
    obj = _obj(ctx)
    h = _require_hash(obj, scan_hash)
    backend = _get_backend(obj)
    result = backend.scan(h, re_scan=re_scan)
    _output(result, obj.get("json"))


@cli.command()
@click.option("--page", default=1, help="Page number.")
@click.option("--page-size", default=50, help="Results per page.")
@click.pass_context
def scans(ctx, page, page_size):
    """List recent scans."""
    obj = _obj(ctx)
    backend = _get_backend(obj)
    result = backend.scans(page=page, page_size=page_size)
    if not obj.get("json") and isinstance(result, dict) and "content" in result:
        for s in result["content"]:
            h = s.get("MD5", s.get("hash", "?"))
            name = s.get("FILE_NAME", s.get("APP_NAME", ""))
            click.echo(f"  {h}  {name}")
    else:
        _output(result, obj.get("json"))


@cli.command()
@click.argument("query")
@click.pass_context
def search(ctx, query):
    """Search scans by hash or text."""
    obj = _obj(ctx)
    backend = _get_backend(obj)
    _output(backend.search(query), obj.get("json"))


@cli.command("delete")
@click.option("--hash", "scan_hash", required=True, help="Scan hash to delete.")
@click.confirmation_option(prompt="Are you sure you want to delete this scan?")
@click.pass_context
def delete_scan(ctx, scan_hash):
    """Delete a scan."""
    obj = _obj(ctx)
    backend = _get_backend(obj)
    _output(backend.delete_scan(scan_hash), obj.get("json"))


@cli.command()
@click.option("--hash", "scan_hash", default=None, help="Scan hash.")
@click.pass_context
def logs(ctx, scan_hash):
    """Show scan logs."""
    obj = _obj(ctx)
    h = _require_hash(obj, scan_hash)
    backend = _get_backend(obj)
    _output(backend.scan_logs(h), obj.get("json"))


@cli.command()
@click.pass_context
def tasks(ctx):
    """Show scan queue / pending tasks."""
    obj = _obj(ctx)
    backend = _get_backend(obj)
    _output(backend.tasks(), obj.get("json"))

# ── Reports ───────────────────────────────────────────────────────────

@cli.command()
@click.option("--hash", "scan_hash", default=None, help="Scan hash.")
@click.pass_context
def report(ctx, scan_hash):
    """Get JSON report for a scan."""
    obj = _obj(ctx)
    h = _require_hash(obj, scan_hash)
    backend = _get_backend(obj)
    _output(backend.report_json(h), obj.get("json", True))


@cli.command()
@click.option("--hash", "scan_hash", default=None, help="Scan hash.")
@click.pass_context
def scorecard(ctx, scan_hash):
    """Get security scorecard for a scan."""
    obj = _obj(ctx)
    h = _require_hash(obj, scan_hash)
    backend = _get_backend(obj)
    _output(backend.scorecard(h), obj.get("json"))


@cli.command()
@click.option("--hash", "scan_hash", default=None, help="Scan hash.")
@click.option("-o", "--output", "output_path", default=None, help="Output file path.")
@click.pass_context
def pdf(ctx, scan_hash, output_path):
    """Download PDF report."""
    obj = _obj(ctx)
    h = _require_hash(obj, scan_hash)
    backend = _get_backend(obj)
    path = backend.download_pdf(h, output_path)
    click.echo(f"Report saved to: {path}")

# ── Compare ───────────────────────────────────────────────────────────

@cli.command()
@click.argument("hash1")
@click.argument("hash2")
@click.pass_context
def compare(ctx, hash1, hash2):
    """Compare two scans side by side."""
    obj = _obj(ctx)
    backend = _get_backend(obj)
    _output(backend.compare(hash1, hash2), obj.get("json"))

# ── Suppressions ──────────────────────────────────────────────────────

@cli.group()
def suppress():
    """Manage finding suppressions."""
    pass


@suppress.command("list")
@click.option("--hash", "scan_hash", required=True, help="Scan hash.")
@click.pass_context
def suppress_list(ctx, scan_hash):
    """List suppressions for a scan."""
    obj = _obj(ctx)
    backend = _get_backend(obj)
    _output(backend.list_suppressions(scan_hash), obj.get("json"))


@suppress.command("add")
@click.option("--hash", "scan_hash", required=True)
@click.option("--rule", required=True, help="Rule ID to suppress.")
@click.pass_context
def suppress_add(ctx, scan_hash, rule):
    """Suppress findings by rule."""
    obj = _obj(ctx)
    backend = _get_backend(obj)
    _output(backend.suppress_by_rule(scan_hash, rule), obj.get("json"))


@suppress.command("remove")
@click.option("--hash", "scan_hash", required=True)
@click.option("--rule", required=True)
@click.option("--type", "suppress_type", default="suppress")
@click.pass_context
def suppress_remove(ctx, scan_hash, rule, suppress_type):
    """Remove a suppression."""
    obj = _obj(ctx)
    backend = _get_backend(obj)
    _output(backend.delete_suppression(scan_hash, rule, suppress_type), obj.get("json"))

# ── Dynamic analysis ──────────────────────────────────────────────────

@cli.group()
def dynamic():
    """Android dynamic analysis commands."""
    pass


@dynamic.command("apps")
@click.pass_context
def dynamic_apps(ctx):
    """List apps available for dynamic analysis."""
    obj = _obj(ctx)
    backend = _get_backend(obj)
    _output(backend.dynamic_get_apps(), obj.get("json"))


@dynamic.command("start")
@click.option("--hash", "scan_hash", default=None, help="Scan hash.")
@click.pass_context
def dynamic_start(ctx, scan_hash):
    """Start dynamic analysis."""
    obj = _obj(ctx)
    h = _require_hash(obj, scan_hash)
    backend = _get_backend(obj)
    _output(backend.dynamic_start(h), obj.get("json"))


@dynamic.command("stop")
@click.option("--hash", "scan_hash", default=None, help="Scan hash.")
@click.pass_context
def dynamic_stop(ctx, scan_hash):
    """Stop dynamic analysis and collect logs."""
    obj = _obj(ctx)
    h = _require_hash(obj, scan_hash)
    backend = _get_backend(obj)
    _output(backend.dynamic_stop(h), obj.get("json"))


@dynamic.command("report")
@click.option("--hash", "scan_hash", default=None, help="Scan hash.")
@click.pass_context
def dynamic_report(ctx, scan_hash):
    """Get dynamic analysis report."""
    obj = _obj(ctx)
    h = _require_hash(obj, scan_hash)
    backend = _get_backend(obj)
    _output(backend.dynamic_report(h), obj.get("json"))


@dynamic.command("screenshot")
@click.option("--hash", "scan_hash", default=None, help="Scan hash.")
@click.pass_context
def dynamic_screenshot(ctx, scan_hash):
    """Capture device screenshot."""
    obj = _obj(ctx)
    h = _require_hash(obj, scan_hash)
    backend = _get_backend(obj)
    _output(backend.screenshot(h), obj.get("json"))


@dynamic.command("logcat")
@click.argument("package")
@click.pass_context
def dynamic_logcat(ctx, package):
    """Stream logcat for a package."""
    obj = _obj(ctx)
    backend = _get_backend(obj)
    _output(backend.logcat(package), obj.get("json"))


@dynamic.command("mobsfy")
@click.option("--hash", "scan_hash", default=None, help="Scan hash.")
@click.pass_context
def dynamic_mobsfy(ctx, scan_hash):
    """Instrument app for dynamic analysis."""
    obj = _obj(ctx)
    h = _require_hash(obj, scan_hash)
    backend = _get_backend(obj)
    _output(backend.mobsfy(h), obj.get("json"))


@dynamic.command("activity")
@click.option("--hash", "scan_hash", default=None, help="Scan hash.")
@click.option("--test", default="exported", help="Test type (exported, etc.).")
@click.pass_context
def dynamic_activity(ctx, scan_hash, test):
    """Run activity tester."""
    obj = _obj(ctx)
    h = _require_hash(obj, scan_hash)
    backend = _get_backend(obj)
    _output(backend.activity_test(h, test), obj.get("json"))


@dynamic.command("tls")
@click.option("--hash", "scan_hash", default=None, help="Scan hash.")
@click.pass_context
def dynamic_tls(ctx, scan_hash):
    """Run TLS/SSL security tests."""
    obj = _obj(ctx)
    h = _require_hash(obj, scan_hash)
    backend = _get_backend(obj)
    _output(backend.tls_tests(h), obj.get("json"))

# ── Frida commands ────────────────────────────────────────────────────

@cli.group()
def frida():
    """Frida instrumentation commands."""
    pass


@frida.command("instrument")
@click.option("--hash", "scan_hash", default=None, help="Scan hash.")
@click.option("--hooks", default="", help="Default hooks (comma-separated).")
@click.option("--aux", default="", help="Auxiliary hooks.")
@click.option("--code", default="", help="Custom Frida code.")
@click.pass_context
def frida_instrument(ctx, scan_hash, hooks, aux, code):
    """Run Frida instrumentation on target app."""
    obj = _obj(ctx)
    h = _require_hash(obj, scan_hash)
    backend = _get_backend(obj)
    _output(backend.frida_instrument(h, hooks, aux, code), obj.get("json"))


@frida.command("logs")
@click.option("--hash", "scan_hash", default=None, help="Scan hash.")
@click.pass_context
def frida_logs(ctx, scan_hash):
    """Get Frida logs."""
    obj = _obj(ctx)
    h = _require_hash(obj, scan_hash)
    backend = _get_backend(obj)
    _output(backend.frida_logs(h), obj.get("json"))


@frida.command("monitor")
@click.option("--hash", "scan_hash", default=None, help="Scan hash.")
@click.pass_context
def frida_monitor(ctx, scan_hash):
    """Live API monitoring via Frida."""
    obj = _obj(ctx)
    h = _require_hash(obj, scan_hash)
    backend = _get_backend(obj)
    _output(backend.frida_api_monitor(h), obj.get("json"))


@frida.command("scripts")
@click.option("--device", default="android", help="Device type (android/ios).")
@click.pass_context
def frida_scripts(ctx, device):
    """List available Frida scripts."""
    obj = _obj(ctx)
    backend = _get_backend(obj)
    _output(backend.frida_list_scripts(device), obj.get("json"))

# ── Session commands ──────────────────────────────────────────────────

@cli.command()
@click.option("--hash", "scan_hash", required=True, help="Scan hash to set as active.")
@click.pass_context
def use(ctx, scan_hash):
    """Set active scan hash for subsequent commands."""
    obj = _obj(ctx)
    session = _get_session(obj)
    session.set_scan(scan_hash)
    click.echo(f"Active scan: {scan_hash}")


@cli.command()
@click.pass_context
def status(ctx):
    """Show current session state."""
    obj = _obj(ctx)
    session = _get_session(obj)
    _output(session.to_dict(), obj.get("json"))


@cli.command()
@click.pass_context
def undo(ctx):
    """Undo last session state change."""
    obj = _obj(ctx)
    session = _get_session(obj)
    if session.undo():
        click.echo(f"Undone. Active scan: {session.current_hash or '(none)'}")
    else:
        click.echo("Nothing to undo.")


@cli.command()
@click.pass_context
def redo(ctx):
    """Redo last undone session state change."""
    obj = _obj(ctx)
    session = _get_session(obj)
    if session.redo():
        click.echo(f"Redone. Active scan: {session.current_hash or '(none)'}")
    else:
        click.echo("Nothing to redo.")

# ── Full analysis pipeline ────────────────────────────────────────────

SKIP_CHOICES = ["mobsf", "decompiled", "apkid", "native", "apktool",
                "repackage", "appshield", "objection"]


@cli.command()
@click.argument("apk_path", type=click.Path(exists=True))
@click.option("-o", "--output", "output_dir", default=None, help="Output directory (default: <apk_name>_analysis/).")
@click.option("-v", "--sdk-version", default="31.0.0", help="Android SDK Build Tools version.")
@click.option("--abi", multiple=True, default=["arm64-v8a", "armeabi-v7a"], help="Target ABIs (repeatable).")
@click.option("--skip", multiple=True, type=click.Choice(SKIP_CHOICES), help="Stages to skip (repeatable).")
@click.pass_context
def analyse(ctx, apk_path, output_dir, sdk_version, abi, skip):
    """Run full app analysis pipeline (MobSF + local toolchain).

    Produces a single analysis directory with MobSF reports, decompiled
    source, native library analysis, APKtool output, repackage test,
    AppShield build, and Objection patch.
    """
    obj = _obj(ctx)
    backend = _get_backend(obj)

    pipeline = AnalysisPipeline(
        apk_path=apk_path,
        output_dir=output_dir,
        sdk_version=sdk_version,
        abis=list(abi),
        backend=backend,
        skip=list(skip),
        echo=click.echo,
    )
    pipeline.run()


@cli.command("attack-surface")
@click.argument("smali_dir", type=click.Path(exists=True))
@click.option("-o", "--output", "output_dir", default=None, help="Output directory (default: ./attack_surface/).")
def attack_surface(smali_dir, output_dir):
    """Run standalone attack surface analysis on an apktool-decoded directory.

    SMALI_DIR should be the apktool output directory containing smali/ folders.
    Produces categorised reports: summary, full report, and JSON data.
    """
    out = Path(output_dir) if output_dir else Path.cwd() / "attack_surface"
    click.echo(f"Scanning {smali_dir} ...")
    results = scan_attack_surface(smali_dir, out)

    # Print summary to terminal
    summary_file = out / "attack_surface_summary.txt"
    if summary_file.is_file():
        click.echo("")
        click.echo(summary_file.read_text())

    click.echo(f"\nFull reports in: {out}")


# ── REPL ──────────────────────────────────────────────────────────────

def _repl(ctx):
    """Interactive REPL mode."""
    click.echo("MobSF CLI — interactive mode. Type 'help' for commands, 'quit' to exit.")
    while True:
        try:
            line = click.prompt("mobsf", prompt_suffix="> ", default="", show_default=False)
        except (EOFError, KeyboardInterrupt):
            click.echo()
            break
        line = line.strip()
        if not line:
            continue
        if line in ("quit", "exit", "q"):
            break
        if line == "help":
            click.echo(ctx.get_help())
            continue
        args = line.split()
        try:
            with ctx.scope() as sub_ctx:
                cli.main(args, standalone_mode=False, **{"parent": ctx})
        except click.UsageError as e:
            click.echo(f"Error: {e}")
        except SystemExit:
            pass
        except Exception as e:
            click.echo(f"Error: {e}")


if __name__ == "__main__":
    cli()

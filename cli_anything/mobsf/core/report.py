"""Unified analysis report — synthesises all stage outputs into one executive report."""
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path


def generate_report(analysis_dir):
    """Generate a unified analysis report from all stage outputs.

    Reads from:
      - summary.json              → pipeline metadata, stage results
      - mobsf/report.json         → app metadata, permissions, components
      - mobsf/scorecard.json      → MobSF security findings by severity
      - mobsf/apkid.json          → packer/obfuscator detection
      - attack_surface/           → bytecode attack surface analysis
      - native/attack_surface/    → native library attack surface analysis
      - apktool/classcount.txt    → app class count
      - apktool/libcount.txt      → native library count
      - repackage/result.txt      → repackage test result
      - appshield/                → protection build results
      - objection/                → Frida patching decisions

    Produces:
      - analysis_report.txt       → human-readable executive report
      - analysis_report.json      → machine-readable unified findings
    """
    analysis_dir = Path(analysis_dir)

    # ── Gather data from all stages ──────────────────────────────────
    summary = _load_json(analysis_dir / "summary.json")
    mobsf_report = _load_json(analysis_dir / "mobsf" / "report.json")
    scorecard = _load_json(analysis_dir / "mobsf" / "scorecard.json")
    apkid = _load_json(analysis_dir / "mobsf" / "apkid.json")
    bytecode_surface = _load_json(analysis_dir / "attack_surface" / "attack_surface.json")
    native_surface = _load_json(analysis_dir / "native" / "attack_surface" / "native_attack_surface.json")
    objection = _load_json(analysis_dir / "objection" / "patching_decisions.json")

    classcount = _read_text(analysis_dir / "apktool" / "classcount.txt").strip()
    libcount = _read_text(analysis_dir / "apktool" / "libcount.txt").strip()
    repackage_result = _read_text(analysis_dir / "repackage" / "result.txt").strip()

    # ── Build unified report ─────────────────────────────────────────
    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "app": _build_app_section(summary, mobsf_report),
        "security_score": _build_score_section(scorecard),
        "protections": _build_protections_section(apkid, bytecode_surface, native_surface, objection),
        "attack_surface": _build_attack_surface_section(bytecode_surface, native_surface),
        "mobsf_findings": _build_mobsf_findings(scorecard),
        "native_security": _build_native_security(native_surface),
        "repackage_test": _build_repackage_section(repackage_result),
        "appshield": _build_appshield_section(analysis_dir),
        "pipeline": _build_pipeline_section(summary),
    }

    # ── Write reports ────────────────────────────────────────────────
    (analysis_dir / "analysis_report.json").write_text(
        json.dumps(report, indent=2, default=str))

    text = _render_text_report(report, analysis_dir)
    (analysis_dir / "analysis_report.txt").write_text(text)

    return report


# ── Section builders ─────────────────────────────────────────────────

def _build_app_section(summary, mobsf):
    """App identity and metadata."""
    meta = summary.get("app_metadata", {})
    return {
        "package_name": meta.get("package_name", mobsf.get("package_name", "")),
        "version_name": meta.get("version_name", mobsf.get("version_name", "")),
        "version_code": meta.get("version_code", mobsf.get("version_code", "")),
        "target_sdk": meta.get("target_sdk", mobsf.get("target_sdk", "")),
        "min_sdk": meta.get("min_sdk", mobsf.get("min_sdk", "")),
        "size": meta.get("size", mobsf.get("size", "")),
        "app_name": mobsf.get("app_name", summary.get("app_name", "")),
        "main_activity": mobsf.get("main_activity", ""),
        "activities": len(mobsf.get("activities", [])),
        "services": len(mobsf.get("services", [])),
        "receivers": len(mobsf.get("receivers", [])),
        "providers": len(mobsf.get("providers", [])),
        "permissions": len(mobsf.get("permissions", [])),
    }


def _build_score_section(scorecard):
    """Security scorecard summary."""
    counts = {}
    for severity in ["high", "warning", "info", "secure", "hotspot"]:
        items = scorecard.get(severity, [])
        counts[severity] = len(items)

    # Calculate a simple risk score: high=10, warning=3, hotspot=5, secure=-2
    risk_score = (counts.get("high", 0) * 10 +
                  counts.get("warning", 0) * 3 +
                  counts.get("hotspot", 0) * 5 -
                  counts.get("secure", 0) * 2)

    if risk_score <= 10:
        rating = "LOW"
    elif risk_score <= 40:
        rating = "MEDIUM"
    elif risk_score <= 80:
        rating = "HIGH"
    else:
        rating = "CRITICAL"

    return {
        "counts": counts,
        "risk_score": risk_score,
        "risk_rating": rating,
    }


def _build_protections_section(apkid, bytecode_surface, native_surface, objection):
    """Detected protections and their bypass status."""
    protections = []

    # From APKiD
    for entry_name, entry_data in apkid.items():
        for ptype in ["packer", "obfuscator", "anti_vm", "anti_debug", "anti_disassembly"]:
            for item in entry_data.get(ptype, []):
                protections.append({"type": ptype, "name": item, "source": "APKiD"})

    # From bytecode attack surface
    for cat_name in ["App Integrity & Tamper Detection", "Root Detection",
                     "Anti-Debug & Dynamic Analysis", "Hooking Framework Detection",
                     "Emulator & VM Detection"]:
        cat = bytecode_surface.get(cat_name, {})
        if cat and cat.get("total_matches", 0) > 0:
            protections.append({
                "type": cat_name,
                "matches": cat["total_matches"],
                "source": "bytecode",
            })

    # From native attack surface
    native_agg = native_surface.get("aggregated", {})
    for cat_name in ["Anti-Analysis & Protection", "Root & Environment Detection",
                     "Protection Vendors"]:
        cat = native_agg.get(cat_name, {})
        if cat and cat.get("total_matches", 0) > 0:
            protections.append({
                "type": cat_name,
                "matches": cat["total_matches"],
                "source": "native",
            })

    # Objection bypass assessment
    bypass = {}
    if objection:
        bypass["network_security_config"] = objection.get("network_security_config", False)
        bypass["script_generated"] = objection.get("script_source") is not None
        bypass["target_class"] = objection.get("target_class", "")

    return {"detected": protections, "bypass": bypass}


def _build_attack_surface_section(bytecode_surface, native_surface):
    """Unified attack surface across bytecode and native code."""
    combined = defaultdict(lambda: {"bytecode": 0, "native": 0, "risk": "INFO"})

    risk_priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}

    for cat_name, cat_data in bytecode_surface.items():
        combined[cat_name]["bytecode"] = cat_data.get("total_matches", 0)
        combined[cat_name]["risk"] = cat_data.get("risk", "INFO")

    native_agg = native_surface.get("aggregated", {})
    for cat_name, cat_data in native_agg.items():
        combined[cat_name]["native"] = cat_data.get("total_matches", 0)
        # Use higher risk level
        existing_risk = combined[cat_name]["risk"]
        new_risk = cat_data.get("risk", "INFO")
        if risk_priority.get(new_risk, 9) < risk_priority.get(existing_risk, 9):
            combined[cat_name]["risk"] = new_risk

    # Sort by risk then total matches
    sorted_cats = sorted(
        combined.items(),
        key=lambda x: (risk_priority.get(x[1]["risk"], 9),
                       -(x[1]["bytecode"] + x[1]["native"]))
    )

    return [
        {"category": name, "risk": data["risk"],
         "bytecode_hits": data["bytecode"], "native_hits": data["native"],
         "total": data["bytecode"] + data["native"]}
        for name, data in sorted_cats
        if data["bytecode"] + data["native"] > 0
    ]


def _build_mobsf_findings(scorecard):
    """Top MobSF findings by severity."""
    findings = []
    for severity in ["high", "warning", "hotspot"]:
        for item in scorecard.get(severity, []):
            findings.append({
                "severity": severity,
                "title": item.get("title", ""),
                "description": item.get("description", "")[:200],
            })
    return findings


def _build_native_security(native_surface):
    """Native library security posture."""
    libs = native_surface.get("libraries", {})
    if not libs:
        return {}

    lib_security = []
    all_urls = set()
    all_build_paths = set()
    total_jni = 0

    for name, lib in libs.items():
        sec = lib.get("security", {})
        lib_security.append({
            "name": name,
            "size": lib.get("size_human", ""),
            "relro": sec.get("relro", "?"),
            "stack_canary": sec.get("stack_canary", False),
            "nx": sec.get("nx", False),
            "fortify": sec.get("fortify", False),
            "jni_exports": len(lib.get("jni_exports", [])),
            "dependencies": lib.get("dependencies", []),
        })
        all_urls.update(lib.get("urls", []))
        all_build_paths.update(lib.get("build_info", {}).get("build_paths", []))
        total_jni += len(lib.get("jni_exports", []))

    internal_urls = [u for u in all_urls
                     if any(x in u for x in ["localhost", "127.0.0.1", "10.", "192.168.", "172."])]

    return {
        "library_count": len(libs),
        "total_size": native_surface.get("total_size_bytes", 0),
        "abi": native_surface.get("abi", ""),
        "libraries": lib_security,
        "total_jni_exports": total_jni,
        "unique_urls": len(all_urls),
        "internal_urls": sorted(internal_urls),
        "leaked_build_paths": len(all_build_paths),
    }


def _build_repackage_section(result_text):
    """Repackage test outcome."""
    if not result_text:
        return {"status": "pass", "detail": "APK re-signed successfully"}
    return {"status": "fail", "detail": result_text[:500]}


def _build_appshield_section(analysis_dir):
    """AppShield protection build results."""
    appshield_dir = analysis_dir / "appshield"
    protected = list(appshield_dir.glob("*-protected.apk"))
    if protected:
        size = protected[0].stat().st_size
        return {
            "status": "built",
            "protected_apk": protected[0].name,
            "size_bytes": size,
        }

    log_file = appshield_dir / "apkdefender.log"
    if log_file.is_file():
        errors = [l for l in log_file.read_text().splitlines() if "ERROR" in l]
        if errors:
            return {"status": "failed", "errors": errors[:5]}

    return {"status": "not_run"}


def _build_pipeline_section(summary):
    """Pipeline execution summary."""
    stages = {}
    for name, data in summary.get("stages", {}).items():
        stages[name] = {
            "status": data.get("status", "?"),
            "duration": data.get("duration_seconds"),
        }
        if data.get("error"):
            stages[name]["error"] = data["error"][:200]

    return {
        "duration_seconds": summary.get("duration_seconds"),
        "stages": stages,
    }


# ── Text report rendering ───────────────────────────────────────────

def _render_text_report(report, analysis_dir):
    """Render the unified report as formatted text."""
    lines = []
    app = report["app"]
    score = report["security_score"]

    # ── Header ───────────────────────────────────────────────────────
    lines.append("=" * 80)
    lines.append("  MOBILE APPLICATION SECURITY ANALYSIS REPORT")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"  Package:     {app['package_name']}")
    lines.append(f"  Version:     {app['version_name']} ({app['version_code']})")
    lines.append(f"  Size:        {app['size']}")
    lines.append(f"  SDK:         min={app['min_sdk']}  target={app['target_sdk']}")
    lines.append(f"  Components:  {app['activities']} activities, {app['services']} services, "
                 f"{app['receivers']} receivers, {app['providers']} providers")
    lines.append(f"  Permissions: {app['permissions']}")
    lines.append(f"  Generated:   {report['generated_at']}")
    lines.append("")

    # ── Risk Rating ──────────────────────────────────────────────────
    lines.append("-" * 80)
    rating = score["risk_rating"]
    counts = score["counts"]
    lines.append(f"  RISK RATING: {rating}  (score: {score['risk_score']})")
    lines.append("")
    lines.append(f"    High: {counts.get('high', 0)}  |  Warning: {counts.get('warning', 0)}  |  "
                 f"Info: {counts.get('info', 0)}  |  Secure: {counts.get('secure', 0)}  |  "
                 f"Hotspot: {counts.get('hotspot', 0)}")
    lines.append("")

    # ── Critical & High Findings ─────────────────────────────────────
    findings = report.get("mobsf_findings", [])
    high_findings = [f for f in findings if f["severity"] in ("high", "hotspot")]
    if high_findings:
        lines.append("-" * 80)
        lines.append("  HIGH-SEVERITY FINDINGS")
        lines.append("-" * 80)
        for f in high_findings:
            tag = f["severity"].upper()
            lines.append(f"  [{tag}] {f['title']}")
        lines.append("")

    # ── Warnings ─────────────────────────────────────────────────────
    warn_findings = [f for f in findings if f["severity"] == "warning"]
    if warn_findings:
        lines.append("-" * 80)
        lines.append(f"  WARNINGS ({len(warn_findings)})")
        lines.append("-" * 80)
        for f in warn_findings:
            lines.append(f"  - {f['title']}")
        lines.append("")

    # ── Attack Surface ───────────────────────────────────────────────
    surface = report.get("attack_surface", [])
    if surface:
        lines.append("-" * 80)
        lines.append("  ATTACK SURFACE (bytecode + native)")
        lines.append("-" * 80)
        lines.append(f"  {'Risk':10s}  {'Category':<42s}  {'Bytecode':>8s}  {'Native':>7s}  {'Total':>6s}")
        lines.append(f"  {'-'*10}  {'-'*42}  {'-'*8}  {'-'*7}  {'-'*6}")
        for cat in surface:
            lines.append(f"  {cat['risk']:10s}  {cat['category']:<42s}  "
                         f"{cat['bytecode_hits']:>8d}  {cat['native_hits']:>7d}  {cat['total']:>6d}")
        lines.append("")

    # ── Detected Protections ─────────────────────────────────────────
    protections = report.get("protections", {})
    detected = protections.get("detected", [])
    if detected:
        lines.append("-" * 80)
        lines.append("  DETECTED PROTECTIONS")
        lines.append("-" * 80)
        for p in detected:
            source = p.get("source", "")
            if "name" in p:
                lines.append(f"  [{source}] {p['type']}: {p['name']}")
            else:
                lines.append(f"  [{source}] {p['type']}  ({p.get('matches', 0)} references)")

        bypass = protections.get("bypass", {})
        if bypass:
            lines.append("")
            lines.append("  Bypass Assessment:")
            if bypass.get("network_security_config"):
                lines.append("    - Network security config will be injected (TLS interception)")
            if bypass.get("script_generated"):
                lines.append("    - Auto-generated Frida bypass script created")
            if bypass.get("target_class"):
                lines.append(f"    - Injection target: {bypass['target_class']}")
        lines.append("")

    # ── Native Library Security ──────────────────────────────────────
    native = report.get("native_security", {})
    if native and native.get("libraries"):
        lines.append("-" * 80)
        lines.append(f"  NATIVE LIBRARIES ({native['library_count']} libraries, "
                     f"{native['abi']}, {native['total_jni_exports']} JNI exports)")
        lines.append("-" * 80)

        lines.append(f"  {'Library':<35s}  {'RELRO':>12s}  {'Canary':>6s}  {'NX':>4s}  {'Fortify':>7s}")
        lines.append(f"  {'-'*35}  {'-'*12}  {'-'*6}  {'-'*4}  {'-'*7}")
        for lib in native["libraries"]:
            canary = "Yes" if lib["stack_canary"] else "No"
            nx = "Yes" if lib["nx"] else "No"
            fortify = "Yes" if lib["fortify"] else "No"
            lines.append(f"  {lib['name']:<35s}  {lib['relro']:>12s}  {canary:>6s}  {nx:>4s}  {fortify:>7s}")

        if native.get("internal_urls"):
            lines.append("")
            lines.append("  Internal/Development URLs found in native code:")
            for url in native["internal_urls"][:10]:
                lines.append(f"    - {url}")

        if native.get("leaked_build_paths"):
            lines.append(f"\n  Build paths leaked: {native['leaked_build_paths']}")

        lines.append("")

    # ── Repackage & Protection Build ─────────────────────────────────
    repackage = report.get("repackage_test", {})
    appshield = report.get("appshield", {})
    lines.append("-" * 80)
    lines.append("  BUILD TESTS")
    lines.append("-" * 80)
    lines.append(f"  Repackage test: {repackage.get('status', '?').upper()}")
    if repackage.get("status") == "fail":
        lines.append(f"    {repackage.get('detail', '')[:100]}")
    lines.append(f"  AppShield build: {appshield.get('status', '?').upper()}")
    if appshield.get("protected_apk"):
        lines.append(f"    Protected APK: {appshield['protected_apk']}")
    lines.append("")

    # ── Pipeline Summary ─────────────────────────────────────────────
    pipeline = report.get("pipeline", {})
    stages = pipeline.get("stages", {})
    if stages:
        lines.append("-" * 80)
        lines.append("  PIPELINE SUMMARY")
        lines.append("-" * 80)
        for name, data in stages.items():
            status = data["status"]
            dur = data.get("duration")
            dur_str = f"{dur:.1f}s" if dur else ""
            marker = {"ok": "PASS", "error": "FAIL", "skipped": "SKIP"}.get(status, status)
            lines.append(f"  {marker:5s}  {name:<20s}  {dur_str}")
        dur_total = pipeline.get("duration_seconds")
        if dur_total:
            lines.append(f"\n  Total: {dur_total:.0f}s")
        lines.append("")

    # ── Footer ───────────────────────────────────────────────────────
    lines.append("=" * 80)
    lines.append("  Report generated by cli-anything-mobsf")
    lines.append("  Detailed reports available in stage subdirectories")
    lines.append("=" * 80)

    return "\n".join(lines)


# ── Helpers ──────────────────────────────────────────────────────────

def _load_json(path):
    path = Path(path)
    if path.is_file():
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _read_text(path):
    path = Path(path)
    if path.is_file():
        try:
            return path.read_text()
        except OSError:
            pass
    return ""

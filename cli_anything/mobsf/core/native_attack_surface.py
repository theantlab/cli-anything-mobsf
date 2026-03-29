"""Native library attack surface analysis.

Analyses extracted .so files via their strings and ELF metadata to produce
a security-focused report covering:
  - ELF security features (RELRO, stack canary, NX, PIE)
  - JNI exported functions
  - Shared library dependencies
  - Hardcoded URLs, IPs, file paths
  - Cryptographic references
  - Credential/secret indicators
  - Anti-analysis and protection references
  - Compiler and build information
"""
import json
import re
from collections import defaultdict
from pathlib import Path


# ── Pattern categories for strings analysis ──────────────────────────

NATIVE_CATEGORIES = {
    "Hardcoded URLs & Endpoints": {
        "description": "URLs and network endpoints compiled into native code. May reveal staging, debug, or internal API endpoints.",
        "risk": "HIGH",
        "patterns": [
            (re.compile(r'https?://[^\s"<>]{5,}'), "HTTP/HTTPS URL"),
            (re.compile(r'ftp://[^\s"<>]{5,}'), "FTP URL"),
            (re.compile(r'wss?://[^\s"<>]{5,}'), "WebSocket URL"),
            (re.compile(r'jdbc:[^\s"<>]{5,}'), "JDBC connection string"),
        ],
    },
    "Hardcoded IPs & Hosts": {
        "description": "IP addresses and hostnames in native code. Internal IPs indicate dev/staging leaks.",
        "risk": "HIGH",
        "patterns": [
            (re.compile(r'\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b'), "Private/internal IP address"),
            (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b(?!.*\.so)'), "IPv4 address"),
        ],
    },
    "Credentials & Secrets": {
        "description": "Potential hardcoded credentials, API keys, tokens, or secrets in native code.",
        "risk": "CRITICAL",
        "regex_patterns": True,
        "patterns": [
            (re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*\S+'), "Hardcoded password"),
            (re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*\S+'), "API key assignment"),
            (re.compile(r'(?i)(secret|token|auth)\s*[=:]\s*["\'][^"\']{8,}'), "Secret/token assignment"),
            (re.compile(r'(?i)bearer\s+[a-zA-Z0-9._\-]{20,}'), "Bearer token"),
            (re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'), "Embedded private key"),
            (re.compile(r'-----BEGIN CERTIFICATE-----'), "Embedded certificate"),
        ],
    },
    "Cryptography": {
        "description": "Cryptographic algorithm and API references. Weak algorithms or modes indicate vulnerabilities.",
        "risk": "HIGH",
        "literal_patterns": [
            ("AES/ECB", "AES in ECB mode (weak — no IV)"),
            ("DES", "DES encryption (weak — 56-bit key)"),
            ("3DES", "Triple DES (legacy)"),
            ("RC4", "RC4 stream cipher (broken)"),
            ("MD5", "MD5 hash (collision-vulnerable)"),
            ("SHA1", "SHA-1 hash (collision-vulnerable)"),
            ("SHA256", "SHA-256 hash"),
            ("SHA512", "SHA-512 hash"),
            ("RSA", "RSA algorithm reference"),
            ("ECDSA", "ECDSA signature"),
            ("AES", "AES encryption"),
            ("HMAC", "HMAC authentication"),
            ("PBKDF", "Key derivation function"),
            ("EVP_", "OpenSSL EVP API"),
            ("SSL_CTX", "OpenSSL context"),
            ("SSL_connect", "OpenSSL connect"),
            ("SSL_read", "OpenSSL read"),
            ("SSL_write", "OpenSSL write"),
            ("X509_", "X.509 certificate operations"),
            ("BIO_", "OpenSSL BIO I/O"),
        ],
    },
    "Anti-Analysis & Protection": {
        "description": "Anti-debugging, anti-tampering, and environment detection in native code.",
        "risk": "MEDIUM",
        "literal_patterns": [
            ("ptrace", "ptrace syscall (anti-debug)"),
            ("PTRACE_TRACEME", "Self-trace anti-debug"),
            ("/proc/self/maps", "Process memory map check"),
            ("/proc/self/status", "Process status check (TracerPid)"),
            ("/proc/self/cmdline", "Command line inspection"),
            ("/proc/net/tcp", "Network connection enumeration"),
            ("TracerPid", "Debugger tracer PID check"),
            ("frida", "Frida detection reference"),
            ("xposed", "Xposed detection reference"),
            ("substrate", "Cydia Substrate reference"),
            ("debugger", "Debugger reference"),
            ("isDebuggerConnected", "Java debugger check via JNI"),
            ("anti_debug", "Anti-debug function"),
            ("anti_tamper", "Anti-tamper function"),
            ("integrity_check", "Integrity verification"),
            ("checksum", "Checksum validation"),
        ],
    },
    "Root & Environment Detection": {
        "description": "Root detection and environment fingerprinting in native code.",
        "risk": "MEDIUM",
        "literal_patterns": [
            ("/system/xbin/su", "su binary path"),
            ("/system/bin/su", "su binary path"),
            ("/sbin/su", "su binary path"),
            ("Superuser", "Superuser reference"),
            ("supersu", "SuperSU reference"),
            ("magisk", "Magisk reference"),
            ("test-keys", "Test signing keys"),
            ("ro.debuggable", "Debuggable property"),
            ("ro.secure", "Secure property"),
            ("ro.build.tags", "Build tags"),
            ("goldfish", "Emulator kernel"),
            ("ranchu", "Emulator kernel"),
            ("generic", "Generic device (emulator indicator)"),
        ],
    },
    "File System & Data Access": {
        "description": "File paths, database references, and storage operations in native code.",
        "risk": "MEDIUM",
        "literal_patterns": [
            ("/data/data/", "App private data directory"),
            ("/sdcard/", "External storage path"),
            ("/storage/emulated", "Emulated storage"),
            (".db", "Database file reference"),
            ("sqlite3", "SQLite library"),
            ("PRAGMA key", "SQLCipher encrypted database"),
            ("shared_prefs", "SharedPreferences directory"),
            ("/tmp/", "Temporary file path"),
            ("chmod", "File permission change"),
            ("mkstemp", "Temporary file creation"),
        ],
    },
    "Logging & Information Leakage": {
        "description": "Logging functions and format strings that may leak sensitive data at runtime.",
        "risk": "MEDIUM",
        "literal_patterns": [
            ("__android_log_print", "Android native logging"),
            ("LOGD", "Debug log macro"),
            ("LOGI", "Info log macro"),
            ("LOGE", "Error log macro"),
            ("LOGW", "Warning log macro"),
            ("fprintf(stderr", "stderr output"),
            ("printf", "printf output (may leak to logcat)"),
        ],
    },
    "Protection Vendors": {
        "description": "Commercial protection tools detected in native code.",
        "risk": "INFO",
        "literal_patterns": [
            ("guardsquare", "Guardsquare (DexGuard/iXGuard)"),
            ("dexguard", "DexGuard protection"),
            ("arxan", "Arxan / Digital.ai"),
            ("promon", "Promon SHIELD"),
            ("verimatrix", "Verimatrix protection"),
            ("appshield", "AppShield reference"),
            ("zimperium", "Zimperium zShield"),
            ("appdome", "Appdome protection"),
            ("trusteer", "IBM Trusteer"),
            ("liapp", "LIAPP protection"),
            ("dexprotector", "DexProtector"),
        ],
    },
}


def analyse_native_libs(native_dir, output_dir):
    """Analyse native libraries and produce attack surface reports.

    Args:
        native_dir: Path to the native/ analysis directory (contains lib/, elf/, strings/)
        output_dir: Path to write native attack surface reports
    """
    native_dir = Path(native_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Find the analysed ABI
    lib_dir = native_dir / "lib"
    elf_dir = native_dir / "elf"
    strings_dir = native_dir / "strings"

    abi_dirs = [d.name for d in lib_dir.iterdir() if d.is_dir()] if lib_dir.is_dir() else []
    if not abi_dirs:
        return {}

    abi = abi_dirs[0]  # We only analyse one ABI

    # ── Gather library metadata ──────────────────────────────────────
    libraries = {}
    for so_file in sorted((lib_dir / abi).glob("*.so")):
        name = so_file.name
        lib_info = {
            "name": name,
            "size_bytes": so_file.stat().st_size,
            "size_human": _human_size(so_file.stat().st_size),
        }

        # Parse readelf output
        readelf_file = elf_dir / abi / f"{name}.readelf"
        if readelf_file.is_file():
            elf_text = readelf_file.read_text()
            lib_info["security"] = _parse_elf_security(elf_text)
            lib_info["dependencies"] = _parse_dependencies(elf_text)
            lib_info["jni_exports"] = _parse_jni_exports(elf_text)
            lib_info["exported_symbols"] = _count_exports(elf_text)

        # Scan strings
        strings_file = strings_dir / abi / f"{name}.strings"
        if strings_file.is_file():
            strings_text = strings_file.read_text()
            lib_info["string_count"] = strings_text.count("\n")
            lib_info["findings"] = _scan_strings(strings_text)
            lib_info["urls"] = _extract_urls(strings_text)
            lib_info["build_info"] = _extract_build_info(strings_text)

        libraries[name] = lib_info

    # ── Aggregate findings across all libraries ──────────────────────
    aggregated = _aggregate_findings(libraries)

    # ── Produce reports ──────────────────────────────────────────────
    report = {
        "abi": abi,
        "library_count": len(libraries),
        "total_size_bytes": sum(l["size_bytes"] for l in libraries.values()),
        "libraries": libraries,
        "aggregated": aggregated,
    }

    (output_dir / "native_attack_surface.json").write_text(
        json.dumps(report, indent=2, default=str))

    _write_native_report(report, output_dir / "native_attack_surface_report.txt")
    _write_native_summary(report, output_dir / "native_attack_surface_summary.txt")

    return report


# ── ELF parsing ──────────────────────────────────────────────────────

def _parse_elf_security(elf_text):
    """Extract ELF security features from readelf output."""
    security = {}

    # RELRO (RELocation Read-Only)
    if "GNU_RELRO" in elf_text:
        if "BIND_NOW" in elf_text:
            security["relro"] = "Full RELRO"
        else:
            security["relro"] = "Partial RELRO"
    else:
        security["relro"] = "No RELRO"

    # Stack canary
    security["stack_canary"] = "__stack_chk_fail" in elf_text

    # NX (Non-eXecutable stack)
    # Look for GNU_STACK with no E (execute) flag
    stack_match = re.search(r'GNU_STACK.*?(?:RW|R E|RWE)', elf_text)
    if stack_match:
        security["nx"] = "E" not in stack_match.group()
    else:
        security["nx"] = True  # Default assumption for modern Android

    # PIE (Position Independent Executable) — shared libs are always PIC
    security["pic"] = "DYN" in elf_text

    # FORTIFY_SOURCE
    security["fortify"] = "__fortify_chk" in elf_text or "__builtin___" in elf_text

    # RPATH/RUNPATH (bad practice — hardcoded library paths)
    security["rpath"] = "RPATH" in elf_text or "RUNPATH" in elf_text

    return security


def _parse_dependencies(elf_text):
    """Extract shared library dependencies."""
    deps = []
    for match in re.finditer(r'\(NEEDED\)\s+Shared library:\s+\[([^\]]+)\]', elf_text):
        deps.append(match.group(1))
    return deps


def _parse_jni_exports(elf_text):
    """Extract JNI-exported functions (Java_* symbols)."""
    jni_funcs = []
    for match in re.finditer(r'\bJava_([a-zA-Z0-9_]+)', elf_text):
        full_name = "Java_" + match.group(1)
        # Convert JNI name to Java-style: Java_com_example_Class_method
        parts = full_name.split("_")[1:]  # drop "Java"
        if len(parts) >= 2:
            java_name = ".".join(parts[:-1]) + "." + parts[-1]
        else:
            java_name = full_name
        if full_name not in [j["symbol"] for j in jni_funcs]:
            jni_funcs.append({"symbol": full_name, "java_name": java_name})
    return jni_funcs


def _count_exports(elf_text):
    """Count total exported (GLOBAL) symbols."""
    return len(re.findall(r'\bGLOBAL\b.*\bFUNC\b', elf_text))


# ── Strings analysis ────────────────────────────────────────────────

def _scan_strings(strings_text):
    """Scan strings for security-relevant patterns."""
    findings = {}
    lines = strings_text.splitlines()

    for category_name, category_data in NATIVE_CATEGORIES.items():
        cat_findings = []

        # Regex patterns
        for pattern, description in category_data.get("patterns", []):
            matches = []
            for line in lines:
                if pattern.search(line):
                    matches.append(line.strip()[:200])
            if matches:
                cat_findings.append({
                    "pattern": description,
                    "match_count": len(matches),
                    "samples": matches[:5],
                })

        # Literal patterns (case-insensitive)
        for literal, description in category_data.get("literal_patterns", []):
            literal_lower = literal.lower()
            matches = []
            for line in lines:
                if literal_lower in line.lower():
                    matches.append(line.strip()[:200])
            if matches:
                cat_findings.append({
                    "pattern": description,
                    "match_count": len(matches),
                    "samples": matches[:5],
                })

        if cat_findings:
            total = sum(f["match_count"] for f in cat_findings)
            findings[category_name] = {
                "risk": category_data["risk"],
                "description": category_data["description"],
                "total_matches": total,
                "pattern_hits": len(cat_findings),
                "findings": cat_findings,
            }

    return findings


def _extract_urls(strings_text):
    """Extract all unique URLs from strings."""
    url_pattern = re.compile(r'(https?://[^\s"<>\']{5,})')
    urls = set()
    for match in url_pattern.finditer(strings_text):
        url = match.group(1).rstrip('.,;:)]}')
        urls.add(url)
    return sorted(urls)


def _extract_build_info(strings_text):
    """Extract compiler/build information from strings."""
    info = {}
    # Clang/GCC version
    for match in re.finditer(r'((?:clang|gcc|GCC)\s+version\s+[\d.]+[^\n]{0,80})', strings_text, re.IGNORECASE):
        info.setdefault("compilers", []).append(match.group(1).strip()[:120])
    # Android NDK
    for match in re.finditer(r'(Android\s+\([^)]+\)\s+[Cc]lang[^\n]{0,80})', strings_text):
        info.setdefault("ndk", []).append(match.group(1).strip()[:120])
    # Build paths that reveal directory structure
    for match in re.finditer(r'(/home/[^\s]{5,80}|/Users/[^\s]{5,80}|/build/[^\s]{5,80})', strings_text):
        info.setdefault("build_paths", []).append(match.group(1))

    # Deduplicate
    for key in info:
        info[key] = sorted(set(info[key]))[:10]

    return info


# ── Aggregation ──────────────────────────────────────────────────────

def _aggregate_findings(libraries):
    """Aggregate findings across all libraries into a unified view."""
    agg = {}

    for lib_name, lib_info in libraries.items():
        for cat_name, cat_data in lib_info.get("findings", {}).items():
            if cat_name not in agg:
                agg[cat_name] = {
                    "risk": cat_data["risk"],
                    "description": cat_data["description"],
                    "total_matches": 0,
                    "libraries": [],
                }
            agg[cat_name]["total_matches"] += cat_data["total_matches"]
            agg[cat_name]["libraries"].append({
                "library": lib_name,
                "matches": cat_data["total_matches"],
                "findings": cat_data["findings"],
            })

    # Sort libraries within each category by match count
    for cat_data in agg.values():
        cat_data["libraries"].sort(key=lambda x: -x["matches"])

    return agg


# ── Report generation ────────────────────────────────────────────────

def _write_native_summary(report, output_path):
    """Write a concise native attack surface summary."""
    lines = []
    lines.append("NATIVE LIBRARY ATTACK SURFACE SUMMARY")
    lines.append("=" * 60)
    lines.append("")

    libs = report["libraries"]
    lines.append(f"ABI: {report['abi']}")
    lines.append(f"Libraries: {report['library_count']}")
    lines.append(f"Total size: {_human_size(report['total_size_bytes'])}")
    lines.append("")

    # Library overview
    lines.append("Library Overview:")
    lines.append(f"  {'Library':<35s}  {'Size':>8s}  {'Exports':>7s}  {'JNI':>4s}  {'Strings':>8s}")
    lines.append(f"  {'-'*35}  {'-'*8}  {'-'*7}  {'-'*4}  {'-'*8}")
    for name, lib in sorted(libs.items(), key=lambda x: -x[1]["size_bytes"]):
        exports = lib.get("exported_symbols", 0)
        jni = len(lib.get("jni_exports", []))
        strings = lib.get("string_count", 0)
        lines.append(f"  {name:<35s}  {lib['size_human']:>8s}  {exports:>7d}  {jni:>4d}  {strings:>8d}")
    lines.append("")

    # ELF security features
    lines.append("ELF Security Features:")
    lines.append(f"  {'Library':<35s}  {'RELRO':>12s}  {'Canary':>6s}  {'NX':>4s}  {'Fortify':>7s}")
    lines.append(f"  {'-'*35}  {'-'*12}  {'-'*6}  {'-'*4}  {'-'*7}")
    for name, lib in sorted(libs.items()):
        sec = lib.get("security", {})
        relro = sec.get("relro", "?")
        canary = "Yes" if sec.get("stack_canary") else "No"
        nx = "Yes" if sec.get("nx") else "No"
        fortify = "Yes" if sec.get("fortify") else "No"
        lines.append(f"  {name:<35s}  {relro:>12s}  {canary:>6s}  {nx:>4s}  {fortify:>7s}")
    lines.append("")

    # Aggregated risk distribution
    agg = report.get("aggregated", {})
    if agg:
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}

        risk_counts = defaultdict(int)
        risk_matches = defaultdict(int)
        for cat_data in agg.values():
            risk_counts[cat_data["risk"]] += 1
            risk_matches[cat_data["risk"]] += cat_data["total_matches"]

        lines.append("Risk Distribution:")
        for risk in ["CRITICAL", "HIGH", "MEDIUM", "INFO"]:
            if risk in risk_counts:
                lines.append(f"  {risk:10s}  {risk_counts[risk]:3d} categories  {risk_matches[risk]:6d} matches")
        lines.append("")

        lines.append("Categories (by risk then volume):")
        lines.append(f"  {'Risk':10s}  {'Category':<40s}  {'Hits':>6s}  {'Libraries':>9s}")
        lines.append(f"  {'-'*10}  {'-'*40}  {'-'*6}  {'-'*9}")
        sorted_cats = sorted(agg.items(),
                             key=lambda x: (risk_order.get(x[1]["risk"], 9), -x[1]["total_matches"]))
        for cat_name, cat_data in sorted_cats:
            lib_count = len(cat_data["libraries"])
            lines.append(f"  {cat_data['risk']:10s}  {cat_name:<40s}  {cat_data['total_matches']:6d}  {lib_count:>9d}")
        lines.append("")

    # Key findings
    lines.append("Key Findings:")
    lines.append("")

    # Weak ELF security
    weak_libs = [name for name, lib in libs.items()
                 if lib.get("security", {}).get("relro") == "No RELRO"
                 or not lib.get("security", {}).get("stack_canary")]
    if weak_libs:
        lines.append("  [!] HARDENING: Libraries with missing security features:")
        for name in weak_libs:
            sec = libs[name].get("security", {})
            issues = []
            if sec.get("relro") == "No RELRO":
                issues.append("no RELRO")
            if not sec.get("stack_canary"):
                issues.append("no stack canary")
            if not sec.get("fortify"):
                issues.append("no FORTIFY")
            lines.append(f"      - {name}: {', '.join(issues)}")

    # Credentials in native code
    if "Credentials & Secrets" in agg:
        creds = agg["Credentials & Secrets"]
        lines.append(f"  [!] SECRETS: {creds['total_matches']} potential credential references in native code")

    # URLs
    all_urls = set()
    for lib in libs.values():
        all_urls.update(lib.get("urls", []))
    if all_urls:
        internal = [u for u in all_urls if any(x in u for x in ["localhost", "127.0.0.1", "10.", "192.168.", "172."])]
        lines.append(f"  [!] URLS: {len(all_urls)} unique URLs found in native strings")
        if internal:
            lines.append(f"      {len(internal)} appear to be internal/development endpoints:")
            for url in sorted(internal)[:5]:
                lines.append(f"        - {url}")

    # JNI exports
    total_jni = sum(len(lib.get("jni_exports", [])) for lib in libs.values())
    if total_jni:
        lines.append(f"  [!] JNI: {total_jni} JNI-exported functions across {report['library_count']} libraries")

    # Build paths (info leak)
    all_paths = set()
    for lib in libs.values():
        all_paths.update(lib.get("build_info", {}).get("build_paths", []))
    if all_paths:
        lines.append(f"  [!] BUILD: {len(all_paths)} build paths leaked (developer directory structure)")
        for p in sorted(all_paths)[:3]:
            lines.append(f"        - {p}")

    Path(output_path).write_text("\n".join(lines))


def _write_native_report(report, output_path):
    """Write a detailed native attack surface report."""
    lines = []
    lines.append("=" * 80)
    lines.append("NATIVE LIBRARY ATTACK SURFACE REPORT")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"ABI: {report['abi']}  |  Libraries: {report['library_count']}  |  "
                 f"Total size: {_human_size(report['total_size_bytes'])}")
    lines.append("")

    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}

    # Per-library detailed report
    for lib_name, lib_info in sorted(report["libraries"].items(),
                                     key=lambda x: -x[1]["size_bytes"]):
        lines.append("=" * 80)
        lines.append(f"  {lib_name}  ({lib_info['size_human']})")
        lines.append("=" * 80)

        # Security features
        sec = lib_info.get("security", {})
        if sec:
            lines.append("")
            lines.append("  ELF Security:")
            lines.append(f"    RELRO: {sec.get('relro', '?')}")
            lines.append(f"    Stack Canary: {'Yes' if sec.get('stack_canary') else 'No'}")
            lines.append(f"    NX: {'Yes' if sec.get('nx') else 'No'}")
            lines.append(f"    PIC: {'Yes' if sec.get('pic') else 'No'}")
            lines.append(f"    FORTIFY: {'Yes' if sec.get('fortify') else 'No'}")
            if sec.get("rpath"):
                lines.append(f"    RPATH/RUNPATH: Present (hardcoded library path — bad practice)")

        # Dependencies
        deps = lib_info.get("dependencies", [])
        if deps:
            lines.append("")
            lines.append(f"  Dependencies ({len(deps)}):")
            for dep in deps:
                lines.append(f"    - {dep}")

        # JNI exports
        jni = lib_info.get("jni_exports", [])
        if jni:
            lines.append("")
            lines.append(f"  JNI Exports ({len(jni)}):")
            for func in jni[:30]:
                lines.append(f"    - {func['symbol']}")
            if len(jni) > 30:
                lines.append(f"    ... and {len(jni) - 30} more")

        # URLs
        urls = lib_info.get("urls", [])
        if urls:
            lines.append("")
            lines.append(f"  URLs ({len(urls)}):")
            for url in urls[:20]:
                lines.append(f"    - {url}")
            if len(urls) > 20:
                lines.append(f"    ... and {len(urls) - 20} more")

        # Build info
        build = lib_info.get("build_info", {})
        if build:
            lines.append("")
            lines.append("  Build Information:")
            for key, values in build.items():
                for v in values[:3]:
                    lines.append(f"    {key}: {v}")

        # Findings by category
        findings = lib_info.get("findings", {})
        if findings:
            lines.append("")
            lines.append("  Security Findings:")
            sorted_cats = sorted(findings.items(),
                                 key=lambda x: (risk_order.get(x[1]["risk"], 9),
                                                -x[1]["total_matches"]))
            for cat_name, cat_data in sorted_cats:
                lines.append("")
                lines.append(f"    [{cat_data['risk']}] {cat_name}  ({cat_data['total_matches']} hits)")
                for finding in sorted(cat_data["findings"], key=lambda f: -f["match_count"]):
                    lines.append(f"      * {finding['pattern']}  ({finding['match_count']})")
                    for sample in finding["samples"][:3]:
                        lines.append(f"          {sample[:100]}")

        lines.append("")

    Path(output_path).write_text("\n".join(lines))


def _human_size(nbytes):
    """Format bytes as human-readable size."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(nbytes) < 1024:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024
    return f"{nbytes:.1f} TB"

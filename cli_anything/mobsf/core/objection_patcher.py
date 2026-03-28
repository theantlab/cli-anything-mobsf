"""Intelligent Objection patching guided by analysis artifacts."""
import json
import os
import shutil
import subprocess
from pathlib import Path


class ObjectionPatcher:
    """Builds and runs an objection patchapk command informed by prior analysis.

    Reads from:
      - mobsf/report.json         → main activity, target SDK, package name, size
      - mobsf/apkid.json          → protection vendors, packers
      - attack_surface/attack_surface.json → TLS pinning, root detection, anti-debug
      - native/                   → which ABIs have .so files
      - apktool/<app>/            → AndroidManifest.xml for fallback activity detection
    """

    def __init__(self, analysis_dir, apk_path, echo=None):
        self.analysis_dir = Path(analysis_dir)
        self.apk_path = Path(apk_path).resolve()
        self.apk_name = self.apk_path.stem
        self.echo = echo or print
        self.decisions = {}

        # Load analysis artifacts
        self.mobsf_report = self._load_json("mobsf/report.json")
        self.apkid = self._load_json("mobsf/apkid.json")
        self.attack_surface = self._load_json("attack_surface/attack_surface.json")
        self.scorecard = self._load_json("mobsf/scorecard.json")

    def _load_json(self, rel_path):
        p = self.analysis_dir / rel_path
        if p.is_file():
            try:
                return json.loads(p.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def plan(self):
        """Analyse artifacts and decide on patching strategy. Returns the plan dict."""
        self.echo("  Analysing artifacts for patching strategy...")

        self.decisions = {
            "architecture": self._decide_architecture(),
            "target_class": self._decide_target_class(),
            "network_security_config": self._decide_network_security(),
            "enable_debug": self._decide_debug(),
            "use_aapt2": self._decide_aapt2(),
            "skip_resources": self._decide_skip_resources(),
            "gadget_config": self._decide_gadget_config(),
            "script_source": self._decide_script_source(),
            "ignore_nativelibs": self._decide_ignore_nativelibs(),
            "concurrency": self._decide_concurrency(),
            "gadget_version": self._get_frida_version(),
        }

        self._print_plan()
        return self.decisions

    def patch(self, output_dir=None):
        """Execute the patching based on the plan."""
        if not self.decisions:
            self.plan()

        output_dir = Path(output_dir) if output_dir else self.analysis_dir / "objection"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Copy APK to output dir
        apk_copy = output_dir / self.apk_path.name
        if not apk_copy.exists():
            shutil.copy2(self.apk_path, apk_copy)

        # Write gadget config if needed
        gadget_config_path = None
        if self.decisions.get("gadget_config"):
            gadget_config_path = output_dir / "gadget-config.json"
            gadget_config_path.write_text(json.dumps(self.decisions["gadget_config"], indent=2))

        # Write auto-load script if needed
        script_path = None
        if self.decisions.get("script_source"):
            script_path = output_dir / "libfrida-gadget.script.so"
            script_path.write_text(self.decisions["script_source"])

        # Build command
        cmd = ["objection", "patchapk", "--source", str(apk_copy)]

        d = self.decisions

        if d.get("architecture"):
            cmd.extend(["-a", d["architecture"]])

        if d.get("gadget_version"):
            cmd.extend(["--gadget-version", d["gadget_version"]])

        if d.get("target_class"):
            cmd.extend(["--target-class", d["target_class"]])

        if d.get("network_security_config"):
            cmd.append("--network-security-config")

        if d.get("enable_debug"):
            cmd.append("--enable-debug")

        if d.get("use_aapt2"):
            cmd.append("--use-aapt2")

        if d.get("skip_resources"):
            cmd.append("--skip-resources")

        if gadget_config_path:
            cmd.extend(["--gadget-config", str(gadget_config_path)])

        if script_path:
            cmd.extend(["--script-source", str(script_path)])

        if d.get("ignore_nativelibs"):
            cmd.append("--ignore-nativelibs")

        if d.get("concurrency"):
            cmd.extend(["--fix-concurrency-to", str(d["concurrency"])])

        # Write the command for reference
        (output_dir / "objection_command.txt").write_text(" ".join(cmd))

        # Write the full decision log
        (output_dir / "patching_decisions.json").write_text(
            json.dumps(self.decisions, indent=2, default=str)
        )

        self.echo(f"  Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, cwd=str(output_dir), capture_output=True, text=True)

        (output_dir / "objection_stdout.txt").write_text(result.stdout)
        (output_dir / "objection_stderr.txt").write_text(result.stderr)

        if result.returncode != 0:
            self.echo(f"  Objection exited with code {result.returncode}")
            self.echo(f"  stderr: {result.stderr[:500]}")
        else:
            # Find the patched APK
            patched = list(output_dir.glob("*.objection.apk"))
            if patched:
                self.echo(f"  Patched APK: {patched[0].name}")
            else:
                self.echo("  Warning: No .objection.apk found in output")

        return result.returncode

    # ── Decision methods ──────────────────────────────────────────────

    def _decide_architecture(self):
        """Pick best ABI from native libraries found during analysis."""
        # Check what ABIs actually have native libs
        native_dir = self.analysis_dir / "native" / "elf"
        available_abis = []
        if native_dir.is_dir():
            available_abis = [d.name for d in native_dir.iterdir() if d.is_dir()]

        # Also check apktool lib dir
        if not available_abis:
            apktool_lib = self.analysis_dir / "apktool" / self.apk_name / "lib"
            if apktool_lib.is_dir():
                available_abis = [d.name for d in apktool_lib.iterdir() if d.is_dir()]

        # Prefer arm64-v8a, then armeabi-v7a
        preferred = ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"]
        for abi in preferred:
            if abi in available_abis:
                self._log_decision("architecture", abi,
                                   f"Selected from available ABIs: {available_abis}")
                return abi

        if available_abis:
            self._log_decision("architecture", available_abis[0],
                               f"Fallback to first available ABI: {available_abis}")
            return available_abis[0]

        self._log_decision("architecture", "arm64-v8a",
                           "No native libs found, defaulting to arm64-v8a")
        return "arm64-v8a"

    def _decide_target_class(self):
        """Find the best class to inject the Frida gadget into.

        Priority:
        1. Main/launcher activity from MobSF report
        2. Application subclass (loads earliest)
        3. Fall back to main activity from manifest
        """
        # From MobSF report — main activity
        main_activity = self.mobsf_report.get("main_activity", "")

        # Check if there's an Application class — it loads before any activity
        app_class = self._find_application_class()
        if app_class:
            self._log_decision("target_class", app_class,
                               "Application subclass found — loads before activities, "
                               "best injection point for early hooking")
            return app_class

        if main_activity:
            self._log_decision("target_class", main_activity,
                               f"Main/launcher activity from MobSF report")
            return main_activity

        self._log_decision("target_class", None,
                           "No target class identified, objection will auto-detect")
        return None

    def _find_application_class(self):
        """Look for a custom Application class in AndroidManifest.xml."""
        manifest_path = self.analysis_dir / "apktool" / self.apk_name / "AndroidManifest.xml"
        if not manifest_path.is_file():
            return None

        try:
            content = manifest_path.read_text()
            import re
            match = re.search(r'android:name="([^"]+)"', content.split("<application")[1].split(">")[0])
            if match:
                class_name = match.group(1)
                # Ignore generic/framework Application classes
                if class_name.startswith("."):
                    pkg = self.mobsf_report.get("package_name", "")
                    class_name = pkg + class_name
                if "android." not in class_name and "androidx." not in class_name:
                    return class_name
        except (IndexError, OSError):
            pass
        return None

    def _decide_network_security(self):
        """Enable network security config if TLS pinning or cert validation detected.

        This injects a network_security_config.xml that trusts user-installed CAs,
        critical for intercepting HTTPS traffic with tools like mitmproxy/Burp.
        """
        reasons = []

        # Check attack surface for TLS/pinning indicators
        tls_cat = self.attack_surface.get("Network & TLS Configuration", {})
        if tls_cat:
            pinning_patterns = ["CertificatePinner", "ssl-pinning", "checkServerTrusted",
                                "X509TrustManager", "SSLSocketFactory", "HostnameVerifier"]
            for finding in tls_cat.get("findings", []):
                if finding["pattern"] in pinning_patterns:
                    reasons.append(f"{finding['pattern']} ({finding['match_count']} hits)")

        # Check target SDK — Android 7+ (SDK 24) needs this for user CA trust
        target_sdk = self.mobsf_report.get("target_sdk", "")
        try:
            if int(target_sdk) >= 24:
                reasons.append(f"targetSdk={target_sdk} (>= 24, requires NSC for user CAs)")
        except (ValueError, TypeError):
            pass

        # Check scorecard for pinning findings
        for severity in ["high", "warning"]:
            for finding in self.scorecard.get(severity, []):
                title = finding.get("title", "").lower()
                if "pinning" in title or "certificate" in title or "ssl" in title:
                    reasons.append(f"Scorecard: {finding['title'][:60]}")

        if reasons:
            self._log_decision("network_security_config", True,
                               "TLS interception support needed: " + "; ".join(reasons[:5]))
            return True

        self._log_decision("network_security_config", False, "No TLS pinning indicators found")
        return False

    def _decide_debug(self):
        """Enable debuggable flag if the app has anti-debug but we want to attach."""
        anti_debug = self.attack_surface.get("Anti-Debug & Dynamic Analysis", {})
        if anti_debug and anti_debug.get("total_matches", 0) > 0:
            self._log_decision("enable_debug", True,
                               f"Anti-debug detected ({anti_debug['total_matches']} hits) — "
                               "enabling debuggable for debugger attachment")
            return True

        self._log_decision("enable_debug", True,
                           "Enabling debuggable flag for dynamic analysis flexibility")
        return True

    def _decide_aapt2(self):
        """Use aapt2 — it's the modern default."""
        self._log_decision("use_aapt2", True, "aapt2 is standard for modern builds")
        return True

    def _decide_skip_resources(self):
        """Skip resource decoding for heavily protected/large APKs that may fail."""
        reasons = []
        skip = False

        # Check for known packers that complicate resource handling
        if self.apkid:
            for entry_name, entry_data in self.apkid.items():
                packers = entry_data.get("packer", [])
                if packers:
                    reasons.append(f"Packer detected: {', '.join(packers)}")

        # Check APK size — very large APKs benefit from skipping resources
        size_str = self.mobsf_report.get("size", "")
        if size_str:
            try:
                size_mb = float(size_str.replace("MB", "").replace("GB", "").strip())
                if "GB" in size_str or size_mb > 150:
                    reasons.append(f"Large APK ({size_str})")
                    skip = True
            except ValueError:
                pass

        # Don't skip if we need network_security_config (it modifies resources)
        if self.decisions.get("network_security_config"):
            if reasons:
                self._log_decision("skip_resources", False,
                                   f"Would skip ({'; '.join(reasons)}) but "
                                   "network_security_config requires resource processing")
            else:
                self._log_decision("skip_resources", False,
                                   "network_security_config requires resource processing")
            return False

        if skip:
            self._log_decision("skip_resources", True, "; ".join(reasons))
            return True

        self._log_decision("skip_resources", False, "Standard resource processing")
        return False

    def _decide_gadget_config(self):
        """Build a Frida gadget config based on detected protections.

        Returns a config dict or None for default behaviour.
        """
        # If we're generating a script, use "path" interaction type
        if self.decisions.get("script_source"):
            config = {
                "interaction": {
                    "type": "script",
                    "path": "libfrida-gadget.script.so",
                }
            }
            self._log_decision("gadget_config", "script-autoload",
                               "Auto-loading bypass script on startup")
            return config

        # Default: listen mode for manual attachment
        self._log_decision("gadget_config", None, "Default listen mode for manual Frida attachment")
        return None

    def _decide_script_source(self):
        """Generate a Frida startup script based on detected protections.

        Builds a script that auto-bypasses detected protections on app launch.
        """
        script_parts = [
            '// Auto-generated Frida startup script',
            '// Based on attack surface analysis',
            '"use strict";',
            '',
        ]
        has_bypasses = False

        # SSL pinning bypass if TLS pinning detected
        tls_cat = self.attack_surface.get("Network & TLS Configuration", {})
        pinning_found = False
        if tls_cat:
            for finding in tls_cat.get("findings", []):
                if finding["pattern"] in ("CertificatePinner", "ssl-pinning",
                                          "checkServerTrusted", "X509TrustManager"):
                    pinning_found = True
                    break

        if pinning_found:
            has_bypasses = True
            script_parts.extend([
                '// ── SSL Pinning Bypass ──────────────────────────────────────',
                '// Detected: CertificatePinner / custom TrustManager',
                'Java.perform(function() {',
                '    // Bypass X509TrustManager',
                '    var TrustManager = Java.use("javax.net.ssl.X509TrustManager");',
                '    var SSLContext = Java.use("javax.net.ssl.SSLContext");',
                '',
                '    var TrustManagerImpl = Java.registerClass({',
                '        name: "com.frida.TrustManager",',
                '        implements: [TrustManager],',
                '        methods: {',
                '            checkClientTrusted: function(chain, authType) {},',
                '            checkServerTrusted: function(chain, authType) {},',
                '            getAcceptedIssuers: function() { return []; }',
                '        }',
                '    });',
                '',
                '    var ctx = SSLContext.getInstance("TLS");',
                '    ctx.init(null, [TrustManagerImpl.$new()], null);',
                '    SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(km, tm, sr) {',
                '        this.init(km, [TrustManagerImpl.$new()], sr);',
                '    };',
                '',
                '    // Bypass OkHttp CertificatePinner',
                '    try {',
                '        var CertPinner = Java.use("okhttp3.CertificatePinner");',
                '        CertPinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCerts) {',
                '            console.log("[*] OkHttp CertificatePinner bypassed for: " + hostname);',
                '        };',
                '    } catch(e) {}',
                '',
                '    console.log("[*] SSL Pinning bypass applied");',
                '});',
                '',
            ])

        # Root detection bypass if root checks detected
        root_cat = self.attack_surface.get("Root Detection", {})
        if root_cat and root_cat.get("total_matches", 0) > 5:
            has_bypasses = True
            # Detect which root detection library
            rootbeer = any(f["pattern"] == "rootBeer"
                          for f in root_cat.get("findings", []))

            script_parts.extend([
                '// ── Root Detection Bypass ───────────────────────────────────',
                f'// Detected: {root_cat["total_matches"]} root check references',
            ])

            if rootbeer:
                script_parts.extend([
                    '// RootBeer library detected',
                    'Java.perform(function() {',
                    '    try {',
                    '        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");',
                    '        var methods = ["isRooted", "isRootedWithoutBusyBoxCheck",',
                    '                       "detectRootManagementApps", "detectPotentiallyDangerousApps",',
                    '                       "detectTestKeys", "checkForBinary", "checkForDangerousProps",',
                    '                       "checkForRWPaths", "detectRootCloakingApps",',
                    '                       "checkSuExists", "checkForRootNative", "checkForMagiskBinary"];',
                    '        methods.forEach(function(method) {',
                    '            try {',
                    '                RootBeer[method].overload().implementation = function() {',
                    '                    console.log("[*] RootBeer." + method + "() bypassed");',
                    '                    return false;',
                    '                };',
                    '            } catch(e) {}',
                    '        });',
                    '        console.log("[*] RootBeer bypass applied");',
                    '    } catch(e) {',
                    '        console.log("[!] RootBeer not found: " + e);',
                    '    }',
                    '});',
                    '',
                ])
            else:
                script_parts.extend([
                    '// Generic root check bypass',
                    'Java.perform(function() {',
                    '    // Hook common su binary checks',
                    '    var Runtime = Java.use("java.lang.Runtime");',
                    '    Runtime.exec.overload("java.lang.String").implementation = function(cmd) {',
                    '        if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {',
                    '            console.log("[*] Blocked exec: " + cmd);',
                    '            throw Java.use("java.io.IOException").$new("not found");',
                    '        }',
                    '        return this.exec(cmd);',
                    '    };',
                    '',
                    '    // Hook File.exists for su paths',
                    '    var File = Java.use("java.io.File");',
                    '    File.exists.implementation = function() {',
                    '        var path = this.getAbsolutePath();',
                    '        var blocked = ["/su", "/sbin/su", "/system/xbin/su", "/system/bin/su",',
                    '                       "/data/local/su", "Superuser.apk", "magisk", "busybox"];',
                    '        for (var i = 0; i < blocked.length; i++) {',
                    '            if (path.indexOf(blocked[i]) !== -1) {',
                    '                console.log("[*] Root check bypassed: " + path);',
                    '                return false;',
                    '            }',
                    '        }',
                    '        return this.exists();',
                    '    };',
                    '',
                    '    // Hook Build.TAGS',
                    '    var Build = Java.use("android.os.Build");',
                    '    Build.TAGS.value = "release-keys";',
                    '',
                    '    console.log("[*] Generic root bypass applied");',
                    '});',
                    '',
                ])

        # Debugger detection bypass
        debug_cat = self.attack_surface.get("Anti-Debug & Dynamic Analysis", {})
        hooking_cat = self.attack_surface.get("Hooking Framework Detection", {})

        if (debug_cat and debug_cat.get("total_matches", 0) > 3) or \
           (hooking_cat and hooking_cat.get("total_matches", 0) > 0):
            has_bypasses = True
            script_parts.extend([
                '// ── Anti-Debug / Anti-Frida Bypass ─────────────────────────',
                'Java.perform(function() {',
                '    // Bypass isDebuggerConnected',
                '    var Debug = Java.use("android.os.Debug");',
                '    Debug.isDebuggerConnected.implementation = function() {',
                '        console.log("[*] isDebuggerConnected() bypassed");',
                '        return false;',
                '    };',
                '',
                '    // Bypass TracerPid check via /proc/self/status',
                '    try {',
                '        var BufferedReader = Java.use("java.io.BufferedReader");',
                '        BufferedReader.readLine.overload().implementation = function() {',
                '            var line = this.readLine();',
                '            if (line && line.indexOf("TracerPid") !== -1) {',
                '                console.log("[*] TracerPid check bypassed");',
                '                return "TracerPid:\\t0";',
                '            }',
                '            return line;',
                '        };',
                '    } catch(e) {}',
                '',
                '    console.log("[*] Anti-debug bypass applied");',
                '});',
                '',
            ])

        if not has_bypasses:
            self._log_decision("script_source", None,
                               "No significant protections detected requiring auto-bypass")
            return None

        # Add summary footer
        script_parts.extend([
            '// ── Summary ─────────────────────────────────────────────────',
            'console.log("[*] All bypasses loaded. Ready for analysis.");',
        ])

        script_text = "\n".join(script_parts)
        self._log_decision("script_source", f"{len(script_parts)} lines",
                           "Auto-generated bypass script for detected protections")
        return script_text

    def _decide_ignore_nativelibs(self):
        """Check if extractNativeLibs should be left alone.

        Some protected APKs use compressed native libs that fail if extracted.
        """
        # If DexProtector or heavy packers detected, safer to ignore
        if self.apkid:
            for entry_data in self.apkid.values():
                packers = entry_data.get("packer", [])
                obfuscators = entry_data.get("obfuscator", [])
                if packers or any(o in ("DexProtector", "DexGuard 9.x") for o in obfuscators):
                    self._log_decision("ignore_nativelibs", True,
                                       f"Packer/obfuscator detected — preserving extractNativeLibs flag")
                    return True

        self._log_decision("ignore_nativelibs", False, "Standard native lib handling")
        return False

    def _decide_concurrency(self):
        """Limit threads for large APKs to prevent OOM during repackaging."""
        size_str = self.mobsf_report.get("size", "")
        if size_str:
            try:
                size_mb = float(size_str.replace("MB", "").replace("GB", "").strip())
                if "GB" in size_str:
                    size_mb *= 1024
                if size_mb > 100:
                    self._log_decision("concurrency", 1,
                                       f"Large APK ({size_str}) — limiting to 1 thread to prevent OOM")
                    return 1
            except ValueError:
                pass

        self._log_decision("concurrency", None, "Default concurrency")
        return None

    def _get_frida_version(self):
        """Get installed Frida version."""
        try:
            result = subprocess.run(["frida", "--version"], capture_output=True, text=True)
            version = result.stdout.strip()
            if version:
                return version
        except FileNotFoundError:
            pass
        return None

    # ── Helpers ───────────────────────────────────────────────────────

    def _log_decision(self, key, value, reason):
        """Record a decision with its reasoning."""
        if key not in self.decisions:
            self.decisions[key] = value
        self.decisions[f"_{key}_reason"] = reason
        display_val = value if not isinstance(value, str) or len(str(value)) < 80 else f"{str(value)[:77]}..."
        self.echo(f"    {key}: {display_val}")
        self.echo(f"      → {reason}")

    def _print_plan(self):
        """Print a summary of all decisions."""
        self.echo("")
        self.echo("  ── Patching Plan ─────────────────────────────────────")
        cmd_parts = ["objection patchapk"]
        d = self.decisions
        if d.get("architecture"):
            cmd_parts.append(f"-a {d['architecture']}")
        if d.get("gadget_version"):
            cmd_parts.append(f"--gadget-version {d['gadget_version']}")
        if d.get("target_class"):
            cmd_parts.append(f"-t {d['target_class']}")
        if d.get("network_security_config"):
            cmd_parts.append("-N")
        if d.get("enable_debug"):
            cmd_parts.append("-d")
        if d.get("use_aapt2"):
            cmd_parts.append("-2")
        if d.get("skip_resources"):
            cmd_parts.append("-D")
        if d.get("gadget_config"):
            cmd_parts.append("-c gadget-config.json")
        if d.get("script_source"):
            cmd_parts.append("-l libfrida-gadget.script.so")
        if d.get("ignore_nativelibs"):
            cmd_parts.append("-n")
        if d.get("concurrency"):
            cmd_parts.append(f"-j {d['concurrency']}")
        cmd_parts.append("-s <apk>")

        self.echo(f"  {' '.join(cmd_parts)}")
        self.echo("  ─────────────────────────────────────────────────────")

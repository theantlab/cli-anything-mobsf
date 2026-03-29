"""Full app analysis pipeline — MobSF + local toolchain."""
import json
import os
import resource
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from cli_anything.mobsf.core.attack_surface import scan_attack_surface
from cli_anything.mobsf.core.native_attack_surface import analyse_native_libs
from cli_anything.mobsf.core.objection_patcher import ObjectionPatcher
from cli_anything.mobsf.scripts import script_path, dictionary_path


ATTACK_KEYSTORE = Path.home() / ".android" / "attack.jks"


def _detect_sdk_version():
    """Return the latest installed Android SDK build-tools version, or None."""
    bt_dir = Path(os.environ.get("ANDROID_SDK", Path.home() / "Android" / "Sdk")) / "build-tools"
    if not bt_dir.is_dir():
        return None
    versions = sorted(
        (d.name for d in bt_dir.iterdir() if d.is_dir()),
        key=lambda v: [int(x) for x in v.split(".") if x.isdigit()],
    )
    return versions[-1] if versions else None


class AnalysisPipeline:
    """Orchestrates the full analysis workflow."""

    # Default resource limits
    DEFAULT_MAX_RAM_MB = 8192        # 8 GB per subprocess (virtual address space)
    JADX_MAX_RAM_MB = 4096           # 4 GB for JADX (Java heap)
    JADX_THREADS = 2                 # Limit JADX parallelism
    NICE_LEVEL = 10                  # Lower CPU priority (0=normal, 19=lowest)

    def __init__(self, apk_path, output_dir=None, sdk_version=None,
                 abis=None, backend=None, skip=None, echo=None,
                 max_ram_mb=None):
        self.apk_path = Path(apk_path).resolve()
        if not self.apk_path.is_file():
            raise FileNotFoundError(f"APK not found: {self.apk_path}")

        self.apk_name = self.apk_path.stem
        self.output_dir = Path(output_dir) if output_dir else Path.cwd() / f"{self.apk_name}_analysis"
        self.sdk_version = sdk_version or _detect_sdk_version() or "35.0.0"
        self.abis = abis or ["arm64-v8a", "armeabi-v7a"]
        self.backend = backend
        self.skip = set(skip or [])
        self.echo = echo or print
        self.max_ram_mb = max_ram_mb or self.DEFAULT_MAX_RAM_MB
        self.scan_hash = None
        self.started_at = datetime.now(timezone.utc)
        self.stage_results = {}

    def run(self):
        """Execute the full pipeline."""
        self._setup_dirs()

        stages = [
            ("mobsf", "MobSF upload & scan", self._stage_mobsf),
            ("decompiled", "JADX decompilation", self._stage_jadx),
            ("apkid", "APKiD fingerprinting", self._stage_apkid_local),
            ("native", "Native library analysis", self._stage_native),
            ("apktool", "APKtool & attack surface", self._stage_apktool),
            ("repackage", "Repackage test", self._stage_repackage),
            ("appshield", "AppShield build", self._stage_appshield),
            ("objection", "Objection patch", self._stage_objection),
        ]

        total = len(stages)
        active = [s for s in stages if s[0] not in self.skip]
        active_total = len(active)

        self.echo("")
        self.echo(f"  Analysing: {self.apk_path.name}")
        self.echo(f"  Output:    {self.output_dir}")
        self.echo(f"  Stages:    {active_total}/{total} ({total - active_total} skipped)")
        self.echo(f"  {'─' * 56}")

        step = 0
        for name, label, fn in stages:
            if name in self.skip:
                self.echo(f"  {'─':>2} {name:<20s} skipped")
                self.stage_results[name] = {"status": "skipped"}
                continue

            step += 1
            bar = self._progress_bar(step, active_total)
            self.echo(f"\n  {bar}  {step}/{active_total}  {label}")

            stage_start = time.time()
            try:
                fn()
                elapsed = time.time() - stage_start
                self.stage_results[name] = {
                    "status": "ok",
                    "duration_seconds": round(elapsed, 1),
                }
                self.echo(f"  {'✓':>2} {name:<20s} {self._fmt_duration(elapsed)}")
            except Exception as e:
                elapsed = time.time() - stage_start
                self.echo(f"  {'✗':>2} {name:<20s} FAILED ({self._fmt_duration(elapsed)})")
                self.echo(f"     {e}")
                self.stage_results[name] = {
                    "status": "error",
                    "error": str(e),
                    "duration_seconds": round(elapsed, 1),
                }

        total_elapsed = time.time() - self.started_at.timestamp()
        self._write_summary()

        self.echo(f"\n  {'─' * 56}")
        ok = sum(1 for s in self.stage_results.values() if s["status"] == "ok")
        failed = sum(1 for s in self.stage_results.values() if s["status"] == "error")
        skipped = sum(1 for s in self.stage_results.values() if s["status"] == "skipped")
        self.echo(f"  Done in {self._fmt_duration(total_elapsed)}  "
                   f"|  {ok} passed  {failed} failed  {skipped} skipped")
        self.echo(f"  {self.output_dir}")

    @staticmethod
    def _progress_bar(current, total, width=20):
        """Render a text progress bar."""
        filled = int(width * current / total)
        bar = "█" * filled + "░" * (width - filled)
        pct = int(100 * current / total)
        return f"[{bar}] {pct:>3}%"

    @staticmethod
    def _fmt_duration(seconds):
        """Format seconds as human-readable duration."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        minutes = int(seconds // 60)
        secs = seconds % 60
        if minutes < 60:
            return f"{minutes}m {secs:.0f}s"
        hours = int(minutes // 60)
        mins = minutes % 60
        return f"{hours}h {mins}m"

    # ── Directory setup ───────────────────────────────────────────────

    def _setup_dirs(self):
        dirs = [
            self.output_dir,
            self.output_dir / "mobsf",
            self.output_dir / "decompiled",
            self.output_dir / "apktool",
            self.output_dir / "native" / "elf",
            self.output_dir / "native" / "binwalk_signature",
            self.output_dir / "native" / "binwalk_entropy",
            self.output_dir / "native" / "strings",
            self.output_dir / "attack_surface",
            self.output_dir / "repackage",
            self.output_dir / "appshield",
            self.output_dir / "objection",
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)

    def _make_preexec(self, mem_limit_mb=None):
        """Return a preexec_fn that sets nice level and memory limit.

        Uses RLIMIT_DATA instead of RLIMIT_AS because JVM-based tools
        (JADX, apktool) map far more virtual address space than they
        actually consume.  RLIMIT_AS kills them prematurely; RLIMIT_DATA
        constrains real heap growth without blocking mmap regions.
        """
        nice = self.NICE_LEVEL
        limit_bytes = (mem_limit_mb or self.max_ram_mb) * 1024 * 1024

        def _preexec():
            # Lower CPU priority so desktop stays responsive
            os.nice(nice)
            # Cap data segment (heap) growth
            resource.setrlimit(resource.RLIMIT_DATA, (limit_bytes, limit_bytes))

        return _preexec

    def _run(self, cmd, cwd=None, check=True, mem_limit_mb=None, timeout=None):
        """Run a shell command with resource limits and return CompletedProcess."""
        try:
            result = subprocess.run(
                cmd, cwd=cwd, capture_output=True, text=True,
                shell=isinstance(cmd, str),
                timeout=timeout,
                preexec_fn=self._make_preexec(mem_limit_mb),
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Command timed out after {timeout}s: {cmd}")
        if check and result.returncode != 0:
            raise RuntimeError(f"Command failed ({result.returncode}): {cmd}\n{result.stderr[:500]}")
        return result

    # ── Stage: MobSF ──────────────────────────────────────────────────

    def _stage_mobsf(self):
        b = self.backend
        mobsf_dir = self.output_dir / "mobsf"

        self.echo("    Uploading to MobSF...")
        upload_result = b.upload(str(self.apk_path))
        self.scan_hash = upload_result.get("hash", "")
        if not self.scan_hash:
            raise RuntimeError(f"Upload failed: {upload_result}")

        scan_info = {
            "hash": self.scan_hash,
            "file_name": upload_result.get("file_name", self.apk_path.name),
            "scan_type": upload_result.get("scan_type", ""),
            "uploaded_at": datetime.now(timezone.utc).isoformat(),
        }
        (mobsf_dir / "scan_info.json").write_text(json.dumps(scan_info, indent=2))

        self.echo("    Running static analysis...")
        b.scan(self.scan_hash)

        self.echo("    Fetching report...")
        report = b.report_json(self.scan_hash)
        (mobsf_dir / "report.json").write_text(json.dumps(report, indent=2, default=str))

        self.echo("    Fetching scorecard...")
        scorecard = b.scorecard(self.scan_hash)
        (mobsf_dir / "scorecard.json").write_text(json.dumps(scorecard, indent=2, default=str))

        apkid_data = report.get("apkid", {})
        if apkid_data:
            (mobsf_dir / "apkid.json").write_text(json.dumps(apkid_data, indent=2, default=str))

        self.echo("    Downloading PDF report...")
        try:
            b.download_pdf(self.scan_hash, str(mobsf_dir / "report.pdf"))
        except Exception as e:
            self.echo(f"    PDF download failed (non-fatal): {e}")

    # ── Stage: JADX ───────────────────────────────────────────────────

    def _stage_jadx(self):
        dec_dir = self.output_dir / "decompiled"
        heap_mb = self.JADX_MAX_RAM_MB
        threads = self.JADX_THREADS
        self.echo(f"    Decompiling with JADX (heap={heap_mb}M, threads={threads})...")
        env = os.environ.copy()
        # JADX reads JAVA_OPTS / _JAVA_OPTIONS for JVM flags
        jvm_flags = f"-Xmx{heap_mb}m -Xms256m"
        env["JAVA_OPTS"] = jvm_flags
        env["_JAVA_OPTIONS"] = jvm_flags
        # JVM virtual memory usage far exceeds -Xmx (mapped libs, thread stacks,
        # code cache, etc.).  Give RLIMIT_AS ~3x the heap to avoid SIGABRT.
        result = subprocess.run(
            [
                "jadx",
                "--threads-count", str(threads),
                "-d", str(dec_dir),
                "-ds", str(dec_dir / "src"),
                "-dr", str(dec_dir / "res"),
                str(self.apk_path),
            ],
            cwd=None, capture_output=True, text=True, env=env,
            preexec_fn=self._make_preexec(mem_limit_mb=heap_mb * 3),
        )
        # JADX returns exit code 1 when it finishes with non-fatal decompilation
        # errors (common on large/obfuscated APKs).  Only treat exit code >= 2 or
        # negative (signal kill) as a hard failure.
        if result.returncode != 0 and result.returncode != 1:
            raise RuntimeError(
                f"JADX failed ({result.returncode}):\n{result.stderr[:500]}"
            )
        if result.returncode == 1:
            self.echo("    JADX finished with non-fatal errors (normal for large APKs)")

    # ── Stage: Local APKiD ────────────────────────────────────────────

    def _stage_apkid_local(self):
        self.echo("    Running local APKiD...")
        result = self._run(["apkid", str(self.apk_path)], check=False)
        out_file = self.output_dir / "mobsf" / f"{self.apk_name}_apkid_local.txt"
        out_file.write_text(result.stdout + result.stderr)

    # ── Stage: Native library analysis ────────────────────────────────

    # ABI preference order for native analysis — only analyse one ABI
    # since the .so files are identical across ABIs (just compiled for
    # different architectures).  ARM ABIs are what matters for mobile.
    _ABI_PREFERENCE = ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"]

    def _stage_native(self):
        # Extract native libs directly from APK — don't depend on JADX/apktool
        import zipfile
        lib_dir = self.output_dir / "native" / "lib"

        # Discover available ABIs without extracting everything
        available_abis = set()
        try:
            with zipfile.ZipFile(str(self.apk_path), 'r') as zf:
                so_entries = [n for n in zf.namelist()
                              if n.startswith("lib/") and n.endswith(".so")]
                for entry in so_entries:
                    # entry format: lib/<abi>/<name>.so
                    parts = entry.split("/")
                    if len(parts) >= 3:
                        available_abis.add(parts[1])
        except Exception as e:
            self.echo(f"    Failed to read APK: {e}")
            return

        if not available_abis:
            self.echo("    No native libraries found, skipping")
            return

        # Pick the best ABI to analyse
        target_abi = None
        for abi in self._ABI_PREFERENCE:
            if abi in available_abis:
                target_abi = abi
                break
        if not target_abi:
            target_abi = sorted(available_abis)[0]

        self.echo(f"    Available ABIs: {sorted(available_abis)}")
        self.echo(f"    Analysing: {target_abi}")

        # Extract only the target ABI
        prefix = f"lib/{target_abi}/"
        try:
            with zipfile.ZipFile(str(self.apk_path), 'r') as zf:
                for entry in so_entries:
                    if entry.startswith(prefix):
                        target = lib_dir / entry[len("lib/"):]
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with zf.open(entry) as src, open(target, 'wb') as dst:
                            shutil.copyfileobj(src, dst)
        except Exception as e:
            self.echo(f"    Failed to extract native libs: {e}")
            return

        native_dir = self.output_dir / "native"
        arch_dir = lib_dir / target_abi
        if not arch_dir.is_dir():
            return
        arch = target_abi

        for subdir in ["elf", "binwalk_signature", "binwalk_entropy", "strings"]:
            (native_dir / subdir / arch).mkdir(parents=True, exist_ok=True)

        so_files = sorted(arch_dir.glob("*.so"))
        self.echo(f"    {len(so_files)} libraries to analyse")

        for so_file in so_files:
            name = so_file.name
            self.echo(f"      {name}")

            # readelf
            result = self._run(["readelf", "-a", str(so_file)], check=False)
            (native_dir / "elf" / arch / f"{name}.readelf").write_text(result.stdout)

            # binwalk signature (60s timeout for very large .so files)
            try:
                self._run([
                    "binwalk", "--signature",
                    f"--log={native_dir / 'binwalk_signature' / arch / f'{name}.binwalk_signature'}",
                    str(so_file),
                ], check=False, timeout=60)
            except RuntimeError:
                self.echo(f"        binwalk signature timed out, skipping")

            # binwalk entropy
            try:
                self._run([
                    "binwalk", "--entropy", "--verbose", "--nplot",
                    "--high", ".7", "--low", ".3",
                    f"--log={native_dir / 'binwalk_entropy' / arch / f'{name}.binwalk_entropy'}",
                    str(so_file),
                ], check=False, timeout=30)
            except RuntimeError:
                self.echo(f"        binwalk entropy timed out, skipping")

            # binwalk entropy plot
            try:
                self._run([
                    "binwalk", "--entropy",
                    "--high", ".7", "--low", ".3",
                    "--save", str(so_file),
                ], cwd=str(native_dir / "binwalk_entropy" / arch), check=False, timeout=30)
            except RuntimeError:
                pass  # plot is non-essential

            # strings
            result = self._run(["strings", str(so_file)], check=False)
            (native_dir / "strings" / arch / f"{name}.strings").write_text(result.stdout)

        # Run native attack surface analysis on the collected data
        self.echo("    Running native attack surface analysis...")
        analyse_native_libs(native_dir, native_dir / "attack_surface")
        self.echo("    Native attack surface reports written")

    # ── Stage: APKtool + code analysis ────────────────────────────────

    def _stage_apktool(self):
        apktool_dir = self.output_dir / "apktool"
        apk_copy = apktool_dir / self.apk_path.name
        shutil.copy2(self.apk_path, apk_copy)

        self.echo("    Disassembling with apktool...")
        self._run(["apktool", "d", "-f", str(apk_copy)], cwd=str(apktool_dir))

        smali_dir = apktool_dir / self.apk_name
        if not smali_dir.is_dir():
            self.echo("    apktool output directory not found")
            return

        # classcountm.sh
        self.echo("    Counting classes...")
        result = self._run(
            [str(script_path("classcountm.sh"))],
            cwd=str(smali_dir), check=False,
        )
        (apktool_dir / "classcount.txt").write_text(result.stdout)

        # libcount.sh
        self.echo("    Counting libraries...")
        result = self._run(
            [str(script_path("libcount.sh"))],
            cwd=str(smali_dir), check=False,
        )
        (apktool_dir / "libcount.txt").write_text(result.stdout)

        # searchstrings.sh
        searchstrings_dic = dictionary_path()
        if searchstrings_dic.is_file():
            self.echo("    Running API grep...")
            result = self._run(
                [str(script_path("searchstrings.sh")), str(searchstrings_dic)],
                cwd=str(smali_dir), check=False,
            )
            (apktool_dir / "searchstrings.txt").write_text(result.stdout)

            result = self._run(
                [str(script_path("searchstringswithfilenames.sh")), str(searchstrings_dic)],
                cwd=str(smali_dir), check=False,
            )
            (apktool_dir / "searchstringswithfilenames.txt").write_text(result.stdout)

        # Attack surface analysis
        self.echo("    Running attack surface analysis...")
        attack_surface_dir = self.output_dir / "attack_surface"
        scan_attack_surface(smali_dir, attack_surface_dir)
        self.echo("    Attack surface reports written")

    # ── Stage: Repackage test ─────────────────────────────────────────

    def _stage_repackage(self):
        repackage_dir = self.output_dir / "repackage"
        apk_copy = repackage_dir / self.apk_path.name
        shutil.copy2(self.apk_path, apk_copy)

        self.echo("    Re-signing APK...")
        result = self._run(
            [
                str(script_path("sign-apk.sh")),
                self.sdk_version,
                str(ATTACK_KEYSTORE),
                "attack", "attack", "attack",
                self.apk_name, "apk",
            ],
            cwd=str(repackage_dir), check=False,
        )

        result_text = result.stdout + result.stderr
        (repackage_dir / "result.txt").write_text(result_text)

        # Clean up intermediates
        for f in repackage_dir.glob("*aligned.apk"):
            f.unlink()
        for f in repackage_dir.glob("*.idsig"):
            f.unlink()

    # ── Stage: AppShield / APK Defender ───────────────────────────────

    @staticmethod
    def _extract_signing_cert(apk_path, output_dir):
        """Extract the signing certificate from an APK for AppShield config.

        Extracts META-INF/*.RSA|DSA|EC from the APK and converts to PEM
        via openssl.  Returns the path to the extracted .pem file, or None.
        """
        import zipfile

        cert_pem = output_dir / "signing-certificate.pem"
        if cert_pem.is_file():
            return cert_pem

        try:
            with zipfile.ZipFile(str(apk_path), 'r') as zf:
                for name in zf.namelist():
                    if name.startswith("META-INF/") and name.split(".")[-1] in ("RSA", "DSA", "EC"):
                        cert_data = zf.read(name)
                        cert_der = output_dir / "signing-certificate.der"
                        cert_der.write_bytes(cert_data)
                        # Convert PKCS#7 to PEM via openssl
                        conv = subprocess.run(
                            ["openssl", "pkcs7", "-inform", "DER", "-print_certs",
                             "-in", str(cert_der), "-out", str(cert_pem)],
                            capture_output=True, text=True,
                        )
                        if conv.returncode == 0 and cert_pem.is_file() and cert_pem.stat().st_size > 0:
                            cert_der.unlink(missing_ok=True)
                            return cert_pem
                        cert_der.unlink(missing_ok=True)
        except Exception:
            pass

        return None

    def _stage_appshield(self):
        appshield_dir = self.output_dir / "appshield"
        # Clean stale configs from prior runs so new-config generates fresh
        for stale in appshield_dir.glob("*-example-configuration.json"):
            stale.unlink()
        (appshield_dir / "config.json").unlink(missing_ok=True)
        apk_copy = appshield_dir / self.apk_path.name
        shutil.copy2(self.apk_path, apk_copy)

        # Copy signing materials: prefer files alongside the APK, fall back
        # to bundled defaults (generic keystore for analysis builds).
        for fname in ["certificate.x509.pem", "keystore.jks", "keystoreinfo.json"]:
            src = self.apk_path.parent / fname
            if not src.is_file():
                src = script_path(fname)
            if src.is_file():
                shutil.copy2(src, appshield_dir / fname)

        self.echo("    Generating APK Defender config...")
        # apkdefender new-config writes to CWD, not -w dir — run from appshield_dir
        self._run(
            ["apkdefender", "-b", "new-config", str(apk_copy)],
            cwd=str(appshield_dir), check=False,
        )

        config_file = appshield_dir / f"{self.apk_name}-example-configuration.json"
        if config_file.is_file():
            self.echo("    Patching config...")
            raw = config_file.read_text()

            # Strip header: find the marker line and take everything after it
            marker = "REMOVE THIS LINE AND THE ONES ABOVE IT"
            lines = raw.splitlines()
            json_start = 0
            for i, line in enumerate(lines):
                if marker in line:
                    json_start = i + 1
                    break
            else:
                # No marker found — try to find first '{' line
                for i, line in enumerate(lines):
                    if line.strip().startswith("{"):
                        json_start = i
                        break

            text = "\n".join(lines[json_start:])

            # Patch signing certificate: prefer bundled/copied cert, then extract from APK
            cert_path = None
            for candidate in [
                appshield_dir / "certificate.x509.pem",
                appshield_dir / "signing-certificate.pem",
            ]:
                if candidate.is_file():
                    cert_path = str(candidate)
                    break

            if not cert_path:
                self.echo("    Extracting signing certificate from APK...")
                extracted = self._extract_signing_cert(self.apk_path, appshield_dir)
                if extracted:
                    cert_path = str(extracted)
                    self.echo(f"    Extracted: {extracted.name}")

            if cert_path:
                text = text.replace("path/to/signing-certificate.crt", cert_path)
            else:
                self.echo("    Warning: no signing certificate found — AppShield build will fail")

            # Inject keystore configuration file reference if available
            ksinfo_file = appshield_dir / "keystoreinfo.json"
            if ksinfo_file.is_file():
                try:
                    config_obj = json.loads(text)
                    gen = config_obj.get("general_configuration", {})
                    gen["keystore_configuration_file"] = str(ksinfo_file)
                    text = json.dumps(config_obj, indent=4)
                    self.echo("    Injected keystore configuration")
                except Exception as e:
                    self.echo(f"    Warning: failed to inject keystore config: {e}")

            config_file.write_text(text)
            (appshield_dir / "config.json").write_text(text)

            self.echo("    Building protected APK...")
            result = self._run(
                [
                    "apkdefender",
                    "-c", str(config_file),
                    "-w", str(appshield_dir),
                    str(apk_copy),
                ],
                cwd=str(appshield_dir), check=False,
            )
            # Check for actual build failure via log
            log_file = appshield_dir / "apkdefender.log"
            if log_file.is_file():
                log_text = log_file.read_text()
                if "ERROR" in log_text:
                    errors = [l for l in log_text.splitlines() if "ERROR" in l]
                    raise RuntimeError(
                        f"AppShield build failed:\n" + "\n".join(errors[:5])
                    )
        else:
            raise RuntimeError("apkdefender new-config did not produce a config file")

    # ── Stage: Objection patch ────────────────────────────────────────

    def _stage_objection(self):
        patcher = ObjectionPatcher(
            analysis_dir=self.output_dir,
            apk_path=self.apk_path,
            echo=self.echo,
        )
        patcher.plan()
        patcher.patch(output_dir=self.output_dir / "objection")

    # ── Summary ───────────────────────────────────────────────────────

    def _write_summary(self):
        finished_at = datetime.now(timezone.utc)
        summary = {
            "app_name": self.apk_name,
            "apk_path": str(self.apk_path),
            "output_dir": str(self.output_dir),
            "scan_hash": self.scan_hash,
            "sdk_version": self.sdk_version,
            "abis": self.abis,
            "started_at": self.started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "duration_seconds": (finished_at - self.started_at).total_seconds(),
            "stages": self.stage_results,
            "skipped": list(self.skip),
        }

        # Pull key findings from MobSF if available
        scorecard_file = self.output_dir / "mobsf" / "scorecard.json"
        if scorecard_file.is_file():
            try:
                sc = json.loads(scorecard_file.read_text())
                summary["findings_count"] = {
                    "high": len(sc.get("high", [])),
                    "warning": len(sc.get("warning", [])),
                    "info": len(sc.get("info", [])),
                    "secure": len(sc.get("secure", [])),
                    "hotspot": len(sc.get("hotspot", [])),
                }
            except Exception:
                pass

        report_file = self.output_dir / "mobsf" / "report.json"
        if report_file.is_file():
            try:
                rpt = json.loads(report_file.read_text())
                summary["app_metadata"] = {
                    "package_name": rpt.get("package_name", ""),
                    "version_name": rpt.get("version_name", ""),
                    "version_code": rpt.get("version_code", ""),
                    "target_sdk": rpt.get("target_sdk", ""),
                    "min_sdk": rpt.get("min_sdk", ""),
                    "size": rpt.get("size", ""),
                }
            except Exception:
                pass

        (self.output_dir / "summary.json").write_text(json.dumps(summary, indent=2))

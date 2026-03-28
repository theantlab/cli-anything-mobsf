"""MobSF REST API backend wrapper."""
import json
import os
import sys
from pathlib import Path
from urllib.parse import urljoin

import requests


class MobSFBackend:
    """Thin wrapper around the MobSF REST API."""

    def __init__(self, url=None, api_key=None):
        self.url = (url or os.environ.get("MOBSF_URL", "http://127.0.0.1:8030")).rstrip("/")
        self.api_key = api_key or os.environ.get("MOBSF_API_KEY", "")
        if not self.api_key:
            self.api_key = self._read_local_key()
        self.session = requests.Session()
        self.session.headers.update({"X-Mobsf-Api-Key": self.api_key})

    # ------------------------------------------------------------------
    # Auth helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _read_local_key():
        """Try to derive the API key from the local secret file."""
        import hashlib

        for candidate in [
            Path.home() / ".MobSF" / "secret",
            Path.home() / ".mobsf" / "secret",
        ]:
            if candidate.is_file():
                data = candidate.read_text().strip()
                return hashlib.sha256(data.encode()).hexdigest()
        return ""

    def _post(self, endpoint, data=None, files=None):
        resp = self.session.post(urljoin(self.url + "/", endpoint), data=data, files=files)
        resp.raise_for_status()
        return resp

    def _get(self, endpoint, params=None):
        resp = self.session.get(urljoin(self.url + "/", endpoint), params=params)
        resp.raise_for_status()
        return resp

    # ------------------------------------------------------------------
    # Static analysis
    # ------------------------------------------------------------------

    def upload(self, file_path):
        """Upload a mobile app file. Returns JSON with hash."""
        p = Path(file_path)
        if not p.is_file():
            raise FileNotFoundError(file_path)
        with open(p, "rb") as f:
            resp = self._post("api/v1/upload", files={"file": (p.name, f, "application/octet-stream")})
        return resp.json()

    def scan(self, scan_hash, scan_type=None, file_name=None, re_scan=False):
        """Trigger static analysis scan."""
        data = {"hash": scan_hash}
        if scan_type:
            data["scan_type"] = scan_type
        if file_name:
            data["file_name"] = file_name
        if re_scan:
            data["re_scan"] = "1"
        return self._post("api/v1/scan", data=data).json()

    def scans(self, page=1, page_size=50):
        """List recent scans."""
        return self._get("api/v1/scans", params={"page": page, "page_size": page_size}).json()

    def search(self, query):
        """Search scans by hash or text."""
        return self._post("api/v1/search", data={"query": query}).json()

    def delete_scan(self, scan_hash):
        """Delete a scan by hash."""
        return self._post("api/v1/delete_scan", data={"hash": scan_hash}).json()

    def scan_logs(self, scan_hash):
        """Get scan logs."""
        return self._post("api/v1/scan_logs", data={"hash": scan_hash}).json()

    def tasks(self):
        """Get scan queue / task list."""
        return self._post("api/v1/tasks").json()

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------

    def report_json(self, scan_hash):
        """Get JSON report for a scan."""
        return self._post("api/v1/report_json", data={"hash": scan_hash}).json()

    def scorecard(self, scan_hash):
        """Get security scorecard."""
        return self._post("api/v1/scorecard", data={"hash": scan_hash}).json()

    def download_pdf(self, scan_hash, output_path=None):
        """Download PDF report. Returns path to saved file."""
        resp = self._post("api/v1/download_pdf", data={"hash": scan_hash})
        out = Path(output_path) if output_path else Path(f"{scan_hash}_report.pdf")
        out.write_bytes(resp.content)
        return str(out)

    # ------------------------------------------------------------------
    # Source & compare
    # ------------------------------------------------------------------

    def view_source(self, scan_hash, file_path, file_type):
        """View a source file from the scan."""
        return self._post("api/v1/view_source", data={
            "hash": scan_hash, "file": file_path, "type": file_type,
        }).json()

    def compare(self, hash1, hash2):
        """Compare two scans."""
        return self._post("api/v1/compare", data={"hash1": hash1, "hash2": hash2}).json()

    # ------------------------------------------------------------------
    # Suppressions
    # ------------------------------------------------------------------

    def list_suppressions(self, scan_hash):
        """List active suppressions for a scan."""
        return self._post("api/v1/list_suppressions", data={"hash": scan_hash}).json()

    def suppress_by_rule(self, scan_hash, rule_id, suppress_type="suppress"):
        """Suppress findings by rule ID."""
        return self._post("api/v1/suppress_by_rule", data={
            "hash": scan_hash, "rule": rule_id, "type": suppress_type,
        }).json()

    def suppress_by_files(self, scan_hash, rule_id, files):
        """Suppress findings by files."""
        return self._post("api/v1/suppress_by_files", data={
            "hash": scan_hash, "rule": rule_id, "files": files,
        }).json()

    def delete_suppression(self, scan_hash, rule_id, suppress_type):
        """Delete a suppression rule."""
        return self._post("api/v1/delete_suppression", data={
            "hash": scan_hash, "rule": rule_id, "type": suppress_type,
        }).json()

    # ------------------------------------------------------------------
    # Android dynamic analysis
    # ------------------------------------------------------------------

    def dynamic_get_apps(self):
        """List apps available for dynamic analysis."""
        return self._get("api/v1/dynamic/get_apps").json()

    def dynamic_start(self, scan_hash):
        """Start dynamic analysis."""
        return self._post("api/v1/dynamic/start_analysis", data={"hash": scan_hash}).json()

    def dynamic_stop(self, scan_hash):
        """Stop dynamic analysis and collect logs."""
        return self._post("api/v1/dynamic/stop_analysis", data={"hash": scan_hash}).json()

    def dynamic_report(self, scan_hash):
        """Get dynamic analysis report JSON."""
        return self._post("api/v1/dynamic/report_json", data={"hash": scan_hash}).json()

    # ------------------------------------------------------------------
    # Android device operations
    # ------------------------------------------------------------------

    def logcat(self, package):
        """Stream logcat output."""
        return self._post("api/v1/android/logcat", data={"package": package}).json()

    def mobsfy(self, scan_hash):
        """Instrument an app for dynamic analysis."""
        return self._post("api/v1/android/mobsfy", data={"hash": scan_hash}).json()

    def screenshot(self, scan_hash):
        """Capture device screenshot."""
        return self._post("api/v1/android/screenshot", data={"hash": scan_hash}).json()

    def activity_test(self, scan_hash, test="exported"):
        """Run activity tester."""
        return self._post("api/v1/android/activity", data={"hash": scan_hash, "test": test}).json()

    def tls_tests(self, scan_hash):
        """Run TLS/SSL security tests."""
        return self._post("api/v1/android/tls_tests", data={"hash": scan_hash}).json()

    # ------------------------------------------------------------------
    # Frida
    # ------------------------------------------------------------------

    def frida_instrument(self, scan_hash, default_hooks="", auxiliary_hooks="", frida_code=""):
        """Run Frida instrumentation."""
        return self._post("api/v1/frida/instrument", data={
            "hash": scan_hash,
            "default_hooks": default_hooks,
            "auxiliary_hooks": auxiliary_hooks,
            "frida_code": frida_code,
        }).json()

    def frida_logs(self, scan_hash):
        """Get Frida logs."""
        return self._post("api/v1/frida/logs", data={"hash": scan_hash}).json()

    def frida_api_monitor(self, scan_hash):
        """Live API monitoring via Frida."""
        return self._post("api/v1/frida/api_monitor", data={"hash": scan_hash}).json()

    def frida_list_scripts(self, device="android"):
        """List available Frida scripts."""
        return self._post("api/v1/frida/list_scripts", data={"device": device}).json()

    def frida_get_dependencies(self, scan_hash):
        """Get runtime dependencies."""
        return self._post("api/v1/frida/get_dependencies", data={"hash": scan_hash}).json()

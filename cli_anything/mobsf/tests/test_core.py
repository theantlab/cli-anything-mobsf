"""Unit tests for core session and backend modules."""
import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from cli_anything.mobsf.core.session import Session
from cli_anything.mobsf.mobsf_cli import cli


class TestSession:

    def test_set_scan(self):
        s = Session()
        s.set_scan("abc123", "app.apk", "apk")
        assert s.current_hash == "abc123"
        assert s.current_file == "app.apk"
        assert len(s.history) == 1

    def test_undo_redo(self):
        s = Session()
        s.set_scan("hash1")
        s.set_scan("hash2")
        assert s.current_hash == "hash2"
        assert s.undo()
        assert s.current_hash == "hash1"
        assert s.redo()
        assert s.current_hash == "hash2"

    def test_undo_empty(self):
        s = Session()
        assert not s.undo()

    def test_redo_empty(self):
        s = Session()
        assert not s.redo()

    def test_clear(self):
        s = Session()
        s.set_scan("hash1")
        s.clear()
        assert s.current_hash == ""
        assert s.undo()
        assert s.current_hash == "hash1"

    def test_to_dict(self):
        s = Session()
        s.set_scan("h", "f.apk", "apk")
        d = s.to_dict()
        assert d["current_hash"] == "h"
        assert d["history_length"] == 1


class TestCLIHelp:

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "MobSF CLI" in result.output

    def test_subcommand_help(self):
        runner = CliRunner()
        for cmd in ["upload", "scan", "scans", "report", "pdf", "compare"]:
            result = runner.invoke(cli, [cmd, "--help"])
            assert result.exit_code == 0, f"{cmd} --help failed"


class TestCLIScans:

    @patch("cli_anything.mobsf.mobsf_cli.MobSFBackend")
    def test_scans_json(self, MockBackend):
        mock = MockBackend.return_value
        mock.scans.return_value = {"content": [{"MD5": "abc", "FILE_NAME": "test.apk"}]}
        runner = CliRunner()
        result = runner.invoke(cli, ["--json", "scans"])
        assert result.exit_code == 0

    @patch("cli_anything.mobsf.mobsf_cli.MobSFBackend")
    def test_tasks(self, MockBackend):
        mock = MockBackend.return_value
        mock.tasks.return_value = {"tasks": []}
        runner = CliRunner()
        result = runner.invoke(cli, ["tasks"])
        assert result.exit_code == 0

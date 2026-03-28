"""Session state management for MobSF CLI."""
import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Session:
    """Tracks CLI session state with undo support."""

    current_hash: str = ""
    current_file: str = ""
    scan_type: str = ""
    history: list = field(default_factory=list)
    _undo_stack: list = field(default_factory=list)
    _redo_stack: list = field(default_factory=list)

    def set_scan(self, scan_hash, file_name="", scan_type=""):
        self._push_undo()
        self.current_hash = scan_hash
        self.current_file = file_name
        self.scan_type = scan_type
        self.history.append({"action": "set_scan", "hash": scan_hash, "file": file_name})

    def clear(self):
        self._push_undo()
        self.current_hash = ""
        self.current_file = ""
        self.scan_type = ""

    def _push_undo(self):
        self._undo_stack.append(self._snapshot())
        self._redo_stack.clear()

    def _snapshot(self):
        return {
            "current_hash": self.current_hash,
            "current_file": self.current_file,
            "scan_type": self.scan_type,
        }

    def _restore(self, snap):
        self.current_hash = snap["current_hash"]
        self.current_file = snap["current_file"]
        self.scan_type = snap["scan_type"]

    def undo(self):
        if not self._undo_stack:
            return False
        self._redo_stack.append(self._snapshot())
        self._restore(self._undo_stack.pop())
        return True

    def redo(self):
        if not self._redo_stack:
            return False
        self._undo_stack.append(self._snapshot())
        self._restore(self._redo_stack.pop())
        return True

    def to_dict(self):
        return {
            "current_hash": self.current_hash,
            "current_file": self.current_file,
            "scan_type": self.scan_type,
            "history_length": len(self.history),
        }

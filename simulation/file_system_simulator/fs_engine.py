"""
File System Engine - Simulates file operations and data classification.
"""
from __future__ import annotations
import random
from dataclasses import dataclass
from typing import Any


@dataclass
class FileEvent:
    tick: int
    timestamp: float
    user_id: str
    source_host: str
    operation: str  # "read", "write", "delete", "rename", "copy", "download", "upload"
    file_path: str
    file_name: str
    file_size: int
    file_type: str
    sensitivity: str  # "public", "internal", "confidential", "restricted"
    success: bool = True
    details: dict[str, Any] | None = None


FILE_TREES = {
    "IT": {"base": "/shared/it/", "folders": ["configs", "scripts", "docs", "logs", "backups"]},
    "Engineering": {"base": "/shared/eng/", "folders": ["src", "docs", "data", "releases", "tests"]},
    "Finance": {"base": "/shared/finance/", "folders": ["reports", "budgets", "invoices", "audits", "tax"]},
    "HR": {"base": "/shared/hr/", "folders": ["personnel", "policies", "benefits", "recruitment", "training"]},
    "Executive": {"base": "/shared/exec/", "folders": ["strategy", "board", "investor", "legal", "m_and_a"]},
    "Operations": {"base": "/shared/ops/", "folders": ["procedures", "inventory", "shipping", "vendors", "quality"]},
}

SENSITIVITY_MAP = {
    "personnel": "restricted", "budgets": "confidential", "strategy": "restricted",
    "board": "restricted", "investor": "restricted", "tax": "confidential",
    "configs": "confidential", "legal": "restricted", "m_and_a": "restricted",
    "audits": "confidential", "benefits": "confidential",
}

FILE_EXTENSIONS = {
    "document": [".docx", ".pdf", ".txt", ".md"],
    "spreadsheet": [".xlsx", ".csv"],
    "presentation": [".pptx"],
    "code": [".py", ".js", ".yaml", ".json", ".sh"],
    "data": [".csv", ".parquet", ".db"],
    "archive": [".zip", ".tar.gz"],
}


class FileSystemEngine:
    """Simulates file system operations with data sensitivity classification."""

    def __init__(self, seed: int = 42):
        self.seed = seed
        self._rng = random.Random(seed)

    def generate_file_event(self, tick: int, timestamp: float, user_id: str,
                             source_host: str, department: str,
                             operation: str | None = None) -> FileEvent:
        tree = FILE_TREES.get(department, FILE_TREES["IT"])
        folder = self._rng.choice(tree["folders"])
        file_type_key = self._rng.choice(list(FILE_EXTENSIONS.keys()))
        ext = self._rng.choice(FILE_EXTENSIONS[file_type_key])
        file_name = f"{folder}_doc_{self._rng.randint(1, 200)}{ext}"
        file_path = f"{tree['base']}{folder}/{file_name}"
        sensitivity = SENSITIVITY_MAP.get(folder, "internal")

        if operation is None:
            operation = self._rng.choices(
                ["read", "write", "download", "copy", "delete", "rename"],
                weights=[0.45, 0.25, 0.12, 0.08, 0.05, 0.05], k=1
            )[0]

        return FileEvent(
            tick=tick, timestamp=timestamp, user_id=user_id, source_host=source_host,
            operation=operation, file_path=file_path, file_name=file_name,
            file_size=self._rng.randint(1024, 10485760), file_type=file_type_key,
            sensitivity=sensitivity,
            details={"department_match": department, "access_method": "smb"},
        )

    def generate_bulk_access(self, tick: int, timestamp: float, user_id: str,
                              source_host: str, department: str, count: int = 10) -> list[FileEvent]:
        """Generate a burst of file access events (potential exfiltration indicator)."""
        return [
            self.generate_file_event(tick, timestamp + i * 0.1, user_id, source_host, department, "download")
            for i in range(count)
        ]

"""File permission control — restrict access to sensitive workspace files."""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path

from loguru import logger

_IS_WINDOWS = os.name == "nt"


class FilePermissionManager:
    """Set restrictive OS permissions on sensitive files inside the workspace.

    On Unix/Linux/macOS:
      - Files → ``0o600`` (owner read/write only)
      - Directories → ``0o700`` (owner read/write/execute only)

    On Windows:
      - Unix-style permissions are not available; the manager logs a debug
        message and skips the operation without raising an error.
    """

    PROTECTED_PATTERNS: list[str] = [
        "*.json",
        "*.key",
        "*.pem",
        "*.env",
        "*.txt",
        "*.log",
        "*.jsonl",
    ]

    PROTECTED_DIRECTORIES: list[str] = [
        ".nanobot",
        "secret",
        "sessions",
        "workspace",
        "memory",
    ]

    def set_secure_permissions(self, file_path: Path) -> bool:
        """Apply secure permissions to *file_path*.

        Returns ``True`` on success (or when skipped on Windows),
        ``False`` on failure.
        """
        if _IS_WINDOWS:
            logger.debug("Windows: skipping file permission control for {}", file_path)
            return True

        try:
            if file_path.is_file():
                file_path.chmod(0o600)
            elif file_path.is_dir():
                file_path.chmod(0o700)
            return True
        except OSError as exc:
            logger.warning("Failed to set permissions on {}: {}", file_path, exc)
            return False

    def _matches_protected_pattern(self, path: Path) -> bool:
        """Return True if *path*'s name matches any of :attr:`PROTECTED_PATTERNS`."""
        name = path.name
        return any(fnmatch.fnmatch(name, pat) for pat in self.PROTECTED_PATTERNS)

    def _in_protected_directory(self, path: Path) -> bool:
        """Return True if any ancestor of *path* is a protected directory name."""
        return any(part in self.PROTECTED_DIRECTORIES for part in path.parts)

    def scan_directory(self, workspace_path: Path) -> list[Path]:
        """Recursively collect sensitive files and directories under *workspace_path*.

        A path is considered sensitive if it matches :attr:`PROTECTED_PATTERNS`
        **or** if it is a directory whose name is in :attr:`PROTECTED_DIRECTORIES`.
        """
        sensitive: list[Path] = []
        try:
            for item in workspace_path.rglob("*"):
                try:
                    if item.is_dir() and item.name in self.PROTECTED_DIRECTORIES:
                        sensitive.append(item)
                    elif item.is_file() and self._matches_protected_pattern(item):
                        sensitive.append(item)
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError) as exc:
            logger.warning("Cannot scan workspace {}: {}", workspace_path, exc)
        return sensitive

    def protect_workspace(self, workspace_path: Path) -> int:
        """Apply secure permissions to all sensitive items in *workspace_path*.

        Returns the number of items successfully protected.
        """
        logger.info("Scanning workspace for sensitive files: {}", workspace_path)
        items = self.scan_directory(workspace_path)
        protected = 0
        for item in items:
            if self.set_secure_permissions(item):
                protected += 1
        logger.info("Protected {} sensitive items in workspace", protected)
        return protected

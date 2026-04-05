"""
Shared utilities for QA checks.
"""

import os
import fnmatch
from pathlib import Path
from typing import List, Dict, Any, Optional


def finding(
    severity: str,
    check: str,
    file: str,
    message: str,
    line: Optional[int] = None,
    snippet: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a standardized finding dict."""
    return {
        "severity": severity,
        "check": check,
        "file": file,
        "line": line,
        "message": message,
        "snippet": snippet,
    }


def resolve_path(path: str) -> str:
    """Expand ~ and resolve to absolute path."""
    return str(Path(path).expanduser().resolve())


def should_ignore(filepath: str, ignore_patterns: List[str]) -> bool:
    """Check if a filepath matches any ignore pattern."""
    parts = Path(filepath).parts
    for pattern in ignore_patterns:
        # Match against any path component
        for part in parts:
            if fnmatch.fnmatch(part, pattern):
                return True
        # Also match full path
        if fnmatch.fnmatch(filepath, pattern):
            return True
    return False


def walk_project_files(
    project_path: str,
    ignore_patterns: List[str],
    extensions: Optional[List[str]] = None,
) -> List[str]:
    """Walk project directory, returning files that match filters."""
    project_path = resolve_path(project_path)
    results = []

    if not os.path.isdir(project_path):
        return results

    for root, dirs, files in os.walk(project_path):
        # Prune ignored directories in-place for performance
        rel_root = os.path.relpath(root, project_path)
        dirs[:] = [
            d for d in dirs
            if not should_ignore(os.path.join(rel_root, d), ignore_patterns)
        ]

        for f in files:
            rel_path = os.path.join(rel_root, f)
            if rel_path.startswith("./"):
                rel_path = rel_path[2:]

            if should_ignore(rel_path, ignore_patterns):
                continue

            if extensions:
                if not any(f.endswith(ext) for ext in extensions):
                    continue

            full_path = os.path.join(root, f)
            results.append(full_path)

    return results


def read_file_safe(path: str, max_size: int = 500_000) -> Optional[str]:
    """Read a file, returning None if too large or binary."""
    try:
        size = os.path.getsize(path)
        if size > max_size:
            return None
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except (OSError, UnicodeDecodeError):
        return None


def get_language_extensions(languages: List[str]) -> List[str]:
    """Map language names to file extensions."""
    mapping = {
        "python": [".py"],
        "javascript": [".js", ".mjs", ".cjs"],
        "typescript": [".ts", ".tsx"],
    }
    exts = []
    for lang in languages:
        exts.extend(mapping.get(lang, []))
    return exts

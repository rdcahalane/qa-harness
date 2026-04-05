"""
Dead code detection: unused imports, unreachable functions, stale files.

Python: AST-based import and function usage analysis.
JS/TS: Regex-based export/import tracking.
"""

import ast
import os
import re
from collections import defaultdict
from typing import List, Dict, Any, Set, Tuple

from .base import (
    finding, walk_project_files, read_file_safe,
    get_language_extensions, resolve_path,
)


# ---------------------------------------------------------------------------
# Python: unused imports
# ---------------------------------------------------------------------------

def _check_python_unused_imports(filepath: str, content: str) -> List[Tuple[int, str]]:
    """Find unused imports in a Python file. Returns [(line, import_name)]."""
    try:
        tree = ast.parse(content, filename=filepath)
    except SyntaxError:
        return []

    # Collect all imports
    imports: Dict[str, int] = {}  # name -> line
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname if alias.asname else alias.name
                imports[name] = node.lineno
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    continue
                name = alias.asname if alias.asname else alias.name
                imports[name] = node.lineno

    if not imports:
        return []

    # Collect all Name references in the file (excluding import nodes themselves)
    used_names: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used_names.add(node.id)
        elif isinstance(node, ast.Attribute):
            # For things like `os.path` -- `os` is used
            if isinstance(node.value, ast.Name):
                used_names.add(node.value.id)

    # Also check string references (for __all__, decorators, etc.)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            used_names.add(node.value)

    unused = []
    for name, line in imports.items():
        # Skip underscore imports (used for side effects)
        if name.startswith("_"):
            continue
        # Skip common side-effect imports
        if name in ("annotations", "absolute_import"):
            continue
        if name not in used_names:
            unused.append((line, name))

    return unused


# ---------------------------------------------------------------------------
# Python: unreachable / potentially dead functions
# ---------------------------------------------------------------------------

def _check_python_dead_functions(
    filepath: str,
    content: str,
) -> List[Tuple[str, int]]:
    """
    Find module-level functions that are never called within the same file.
    Returns [(func_name, line)].
    Note: cross-file usage is checked at finalize time.
    """
    try:
        tree = ast.parse(content, filename=filepath)
    except SyntaxError:
        return []

    # Collect top-level function definitions
    defined: Dict[str, int] = {}
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Skip dunder methods and test functions
            if node.name.startswith("__") or node.name.startswith("test_"):
                continue
            # Skip if decorated (likely registered somewhere)
            if node.decorator_list:
                continue
            defined[node.name] = node.lineno

    if not defined:
        return []

    # Check if function names appear in the rest of the file text
    # (crude but fast -- AST walk for Call nodes would be more precise
    #  but misses string refs, getattr, etc.)
    dead = []
    for fname, line in defined.items():
        # Count occurrences of the name in source (excluding the def line itself)
        count = 0
        for i, src_line in enumerate(content.split("\n"), 1):
            if i == line:
                continue
            if re.search(rf"\b{re.escape(fname)}\b", src_line):
                count += 1
        if count == 0:
            dead.append((fname, line))

    return dead


# ---------------------------------------------------------------------------
# JS/TS: unused exports (cross-file)
# ---------------------------------------------------------------------------

_JS_EXPORT_RE = re.compile(
    r"export\s+(?:default\s+)?(?:function|class|const|let|var|async\s+function)\s+(\w+)"
)
_JS_IMPORT_RE = re.compile(
    r"import\s+(?:\{([^}]+)\}|(\w+))\s+from"
)


def _collect_js_exports(filepath: str, content: str) -> List[Tuple[str, int]]:
    """Collect exported names from a JS/TS file."""
    exports = []
    for match in _JS_EXPORT_RE.finditer(content):
        name = match.group(1)
        line = content[:match.start()].count("\n") + 1
        exports.append((name, line))
    return exports


def _collect_js_imports(content: str) -> Set[str]:
    """Collect all imported names from a JS/TS file."""
    names = set()
    for match in _JS_IMPORT_RE.finditer(content):
        if match.group(1):
            # Named imports: { A, B as C }
            for part in match.group(1).split(","):
                part = part.strip()
                if " as " in part:
                    part = part.split(" as ")[1].strip()
                if part:
                    names.add(part)
        if match.group(2):
            names.add(match.group(2))
    return names


# ---------------------------------------------------------------------------
# Stale files: files not modified in 180+ days and not imported anywhere
# ---------------------------------------------------------------------------

def _find_stale_files(
    project_path: str,
    ignore: List[str],
    extensions: List[str],
    max_age_days: int = 180,
) -> List[Tuple[str, float]]:
    """Find files older than max_age_days."""
    import time
    cutoff = time.time() - (max_age_days * 86400)
    stale = []

    files = walk_project_files(project_path, ignore, extensions)
    for fpath in files:
        try:
            mtime = os.path.getmtime(fpath)
            if mtime < cutoff:
                rel = os.path.relpath(fpath, project_path)
                age_days = (time.time() - mtime) / 86400
                stale.append((rel, age_days))
        except OSError:
            continue

    return stale


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run(project_config: Dict[str, Any], global_config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Run dead code detection on a project."""
    findings_list = []
    project_path = resolve_path(project_config["path"])
    project_name = project_config["name"]
    ignore = project_config.get("ignore_patterns", [])
    languages = project_config.get("languages", [])

    # --- Python checks ---
    if "python" in languages:
        py_files = walk_project_files(project_path, ignore, [".py"])

        # Collect all exported function names across project for cross-ref
        all_py_names: Set[str] = set()
        for fpath in py_files:
            content = read_file_safe(fpath)
            if not content:
                continue
            # Crude: all words that look like function calls
            all_py_names.update(re.findall(r"\b(\w+)\s*\(", content))

        for fpath in py_files:
            content = read_file_safe(fpath)
            if not content:
                continue
            rel = os.path.relpath(fpath, project_path)
            display = f"{project_name}/{rel}"

            # Unused imports
            for line, name in _check_python_unused_imports(fpath, content):
                findings_list.append(finding(
                    severity="info",
                    check="dead_code",
                    file=display,
                    line=line,
                    message=f"Unused import: {name}",
                ))

            # Dead functions (only report if not called anywhere in project)
            for fname, line in _check_python_dead_functions(fpath, content):
                if fname not in all_py_names:
                    findings_list.append(finding(
                        severity="info",
                        check="dead_code",
                        file=display,
                        line=line,
                        message=f"Potentially unused function: {fname}() "
                                f"-- not called anywhere in {project_name}",
                    ))

    # --- JS/TS checks ---
    js_exts = []
    if "javascript" in languages:
        js_exts.extend([".js", ".mjs", ".cjs"])
    if "typescript" in languages:
        js_exts.extend([".ts", ".tsx"])

    if js_exts:
        js_files = walk_project_files(project_path, ignore, js_exts)

        # Collect all imports across the project
        all_imported: Set[str] = set()
        all_exports: List[Tuple[str, str, str, int]] = []  # (name, file, display, line)

        for fpath in js_files:
            content = read_file_safe(fpath)
            if not content:
                continue
            rel = os.path.relpath(fpath, project_path)
            display = f"{project_name}/{rel}"

            all_imported.update(_collect_js_imports(content))

            for name, line in _collect_js_exports(fpath, content):
                all_exports.append((name, fpath, display, line))

        # Report exports not imported anywhere
        for name, fpath, display, line in all_exports:
            if name not in all_imported:
                # Skip common patterns that are used via routes/config
                if name in ("default", "handler", "GET", "POST", "PUT", "DELETE",
                            "middleware", "config", "metadata", "generateMetadata",
                            "generateStaticParams", "revalidate", "dynamic",
                            "runtime", "fetchCache"):
                    continue
                # Skip page/layout/route files (Next.js convention)
                basename = os.path.basename(fpath)
                if basename in ("page.tsx", "page.ts", "page.js",
                               "layout.tsx", "layout.ts", "layout.js",
                               "route.ts", "route.js",
                               "loading.tsx", "error.tsx", "not-found.tsx"):
                    continue

                findings_list.append(finding(
                    severity="info",
                    check="dead_code",
                    file=display,
                    line=line,
                    message=f"Exported function '{name}' not imported anywhere in project",
                ))

    # --- Stale files ---
    all_exts = get_language_extensions(languages)
    stale = _find_stale_files(project_path, ignore, all_exts)
    for rel, age_days in stale:
        if age_days > 365:
            severity = "warning"
        else:
            severity = "info"
        findings_list.append(finding(
            severity=severity,
            check="dead_code",
            file=f"{project_name}/{rel}",
            message=f"Stale file: not modified in {int(age_days)} days",
        ))

    return findings_list

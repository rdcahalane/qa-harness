"""
Duplicate code detection using AST comparison (Python) and
token-sequence hashing (JS/TS).

Finds functions/methods with highly similar structure across and within projects.
"""

import ast
import hashlib
import os
import re
from collections import defaultdict
from typing import List, Dict, Any, Optional, Tuple

from .base import (
    finding, walk_project_files, read_file_safe,
    get_language_extensions, resolve_path,
)

# Minimum function body size (lines) to consider
MIN_FUNC_LINES = 5
# Similarity threshold for AST comparison (0-1)
SIMILARITY_THRESHOLD = 0.85


# ---------------------------------------------------------------------------
# Python AST-based duplicate detection
# ---------------------------------------------------------------------------

def _normalize_ast(node: ast.AST) -> str:
    """
    Produce a normalized string from an AST node by replacing all names
    with positional placeholders. Two functions with identical structure
    but different variable/function names will produce the same string.
    """
    name_map: Dict[str, str] = {}
    counter = [0]

    def _get_placeholder(name: str) -> str:
        if name not in name_map:
            name_map[name] = f"_V{counter[0]}"
            counter[0] += 1
        return name_map[name]

    def _walk(n: ast.AST) -> str:
        if isinstance(n, ast.Name):
            return f"Name({_get_placeholder(n.id)})"
        if isinstance(n, ast.Constant):
            return f"Const({type(n.value).__name__})"
        if isinstance(n, ast.FunctionDef) or isinstance(n, ast.AsyncFunctionDef):
            args = ",".join(_get_placeholder(a.arg) for a in n.args.args)
            body = ";".join(_walk(c) for c in n.body)
            return f"Func({args}){{{body}}}"
        if isinstance(n, ast.Attribute):
            return f"Attr({_walk(n.value)}.{n.attr})"
        if isinstance(n, ast.Call):
            func = _walk(n.func)
            args = ",".join(_walk(a) for a in n.args)
            return f"Call({func})({args})"
        if isinstance(n, ast.Assign):
            targets = ",".join(_walk(t) for t in n.targets)
            return f"Assign({targets}={_walk(n.value)})"
        if isinstance(n, ast.Return):
            val = _walk(n.value) if n.value else "None"
            return f"Return({val})"
        if isinstance(n, ast.If):
            test = _walk(n.test)
            body = ";".join(_walk(c) for c in n.body)
            orelse = ";".join(_walk(c) for c in n.orelse)
            return f"If({test}){{{body}}}else{{{orelse}}}"
        if isinstance(n, ast.For):
            target = _walk(n.target)
            iter_ = _walk(n.iter)
            body = ";".join(_walk(c) for c in n.body)
            return f"For({target} in {iter_}){{{body}}}"
        if isinstance(n, ast.While):
            test = _walk(n.test)
            body = ";".join(_walk(c) for c in n.body)
            return f"While({test}){{{body}}}"
        if isinstance(n, ast.BinOp):
            return f"BinOp({_walk(n.left)}{type(n.op).__name__}{_walk(n.right)})"
        if isinstance(n, ast.Compare):
            left = _walk(n.left)
            ops = ",".join(type(o).__name__ for o in n.ops)
            comps = ",".join(_walk(c) for c in n.comparators)
            return f"Compare({left}{ops}{comps})"
        if isinstance(n, ast.BoolOp):
            vals = ",".join(_walk(v) for v in n.values)
            return f"BoolOp({type(n.op).__name__},{vals})"
        if isinstance(n, ast.Expr):
            return f"Expr({_walk(n.value)})"
        if isinstance(n, ast.Dict):
            keys = ",".join(_walk(k) if k else "None" for k in n.keys)
            vals = ",".join(_walk(v) for v in n.values)
            return f"Dict({keys}:{vals})"
        if isinstance(n, ast.List):
            elts = ",".join(_walk(e) for e in n.elts)
            return f"List({elts})"
        if isinstance(n, ast.Subscript):
            return f"Sub({_walk(n.value)}[{_walk(n.slice)}])"
        if isinstance(n, ast.Try):
            body = ";".join(_walk(c) for c in n.body)
            handlers = ";".join(_walk(h) for h in n.handlers)
            return f"Try{{{body}}}catch{{{handlers}}}"

        # Fallback: node class name + children
        children = []
        for child in ast.iter_child_nodes(n):
            children.append(_walk(child))
        cname = type(n).__name__
        return f"{cname}({','.join(children)})"

    return _walk(node)


def _extract_python_functions(filepath: str) -> List[Tuple[str, int, str, int]]:
    """
    Extract (func_name, start_line, normalized_ast_hash, line_count)
    from a Python file.
    """
    source = read_file_safe(filepath)
    if not source:
        return []

    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        return []

    results = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Count body lines
            if not node.body:
                continue
            end_line = getattr(node, "end_lineno", node.lineno + MIN_FUNC_LINES)
            line_count = end_line - node.lineno
            if line_count < MIN_FUNC_LINES:
                continue

            normalized = _normalize_ast(node)
            norm_hash = hashlib.md5(normalized.encode()).hexdigest()
            results.append((node.name, node.lineno, norm_hash, line_count))

    return results


# ---------------------------------------------------------------------------
# JS/TS token-sequence hashing for duplicate detection
# ---------------------------------------------------------------------------

# Regex to strip comments and normalize whitespace
_JS_COMMENT_RE = re.compile(r"//[^\n]*|/\*[\s\S]*?\*/")
_JS_STRING_RE = re.compile(r"""(['"`])(?:(?!\1|\\).|\\.)*\1""")
_JS_FUNC_RE = re.compile(
    r"(?:async\s+)?(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[a-zA-Z_$]\w*)\s*=>)",
    re.MULTILINE,
)


def _extract_js_blocks(filepath: str) -> List[Tuple[str, int, str, int]]:
    """
    Extract function-like blocks from JS/TS files using brace matching.
    Returns (name, line, content_hash, line_count).
    """
    source = read_file_safe(filepath)
    if not source:
        return []

    results = []
    lines = source.split("\n")

    for match in _JS_FUNC_RE.finditer(source):
        name = match.group(1) or match.group(2) or "anonymous"
        start_pos = match.start()
        start_line = source[:start_pos].count("\n") + 1

        # Find the opening brace
        brace_pos = source.find("{", match.end())
        if brace_pos == -1:
            # Arrow function without braces -- skip (too short)
            continue

        # Match braces
        depth = 1
        pos = brace_pos + 1
        while pos < len(source) and depth > 0:
            ch = source[pos]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            elif ch in ("'", '"', "`"):
                # Skip strings
                end = source.find(ch, pos + 1)
                if end != -1:
                    pos = end
            pos += 1

        if depth != 0:
            continue

        block = source[brace_pos:pos]
        end_line = source[:pos].count("\n") + 1
        line_count = end_line - start_line

        if line_count < MIN_FUNC_LINES:
            continue

        # Normalize: strip comments, strings, whitespace
        normalized = _JS_COMMENT_RE.sub("", block)
        normalized = _JS_STRING_RE.sub("STR", normalized)
        normalized = re.sub(r"\s+", " ", normalized).strip()
        normalized = re.sub(r"\b[a-zA-Z_$]\w*\b", "ID", normalized)

        content_hash = hashlib.md5(normalized.encode()).hexdigest()
        results.append((name, start_line, content_hash, line_count))

    return results


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run(project_config: Dict[str, Any], global_config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Scan a project for duplicate functions. Also accepts cross_project_hashes
    in global_config to detect cross-project duplicates.
    """
    findings = []
    project_path = resolve_path(project_config["path"])
    project_name = project_config["name"]
    ignore = project_config.get("ignore_patterns", [])
    languages = project_config.get("languages", [])

    # Collect all function hashes: hash -> [(project, file, name, line, line_count)]
    hash_registry = global_config.get("_duplicate_registry", {})

    # Python files
    if "python" in languages:
        py_files = walk_project_files(project_path, ignore, [".py"])
        for fpath in py_files:
            rel = os.path.relpath(fpath, project_path)
            for func_name, line, fhash, lcount in _extract_python_functions(fpath):
                entry = (project_name, rel, func_name, line, lcount)
                hash_registry.setdefault(fhash, []).append(entry)

    # JS/TS files
    js_exts = []
    if "javascript" in languages:
        js_exts.extend([".js", ".mjs", ".cjs"])
    if "typescript" in languages:
        js_exts.extend([".ts", ".tsx"])

    if js_exts:
        js_files = walk_project_files(project_path, ignore, js_exts)
        for fpath in js_files:
            rel = os.path.relpath(fpath, project_path)
            for func_name, line, fhash, lcount in _extract_js_blocks(fpath):
                entry = (project_name, rel, func_name, line, lcount)
                hash_registry.setdefault(fhash, []).append(entry)

    # Store back for cross-project accumulation
    global_config["_duplicate_registry"] = hash_registry

    return findings


def finalize(global_config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Called after all projects have been scanned. Emits findings for
    duplicate function groups.
    """
    findings = []
    registry = global_config.get("_duplicate_registry", {})

    for fhash, entries in registry.items():
        if len(entries) < 2:
            continue

        # Check if duplicates span multiple projects or files
        unique_locations = set((e[0], e[1]) for e in entries)
        if len(unique_locations) < 2:
            # Same file duplicates -- less interesting but still report
            if len(entries) < 3:
                continue

        cross_project = len(set(e[0] for e in entries)) > 1
        severity = "warning" if cross_project else "info"

        locations = []
        for proj, fpath, fname, line, lcount in entries:
            locations.append(f"  {proj}/{fpath}:{line} -> {fname}() ({lcount} lines)")

        primary = entries[0]
        findings.append(finding(
            severity=severity,
            check="duplicate_code",
            file=f"{primary[0]}/{primary[1]}",
            line=primary[3],
            message=f"Duplicate function structure found in {len(entries)} locations"
                    + (" (CROSS-PROJECT)" if cross_project else "")
                    + ":\n" + "\n".join(locations),
        ))

    return findings

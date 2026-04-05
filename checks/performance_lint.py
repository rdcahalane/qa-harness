"""
Performance linter: find N+1 queries, missing indexes, unbounded queries,
expensive patterns in Python and JS/TS code.
"""

import os
import re
from typing import List, Dict, Any

from .base import (
    finding, walk_project_files, read_file_safe,
    get_language_extensions, resolve_path,
)


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# N+1 query patterns: queries inside loops
N_PLUS_1_PATTERNS = [
    # Python: query inside for/while loop
    (
        r"(?:for|while)\s+.+:\s*\n(?:\s+.*\n)*?\s+.*\.(?:execute|fetchone|fetchall|select|from_|query)\s*\(",
        "python",
        "Potential N+1 query: database call inside a loop",
    ),
    # JS: await query inside for/while/forEach
    (
        r"(?:for|while)\s*\(.+\)\s*\{[\s\S]{0,500}?await\s+.*\.(?:select|from|query|execute|findOne|findMany|find)\s*\(",
        "javascript",
        "Potential N+1 query: awaited database call inside a loop",
    ),
    # Supabase .select() inside loop
    (
        r"(?:for|while|\.forEach|\.map)\s*[\(\{][\s\S]{0,300}?supabase[\s\S]{0,100}?\.select\s*\(",
        "javascript",
        "Potential N+1: Supabase .select() inside a loop",
    ),
]

# Unbounded query patterns
UNBOUNDED_PATTERNS = [
    # SELECT * without LIMIT
    (
        r"""\.select\s*\(\s*['"]?\*['"]?\s*\)(?![\s\S]{0,200}\.limit\s*\()""",
        "Unbounded SELECT * without .limit() -- may return entire table",
        "warning",
    ),
    # Supabase select without limit (JS)
    (
        r"supabase\s*\.\s*from\s*\([^)]+\)\s*\.\s*select\s*\([^)]*\)(?![\s\S]{0,150}\.(?:limit|single|maybeSingle)\s*\()",
        "Supabase query without .limit() or .single() -- may return unbounded rows",
        "warning",
    ),
    # Python fetchall without limit
    (
        r"\.fetchall\s*\(\s*\)(?![\s\S]{0,50}LIMIT)",
        "fetchall() without LIMIT in query -- may load entire result set into memory",
        "info",
    ),
]

# Expensive operation patterns
EXPENSIVE_PATTERNS = [
    # JSON.parse in a hot loop
    (
        r"(?:for|while|\.map|\.forEach|\.reduce)\s*[\(\{][\s\S]{0,200}?JSON\.parse\s*\(",
        "JSON.parse() inside a loop -- consider parsing once and reusing",
        "info",
    ),
    # Regex compilation inside loop (Python)
    (
        r"(?:for|while)\s+.+:\s*\n(?:\s+.*\n)*?\s+.*re\.(?:compile|search|match|findall)\s*\(",
        "Regex operation inside loop -- compile the regex once outside the loop",
        "info",
    ),
    # Synchronous file I/O in async context (Node.js)
    (
        r"(?:async\s+function|=>\s*\{)[\s\S]{0,500}?(?:readFileSync|writeFileSync|existsSync|statSync)\s*\(",
        "Synchronous fs operation in async function -- use async/promises variant",
        "warning",
    ),
    # Missing index hint: filtering on non-obvious columns
    (
        r"\.eq\s*\(\s*['\"](?:created_at|updated_at|status|type|category)['\"]",
        "Filtering on common column -- verify database index exists",
        "info",
    ),
    # Large array operations
    (
        r"\.sort\s*\(\s*\)(?:[\s\S]{0,30}\.reverse\s*\(\s*\))?",
        "Array .sort() -- O(n log n); for large arrays, consider maintaining sorted order",
        "info",
    ),
    # String concatenation in loop
    (
        r"(?:for|while)\s*[\(\{][\s\S]{0,200}?\+=\s*['\"`]",
        "String concatenation in loop -- use array.join() or template literals",
        "info",
    ),
]

# Missing error handling patterns
ERROR_PATTERNS = [
    # fetch without error handling
    (
        r"(?:await\s+)?fetch\s*\([^)]+\)(?!\s*\.then\s*\([\s\S]{0,100}\.catch|\s*\.\s*catch)",
        "fetch() without .catch() or try/catch -- network errors will crash",
        "info",
    ),
    # Python: bare except
    (
        r"except\s*:",
        "Bare 'except:' catches SystemExit and KeyboardInterrupt -- use 'except Exception:'",
        "warning",
    ),
]

# SQL injection patterns
SQL_PATTERNS = [
    # f-string or format in SQL
    (
        r"""(?:execute|query|run)\s*\(\s*f['""].*\{.*\}""",
        "SQL query with f-string interpolation -- use parameterized queries",
        "critical",
    ),
    (
        r"""(?:execute|query|run)\s*\(\s*['"].*%s.*['"]\s*%\s*""",
        "SQL query with % formatting -- use parameterized queries",
        "warning",
    ),
    (
        r"""(?:execute|query|run)\s*\(\s*['"].*\+\s*(?:req\.|request\.|params\.|body\.)""",
        "SQL query with string concatenation from request -- SQL injection risk",
        "critical",
    ),
]


def _scan_line_patterns(
    filepath: str,
    content: str,
    project_name: str,
) -> List[Dict[str, Any]]:
    """Scan for single-line performance anti-patterns."""
    results = []

    for line_num, line in enumerate(content.split("\n"), 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        # Error patterns
        for pattern, message, severity in ERROR_PATTERNS:
            if re.search(pattern, line):
                results.append(finding(
                    severity=severity,
                    check="performance_lint",
                    file=filepath,
                    line=line_num,
                    message=message,
                    snippet=stripped[:200],
                ))
                break

        # SQL injection
        for pattern, message, severity in SQL_PATTERNS:
            if re.search(pattern, line):
                results.append(finding(
                    severity=severity,
                    check="performance_lint",
                    file=filepath,
                    line=line_num,
                    message=message,
                    snippet=stripped[:200],
                ))
                break

    return results


def _scan_multiline_patterns(
    filepath: str,
    content: str,
    project_name: str,
    file_lang: str,
) -> List[Dict[str, Any]]:
    """Scan for multi-line performance patterns (N+1, unbounded, expensive)."""
    results = []

    # N+1 patterns
    for pattern, lang, message in N_PLUS_1_PATTERNS:
        if lang != file_lang and lang != "any":
            continue
        for match in re.finditer(pattern, content):
            line = content[:match.start()].count("\n") + 1
            snippet = match.group(0)[:200].replace("\n", " | ")
            results.append(finding(
                severity="warning",
                check="performance_lint",
                file=filepath,
                line=line,
                message=message,
                snippet=snippet,
            ))

    # Unbounded queries
    for pattern, message, severity in UNBOUNDED_PATTERNS:
        for match in re.finditer(pattern, content):
            line = content[:match.start()].count("\n") + 1
            snippet = match.group(0)[:200].replace("\n", " | ")
            results.append(finding(
                severity=severity,
                check="performance_lint",
                file=filepath,
                line=line,
                message=message,
                snippet=snippet,
            ))

    # Expensive patterns
    for pattern, message, severity in EXPENSIVE_PATTERNS:
        for match in re.finditer(pattern, content):
            line = content[:match.start()].count("\n") + 1
            snippet = match.group(0)[:200].replace("\n", " | ")
            results.append(finding(
                severity=severity,
                check="performance_lint",
                file=filepath,
                line=line,
                message=message,
                snippet=snippet,
            ))

    return results


# ---------------------------------------------------------------------------
# Migration / index checks
# ---------------------------------------------------------------------------

def _check_migrations(
    project_path: str,
    project_name: str,
    ignore: List[str],
) -> List[Dict[str, Any]]:
    """Check SQL migrations for missing indexes on common patterns."""
    results = []

    migration_dirs = [
        os.path.join(project_path, "migrations"),
        os.path.join(project_path, "supabase", "migrations"),
        os.path.join(project_path, "prisma", "migrations"),
    ]

    for mdir in migration_dirs:
        if not os.path.isdir(mdir):
            continue

        sql_files = walk_project_files(mdir, ignore, [".sql"])
        for fpath in sql_files:
            content = read_file_safe(fpath)
            if not content:
                continue

            rel = os.path.relpath(fpath, project_path)
            display = f"{project_name}/{rel}"

            # Check for CREATE TABLE without indexes on foreign keys
            tables = re.findall(
                r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\S+)\s*\(([\s\S]+?)\);",
                content,
                re.IGNORECASE,
            )

            for table_name, table_body in tables:
                # Find foreign key columns
                fk_cols = re.findall(
                    r"(\w+_id)\s+(?:integer|bigint|uuid|text)",
                    table_body,
                    re.IGNORECASE,
                )
                # Check if corresponding indexes exist in the same migration
                for col in fk_cols:
                    idx_pattern = re.compile(
                        rf"CREATE\s+(?:UNIQUE\s+)?INDEX.*ON\s+{re.escape(table_name)}.*\({re.escape(col)}\)",
                        re.IGNORECASE,
                    )
                    if not idx_pattern.search(content):
                        results.append(finding(
                            severity="warning",
                            check="performance_lint",
                            file=display,
                            message=f"Foreign key column '{col}' in table '{table_name}' "
                                    f"has no index -- queries filtering on this will be slow",
                        ))

    return results


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run(project_config: Dict[str, Any], global_config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Run performance lint on a project."""
    findings_list = []
    project_path = resolve_path(project_config["path"])
    project_name = project_config["name"]
    ignore = project_config.get("ignore_patterns", [])
    languages = project_config.get("languages", [])

    extensions = get_language_extensions(languages)
    files = walk_project_files(project_path, ignore, extensions)

    for fpath in files:
        content = read_file_safe(fpath)
        if not content:
            continue

        rel = os.path.relpath(fpath, project_path)
        display = f"{project_name}/{rel}"

        # Determine language for this file
        if fpath.endswith(".py"):
            file_lang = "python"
        elif fpath.endswith((".js", ".mjs", ".cjs", ".ts", ".tsx")):
            file_lang = "javascript"
        else:
            file_lang = "unknown"

        findings_list.extend(_scan_line_patterns(display, content, project_name))
        findings_list.extend(
            _scan_multiline_patterns(display, content, project_name, file_lang)
        )

    # Check migrations
    findings_list.extend(_check_migrations(project_path, project_name, ignore))

    return findings_list

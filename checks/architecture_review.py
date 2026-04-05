"""
Architecture review: detect shared patterns, duplicated infrastructure,
inconsistent configurations across projects.

Looks for:
- Similar Supabase client setups
- Duplicated signal storage patterns
- Inconsistent env var naming
- Shared utility code that should be a package
- Framework version mismatches
"""

import json
import os
import re
from collections import defaultdict
from typing import List, Dict, Any, Tuple, Set

from .base import (
    finding, walk_project_files, read_file_safe,
    get_language_extensions, resolve_path,
)


# ---------------------------------------------------------------------------
# Pattern detectors
# ---------------------------------------------------------------------------

def _find_supabase_clients(
    project_path: str,
    project_name: str,
    ignore: List[str],
    extensions: List[str],
) -> List[Dict[str, Any]]:
    """Find Supabase client initialization patterns."""
    findings_list = []
    clients_found = []

    files = walk_project_files(project_path, ignore, extensions)
    supabase_re = re.compile(
        r"createClient|createServerClient|createBrowserClient|"
        r"supabase\.createClient|@supabase/supabase-js|"
        r"from\s+['\"]@supabase",
        re.IGNORECASE,
    )

    for fpath in files:
        content = read_file_safe(fpath)
        if not content:
            continue
        if supabase_re.search(content):
            rel = os.path.relpath(fpath, project_path)
            clients_found.append(rel)

    if len(clients_found) > 3:
        findings_list.append(finding(
            severity="info",
            check="architecture_review",
            file=project_name,
            message=f"Supabase client initialized in {len(clients_found)} files -- "
                    f"consider a shared client module. Files: "
                    + ", ".join(clients_found[:5])
                    + ("..." if len(clients_found) > 5 else ""),
        ))

    return findings_list, clients_found


def _find_fetch_wrappers(
    project_path: str,
    project_name: str,
    ignore: List[str],
    extensions: List[str],
) -> List[Tuple[str, str]]:
    """Find HTTP fetch/axios wrapper patterns that could be shared."""
    wrappers = []
    fetch_re = re.compile(
        r"(?:async\s+)?(?:function|const|let|var)\s+(\w*(?:fetch|request|api|http)\w*)\s*"
        r"(?:=\s*(?:async\s*)?\(|[\(])",
        re.IGNORECASE,
    )

    files = walk_project_files(project_path, ignore, extensions)
    for fpath in files:
        content = read_file_safe(fpath)
        if not content:
            continue
        for match in fetch_re.finditer(content):
            rel = os.path.relpath(fpath, project_path)
            wrappers.append((match.group(1), rel))

    return wrappers


def _check_env_consistency(
    project_path: str,
    project_name: str,
) -> List[Dict[str, Any]]:
    """Check for env var naming consistency and missing .env.example."""
    findings_list = []

    # Check if .env.example exists
    has_env = os.path.isfile(os.path.join(project_path, ".env"))
    has_example = os.path.isfile(os.path.join(project_path, ".env.example"))

    if has_env and not has_example:
        findings_list.append(finding(
            severity="info",
            check="architecture_review",
            file=f"{project_name}/.env.example",
            message="Project has .env but no .env.example -- "
                    "new developers won't know required env vars",
        ))

    return findings_list


def _check_package_versions(
    project_path: str,
    project_name: str,
) -> Dict[str, Dict[str, str]]:
    """Extract key dependency versions from package.json."""
    pkg_path = os.path.join(project_path, "package.json")
    if not os.path.isfile(pkg_path):
        return {}

    content = read_file_safe(pkg_path)
    if not content:
        return {}

    try:
        pkg = json.loads(content)
    except json.JSONDecodeError:
        return {}

    deps = {}
    for section in ("dependencies", "devDependencies"):
        if section in pkg:
            deps.update(pkg[section])

    # Key frameworks to track
    tracked = [
        "next", "react", "react-dom", "typescript", "tailwindcss",
        "@supabase/supabase-js", "express", "fastify",
    ]

    versions = {}
    for dep in tracked:
        if dep in deps:
            versions[dep] = deps[dep]

    return versions


def _check_python_requirements(
    project_path: str,
) -> Dict[str, str]:
    """Extract key Python dependency versions."""
    versions = {}
    for req_file in ("requirements.txt", "pyproject.toml"):
        fpath = os.path.join(project_path, req_file)
        if not os.path.isfile(fpath):
            continue
        content = read_file_safe(fpath)
        if not content:
            continue

        if req_file == "requirements.txt":
            for line in content.split("\n"):
                line = line.strip()
                if "==" in line:
                    name, ver = line.split("==", 1)
                    versions[name.strip()] = ver.strip()
                elif ">=" in line:
                    name, ver = line.split(">=", 1)
                    versions[name.strip()] = f">={ver.strip()}"

    return versions


# ---------------------------------------------------------------------------
# Cross-project analysis (called from finalize)
# ---------------------------------------------------------------------------

def _compare_framework_versions(
    all_versions: Dict[str, Dict[str, str]],
) -> List[Dict[str, Any]]:
    """Compare framework versions across projects."""
    findings_list = []

    # Invert: dep -> {project: version}
    dep_map: Dict[str, Dict[str, str]] = defaultdict(dict)
    for project, versions in all_versions.items():
        for dep, ver in versions.items():
            dep_map[dep][project] = ver

    for dep, project_versions in dep_map.items():
        if len(project_versions) < 2:
            continue

        unique_versions = set(project_versions.values())
        if len(unique_versions) > 1:
            details = ", ".join(
                f"{proj}={ver}" for proj, ver in sorted(project_versions.items())
            )
            findings_list.append(finding(
                severity="warning",
                check="architecture_review",
                file="(cross-project)",
                message=f"Version mismatch for '{dep}': {details}",
            ))

    return findings_list


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run(project_config: Dict[str, Any], global_config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Run architecture review on a project."""
    findings_list = []
    project_path = resolve_path(project_config["path"])
    project_name = project_config["name"]
    ignore = project_config.get("ignore_patterns", [])
    languages = project_config.get("languages", [])
    extensions = get_language_extensions(languages)

    # Supabase client sprawl
    sb_findings, sb_clients = _find_supabase_clients(
        project_path, project_name, ignore, extensions
    )
    findings_list.extend(sb_findings)

    # Env consistency
    findings_list.extend(_check_env_consistency(project_path, project_name))

    # Collect framework versions for cross-project comparison
    arch_registry = global_config.setdefault("_architecture_registry", {
        "versions": {},
        "fetch_wrappers": {},
        "supabase_clients": {},
    })

    # JS/TS versions
    js_versions = _check_package_versions(project_path, project_name)
    # Python versions
    py_versions = _check_python_requirements(project_path)
    all_versions = {**js_versions, **py_versions}
    if all_versions:
        arch_registry["versions"][project_name] = all_versions

    # Fetch wrappers
    wrappers = _find_fetch_wrappers(project_path, project_name, ignore, extensions)
    if wrappers:
        arch_registry["fetch_wrappers"][project_name] = wrappers

    # Supabase client files
    if sb_clients:
        arch_registry["supabase_clients"][project_name] = sb_clients

    return findings_list


def finalize(global_config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Cross-project architecture findings."""
    findings_list = []
    registry = global_config.get("_architecture_registry", {})

    # Framework version mismatches
    findings_list.extend(
        _compare_framework_versions(registry.get("versions", {}))
    )

    # Cross-project Supabase client duplication
    sb_clients = registry.get("supabase_clients", {})
    total_sb = sum(len(v) for v in sb_clients.values())
    if total_sb > 5 and len(sb_clients) > 1:
        projects = ", ".join(f"{k}({len(v)})" for k, v in sb_clients.items())
        findings_list.append(finding(
            severity="warning",
            check="architecture_review",
            file="(cross-project)",
            message=f"Supabase client initialized in {total_sb} files across "
                    f"{len(sb_clients)} projects ({projects}) -- "
                    f"consider a shared @ryancahalane/supabase-client package",
        ))

    # Cross-project fetch wrapper duplication
    wrappers = registry.get("fetch_wrappers", {})
    total_wrappers = sum(len(v) for v in wrappers.values())
    if total_wrappers > 8 and len(wrappers) > 2:
        findings_list.append(finding(
            severity="info",
            check="architecture_review",
            file="(cross-project)",
            message=f"Found {total_wrappers} HTTP fetch wrappers across "
                    f"{len(wrappers)} projects -- consider a shared fetch utility",
        ))

    return findings_list

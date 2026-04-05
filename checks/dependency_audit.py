"""
Dependency audit: check for outdated/vulnerable dependencies across projects.

For JS: reads package.json + package-lock.json, checks for known vulnerable
         patterns and very outdated versions.
For Python: reads requirements.txt / pyproject.toml.

No network calls -- uses heuristic version checks and known CVE patterns.
"""

import json
import os
import re
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

from .base import finding, resolve_path, read_file_safe


# Known vulnerable package+version ranges (manually maintained shortlist)
# Format: (package_name, bad_version_prefix, CVE/description)
KNOWN_VULNERABLE_JS = [
    ("lodash", "4.17.1", "CVE-2021-23337 prototype pollution (fixed in 4.17.21)"),
    ("minimist", "0.", "CVE-2021-44906 prototype pollution"),
    ("node-fetch", "2.6.0", "CVE-2022-0235 information disclosure (fixed 2.6.7)"),
    ("node-fetch", "2.6.1", "CVE-2022-0235 information disclosure (fixed 2.6.7)"),
    ("jsonwebtoken", "8.", "CVE-2022-23529 insecure key handling (fixed 9.0.0)"),
    ("axios", "0.", "Multiple CVEs in 0.x -- upgrade to 1.x"),
    ("express", "4.17.", "Older Express 4 -- check for CVE-2024-29041"),
    ("tar", "6.1.", "CVE-2024-28863 denial of service"),
    ("xml2js", "0.4.", "CVE-2023-0842 prototype pollution"),
    ("semver", "5.", "CVE-2022-25883 ReDoS in semver <5.7.2, <6.3.1, <7.5.2"),
    ("got", "11.", "CVE-2022-33987 redirect SSRF"),
]

KNOWN_VULNERABLE_PY = [
    ("requests", "2.25.", "Older requests -- check for CVE-2023-32681"),
    ("urllib3", "1.", "urllib3 1.x has multiple CVEs -- upgrade to 2.x"),
    ("Pillow", "9.", "Pillow 9.x has multiple CVEs -- upgrade to 10.x+"),
    ("cryptography", "3.", "cryptography 3.x -- multiple CVEs, upgrade to 41+"),
    ("django", "3.", "Django 3.x is EOL"),
    ("flask", "1.", "Flask 1.x is EOL -- upgrade to 2.x+"),
    ("jinja2", "2.", "Jinja2 2.x -- CVE-2024-22195 XSS"),
    ("pyyaml", "5.", "PyYAML 5.x -- CVE-2020-14343 arbitrary code execution via yaml.load"),
    ("setuptools", "6", "Old setuptools may have supply chain risks"),
]


def _parse_version(ver: str) -> Optional[Tuple[int, ...]]:
    """Parse a semver-like string into a tuple of ints."""
    ver = ver.lstrip("^~>=<! ")
    match = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", ver)
    if not match:
        return None
    parts = []
    for g in match.groups():
        if g is not None:
            parts.append(int(g))
    return tuple(parts)


def _check_js_deps(
    project_path: str,
    project_name: str,
) -> List[Dict[str, Any]]:
    """Check JS dependencies for vulnerabilities and staleness."""
    findings_list = []
    pkg_path = os.path.join(project_path, "package.json")

    if not os.path.isfile(pkg_path):
        return findings_list

    content = read_file_safe(pkg_path)
    if not content:
        return findings_list

    try:
        pkg = json.loads(content)
    except json.JSONDecodeError:
        findings_list.append(finding(
            severity="warning",
            check="dependency_audit",
            file=f"{project_name}/package.json",
            message="Invalid JSON in package.json",
        ))
        return findings_list

    all_deps = {}
    for section in ("dependencies", "devDependencies"):
        all_deps.update(pkg.get(section, {}))

    # Check for known vulnerabilities
    for dep_name, dep_ver in all_deps.items():
        clean_ver = dep_ver.lstrip("^~>=<! ")

        for vuln_name, vuln_prefix, vuln_desc in KNOWN_VULNERABLE_JS:
            if dep_name == vuln_name and clean_ver.startswith(vuln_prefix):
                findings_list.append(finding(
                    severity="warning",
                    check="dependency_audit",
                    file=f"{project_name}/package.json",
                    message=f"Potentially vulnerable: {dep_name}@{clean_ver} -- {vuln_desc}",
                ))

    # Check for very old pinned versions (major version 0.x in production deps)
    prod_deps = pkg.get("dependencies", {})
    for dep_name, dep_ver in prod_deps.items():
        parsed = _parse_version(dep_ver)
        if parsed and parsed[0] == 0 and dep_name not in (
            # Some packages are legitimately 0.x
            "tailwind-merge", "clsx",
        ):
            findings_list.append(finding(
                severity="info",
                check="dependency_audit",
                file=f"{project_name}/package.json",
                message=f"Production dependency on pre-1.0: {dep_name}@{dep_ver} "
                        f"-- may be unstable",
            ))

    # Check lockfile freshness
    lock_path = os.path.join(project_path, "package-lock.json")
    if os.path.isfile(lock_path):
        lock_age = (datetime.now().timestamp() - os.path.getmtime(lock_path)) / 86400
        if lock_age > 90:
            findings_list.append(finding(
                severity="info",
                check="dependency_audit",
                file=f"{project_name}/package-lock.json",
                message=f"Lockfile is {int(lock_age)} days old -- "
                        f"consider running npm audit / npm update",
            ))
    elif os.path.isfile(pkg_path) and all_deps:
        findings_list.append(finding(
            severity="warning",
            check="dependency_audit",
            file=f"{project_name}/package-lock.json",
            message="No lockfile found -- builds may be non-deterministic",
        ))

    # Check for engines field
    if "engines" not in pkg and all_deps:
        findings_list.append(finding(
            severity="info",
            check="dependency_audit",
            file=f"{project_name}/package.json",
            message="No 'engines' field -- Node.js version not pinned",
        ))

    return findings_list


def _check_py_deps(
    project_path: str,
    project_name: str,
) -> List[Dict[str, Any]]:
    """Check Python dependencies for vulnerabilities and staleness."""
    findings_list = []
    deps: Dict[str, str] = {}

    # requirements.txt
    req_path = os.path.join(project_path, "requirements.txt")
    if os.path.isfile(req_path):
        content = read_file_safe(req_path) or ""
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "==" in line:
                name, ver = line.split("==", 1)
                deps[name.strip().lower()] = ver.strip()
            elif ">=" in line:
                name, ver = line.split(">=", 1)
                deps[name.strip().lower()] = ver.strip()
            elif line and not line.startswith("-"):
                # Unpinned dependency
                dep_name = re.split(r"[<>=!]", line)[0].strip()
                if dep_name:
                    deps[dep_name.lower()] = "unpinned"

        # Check for unpinned deps
        unpinned = [n for n, v in deps.items() if v == "unpinned"]
        if unpinned:
            findings_list.append(finding(
                severity="warning",
                check="dependency_audit",
                file=f"{project_name}/requirements.txt",
                message=f"Unpinned Python dependencies (non-reproducible): "
                        + ", ".join(unpinned[:10]),
            ))

    # pyproject.toml -- just check if it exists for Python projects
    pyproject_path = os.path.join(project_path, "pyproject.toml")
    if not os.path.isfile(req_path) and not os.path.isfile(pyproject_path):
        # Check if there are .py files (it's a Python project)
        py_files_exist = any(
            f.endswith(".py")
            for f in os.listdir(project_path)
            if os.path.isfile(os.path.join(project_path, f))
        )
        if py_files_exist:
            findings_list.append(finding(
                severity="info",
                check="dependency_audit",
                file=f"{project_name}/requirements.txt",
                message="Python project without requirements.txt or pyproject.toml",
            ))

    # Check for known vulnerabilities
    for dep_name, dep_ver in deps.items():
        if dep_ver == "unpinned":
            continue
        for vuln_name, vuln_prefix, vuln_desc in KNOWN_VULNERABLE_PY:
            if dep_name == vuln_name.lower() and dep_ver.startswith(vuln_prefix):
                findings_list.append(finding(
                    severity="warning",
                    check="dependency_audit",
                    file=f"{project_name}/requirements.txt",
                    message=f"Potentially vulnerable: {dep_name}=={dep_ver} -- {vuln_desc}",
                ))

    return findings_list


def run(project_config: Dict[str, Any], global_config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Run dependency audit on a project."""
    findings_list = []
    project_path = resolve_path(project_config["path"])
    project_name = project_config["name"]
    languages = project_config.get("languages", [])

    if any(lang in languages for lang in ("javascript", "typescript")):
        findings_list.extend(_check_js_deps(project_path, project_name))

    if "python" in languages:
        findings_list.extend(_check_py_deps(project_path, project_name))

    return findings_list

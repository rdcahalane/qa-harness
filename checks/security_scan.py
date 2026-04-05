"""
Security scanner: finds hardcoded secrets, exposed API keys in source code
(not .env files), insecure patterns, and dangerous configurations.
"""

import os
import re
from typing import List, Dict, Any

from .base import (
    finding, walk_project_files, read_file_safe,
    get_language_extensions, resolve_path,
)


# High-entropy string detector (Shannon entropy)
def _entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    from collections import Counter
    import math
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


# Known secret prefixes that are always bad in source code
KNOWN_PREFIXES = [
    ("sk-", "OpenAI/Anthropic API key"),
    ("sk-ant-", "Anthropic API key"),
    ("ghp_", "GitHub personal access token"),
    ("gho_", "GitHub OAuth token"),
    ("ghs_", "GitHub App installation token"),
    ("github_pat_", "GitHub fine-grained PAT"),
    ("xoxb-", "Slack bot token"),
    ("xoxp-", "Slack user token"),
    ("xoxa-", "Slack app token"),
    ("AKIA", "AWS access key ID"),
    ("eyJhbG", "JWT token (likely sensitive)"),
    ("sb-", "Supabase key prefix"),
]

# Insecure code patterns
INSECURE_PATTERNS = [
    (r"eval\s*\(", "Use of eval() -- potential code injection", "warning"),
    (r"child_process\.exec\s*\(", "child_process.exec -- prefer execFile for safety", "warning"),
    (r"subprocess\.call\s*\(.+shell\s*=\s*True", "subprocess with shell=True -- command injection risk", "warning"),
    (r"os\.system\s*\(", "os.system() -- use subprocess instead", "warning"),
    (r"innerHTML\s*=", "innerHTML assignment -- XSS risk, use textContent", "warning"),
    (r"dangerouslySetInnerHTML", "React dangerouslySetInnerHTML -- XSS risk", "info"),
    (r"(?i)cors.*origin.*['\"]?\*['\"]?", "CORS with wildcard origin", "warning"),
    (r"(?i)disable.*ssl|verify\s*=\s*False|rejectUnauthorized.*false", "SSL verification disabled", "critical"),
    (r"(?i)(?:md5|sha1)\s*\(", "Weak hash algorithm (MD5/SHA1) -- use SHA-256+", "info"),
    (r"Math\.random\s*\(", "Math.random() for security-sensitive context -- use crypto", "info"),
    (r"(?i)password\s*=\s*['\"][^'\"]+['\"]", "Hardcoded password in source", "critical"),
    (r"(?i)BEGIN\s+(RSA\s+)?PRIVATE\s+KEY", "Private key in source code", "critical"),
]

# Files that are safe to have secrets (env files, examples)
SAFE_BASENAMES = {
    ".env", ".env.local", ".env.development", ".env.production",
    ".env.example", ".env.sample", ".env.template",
    ".env.test", ".env.development.local", ".env.production.local",
}


def _is_safe_file(filepath: str) -> bool:
    """Check if file is an env file or example that's okay to have secrets."""
    basename = os.path.basename(filepath)
    return basename in SAFE_BASENAMES


def _is_test_or_mock(filepath: str) -> bool:
    """Reduce noise: test files may have fake keys."""
    lower = filepath.lower()
    return any(p in lower for p in [
        "test", "mock", "fixture", "fake", "stub", "example", "sample",
        "__tests__", "spec.",
    ])


def _scan_for_secrets(
    filepath: str,
    content: str,
    secret_patterns: List[str],
    project_name: str,
) -> List[Dict[str, Any]]:
    """Scan file content for hardcoded secrets."""
    results = []

    if _is_safe_file(filepath):
        return results

    is_test = _is_test_or_mock(filepath)

    for line_num, line in enumerate(content.split("\n"), 1):
        stripped = line.strip()

        # Skip comments
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
            continue

        # Check known prefixes
        for prefix, desc in KNOWN_PREFIXES:
            # Look for the prefix in string literals
            pattern = re.compile(
                rf"""['"]{re.escape(prefix)}[A-Za-z0-9_\-]{{10,}}['"]"""
            )
            match = pattern.search(line)
            if match:
                severity = "info" if is_test else "critical"
                results.append(finding(
                    severity=severity,
                    check="security_scan",
                    file=filepath,
                    line=line_num,
                    message=f"Hardcoded {desc} found in source code"
                            + (" (test file)" if is_test else ""),
                    snippet=_redact(stripped),
                ))

        # Check regex patterns from config
        for pat_str in secret_patterns:
            try:
                pat = re.compile(pat_str)
                match = pat.search(line)
                if match:
                    # Check entropy of the matched value to reduce false positives
                    matched_text = match.group(0)
                    # Extract the value part (after = or :)
                    val_match = re.search(r"""['"](.*?)['"]""", matched_text)
                    if val_match:
                        val = val_match.group(1)
                        if _entropy(val) < 3.0:
                            continue  # Low entropy -- probably not a real secret
                        if len(val) < 10:
                            continue  # Too short

                    severity = "info" if is_test else "warning"
                    results.append(finding(
                        severity=severity,
                        check="security_scan",
                        file=filepath,
                        line=line_num,
                        message="Potential hardcoded secret/credential in source code",
                        snippet=_redact(stripped),
                    ))
                    break  # One finding per line is enough
            except re.error:
                continue

    return results


def _scan_for_insecure_patterns(
    filepath: str,
    content: str,
    project_name: str,
) -> List[Dict[str, Any]]:
    """Scan for insecure coding patterns."""
    results = []

    for line_num, line in enumerate(content.split("\n"), 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        for pattern, message, severity in INSECURE_PATTERNS:
            if re.search(pattern, line):
                results.append(finding(
                    severity=severity,
                    check="security_scan",
                    file=filepath,
                    line=line_num,
                    message=message,
                    snippet=stripped[:200],
                ))
                break  # One pattern per line

    return results


def _redact(text: str, keep_chars: int = 8) -> str:
    """Redact potential secrets in snippets, keeping only first N chars visible."""
    # Find string literals and partially redact them
    def _redact_match(m):
        quote = m.group(1)
        val = m.group(2)
        if len(val) > keep_chars:
            return f"{quote}{val[:keep_chars]}...REDACTED{quote}"
        return m.group(0)

    return re.sub(r"""(['"])((?:(?!\1).)+)\1""", _redact_match, text)


def _check_gitignore(project_path: str, project_name: str) -> List[Dict[str, Any]]:
    """Check that .env files are in .gitignore."""
    results = []
    gitignore_path = os.path.join(project_path, ".gitignore")

    if not os.path.isfile(gitignore_path):
        results.append(finding(
            severity="warning",
            check="security_scan",
            file=f"{project_name}/.gitignore",
            message="No .gitignore file found -- secrets may be committed",
        ))
        return results

    content = read_file_safe(gitignore_path) or ""
    lines = {l.strip() for l in content.split("\n")}

    critical_patterns = [".env", ".env.local", ".env.production"]
    for pat in critical_patterns:
        if pat not in lines and f"*{pat}*" not in lines and ".env*" not in lines:
            results.append(finding(
                severity="warning",
                check="security_scan",
                file=f"{project_name}/.gitignore",
                message=f"{pat} not found in .gitignore -- secrets may be committed",
            ))

    return results


def run(project_config: Dict[str, Any], global_config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Run security scan on a project."""
    findings_list = []
    project_path = resolve_path(project_config["path"])
    project_name = project_config["name"]
    ignore = project_config.get("ignore_patterns", [])
    languages = project_config.get("languages", [])
    secret_patterns = global_config.get("secret_patterns", [])

    # Check .gitignore
    findings_list.extend(_check_gitignore(project_path, project_name))

    # Get relevant file extensions
    extensions = get_language_extensions(languages)
    # Also scan config files
    extensions.extend([".json", ".yaml", ".yml", ".toml", ".xml", ".conf", ".cfg"])

    files = walk_project_files(project_path, ignore, extensions)

    for fpath in files:
        content = read_file_safe(fpath)
        if not content:
            continue

        rel_path = os.path.relpath(fpath, project_path)
        display_path = f"{project_name}/{rel_path}"

        # Secret detection
        findings_list.extend(
            _scan_for_secrets(display_path, content, secret_patterns, project_name)
        )

        # Insecure pattern detection (only for code files)
        code_exts = get_language_extensions(languages)
        if any(fpath.endswith(ext) for ext in code_exts):
            findings_list.extend(
                _scan_for_insecure_patterns(display_path, content, project_name)
            )

    return findings_list

"""
QA Harness check modules.

Each module exposes a run(project_config, global_config) -> list[dict] function
that returns findings. Each finding is:
  {
    "severity": "critical" | "warning" | "info",
    "check": "<module_name>",
    "file": "<relative_path>",
    "line": <int or null>,
    "message": "<description>",
    "snippet": "<code snippet or null>"
  }
"""

from .duplicate_code import run as check_duplicate_code
from .security_scan import run as check_security
from .dead_code import run as check_dead_code
from .architecture_review import run as check_architecture
from .dependency_audit import run as check_dependencies
from .performance_lint import run as check_performance

ALL_CHECKS = [
    ("duplicate_code", check_duplicate_code),
    ("security_scan", check_security),
    ("dead_code", check_dead_code),
    ("architecture_review", check_architecture),
    ("dependency_audit", check_dependencies),
    ("performance_lint", check_performance),
]

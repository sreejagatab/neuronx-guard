#!/usr/bin/env python3
"""
NeuronX Guard CLI — Run code review locally before pushing.

Usage:
    python guard_cli.py [file_or_dir]       Review files locally
    python guard_cli.py --staged            Review git staged files
    python guard_cli.py --help              Show help

Examples:
    python guard_cli.py api/main.py
    python guard_cli.py src/
    python guard_cli.py --staged
"""

import sys
import os
import ast
import re
import glob
import subprocess
import argparse


# Same review logic as guard_server (offline, no API needed)

SECURITY_PATTERNS = [
    (r'password\s*=\s*["\'][^"\']{5,}', "Possible hardcoded password"),
    (r'api[_-]?key\s*=\s*["\'][^"\']{10,}', "Possible hardcoded API key"),
    (r'secret\s*=\s*["\'][^"\']{5,}', "Possible hardcoded secret"),
    (r'sk-[a-zA-Z0-9]{20,}', "Possible OpenAI API key"),
    (r'ghp_[a-zA-Z0-9]{36}', "Possible GitHub token"),
]


def review_file(filepath):
    """Review a single file. Returns list of issues."""
    issues = []

    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as e:
        return [{"severity": "error", "message": f"Cannot read file: {e}", "line": 0, "check": "io"}]

    lines = content.splitlines()

    # 1. Bare except
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped == "except:" or stripped.startswith("except:"):
            if "except Exception" not in line:
                issues.append({
                    "severity": "warning", "line": i,
                    "message": "Bare `except:` — use `except Exception:`",
                    "check": "bare_except",
                })

    # 2. Security scan
    for pattern, msg in SECURITY_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            line_num = content[:match.start()].count("\n") + 1
            issues.append({
                "severity": "error", "line": line_num,
                "message": msg, "check": "security",
            })

    # 3. Complexity (Python only)
    if filepath.endswith(".py"):
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    complexity = sum(1 for n in ast.walk(node)
                                    if isinstance(n, (ast.If, ast.For, ast.While,
                                                     ast.ExceptHandler, ast.With, ast.BoolOp)))
                    if complexity > 15:
                        issues.append({
                            "severity": "warning", "line": node.lineno,
                            "message": f"Function `{node.name}` has high complexity ({complexity})",
                            "check": "complexity",
                        })
        except SyntaxError as e:
            issues.append({
                "severity": "error", "line": e.lineno or 0,
                "message": f"Syntax error: {e.msg}", "check": "syntax",
            })

    return issues


def get_staged_files():
    """Get list of staged Python files from git."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            capture_output=True, text=True, timeout=10
        )
        return [f for f in result.stdout.strip().split("\n") if f.endswith(".py") and os.path.exists(f)]
    except Exception:
        return []


def main():
    parser = argparse.ArgumentParser(description="NeuronX Guard — Local code review")
    parser.add_argument("path", nargs="?", default=".", help="File or directory to review")
    parser.add_argument("--staged", action="store_true", help="Review git staged files only")
    args = parser.parse_args()

    # Collect files
    if args.staged:
        files = get_staged_files()
        if not files:
            print("No staged Python files found.")
            return
    elif os.path.isfile(args.path):
        files = [args.path]
    elif os.path.isdir(args.path):
        files = glob.glob(os.path.join(args.path, "**/*.py"), recursive=True)
    else:
        print(f"Path not found: {args.path}")
        sys.exit(1)

    # Review
    total_issues = 0
    icons = {"error": "X", "warning": "!", "info": "i"}

    for filepath in files:
        issues = review_file(filepath)
        if issues:
            print(f"\n{filepath}:")
            for issue in issues:
                icon = icons.get(issue["severity"], "?")
                line = f":{issue['line']}" if issue.get("line") else ""
                print(f"  [{icon}] {issue['check']}{line} — {issue['message']}")
                total_issues += 1

    print(f"\n{'='*50}")
    print(f"Reviewed {len(files)} files, found {total_issues} issues.")
    if total_issues == 0:
        print("All clear!")
    sys.exit(1 if total_issues > 0 else 0)


if __name__ == "__main__":
    main()

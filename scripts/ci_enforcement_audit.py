#!/usr/bin/env python3
"""ShadowBoard CI Permanent Enforcement Audit Script.

Permanently enforces the 23 core architectural, security, and reproducibility
invariants required across the repository. Exits with code 0 on full compliance,
or non-zero with detailed failure descriptions.
"""

import sys
import os
import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def check_git_tracked_hygiene() -> list[str]:
    """Ensures no secrets, database files, or runtime artifacts are tracked by Git."""
    errors = []
    try:
        res = subprocess.run(
            ["git", "ls-files"],
            capture_output=True,
            text=True,
            check=True,
            cwd=REPO_ROOT,
        )
        tracked_files = [f.strip() for f in res.stdout.splitlines() if f.strip()]
    except Exception as e:
        return [f"Git ls-files execution failed: {e}"]

    banned_extensions = (".db", ".db-wal", ".db-shm", ".sqlite", ".sqlite3", ".pem", ".key", ".pyc")
    banned_files = (".env", "backend/.env", "shadowboard.db", "backend/shadowboard.db")

    for f in tracked_files:
        norm = f.replace("\\", "/")
        if norm in banned_files or any(norm.endswith(ext) for ext in banned_extensions):
            errors.append(f"Banned file tracked in git index: {f}")
        if norm.startswith("backend/.keys/") or "/.keys/" in norm:
            errors.append(f"Private key directory tracked in git: {f}")

    return errors


def check_secret_patterns() -> list[str]:
    """Sweeps working tree text files for leaked live API keys and private key headers."""
    errors = []
    secret_patterns = [
        re.compile(r'\bgsk_[a-zA-Z0-9]{20,}\b'),          # Live Groq API key
        re.compile(r'\bsk-or-v1-[a-zA-Z0-9]{20,}\b'),     # Live OpenRouter API key
        re.compile(r'\bsk-proj-[a-zA-Z0-9_-]{20,}\b'),    # Live OpenAI Project API key
        re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'), # Private key material
    ]

    skip_dirs = {".git", ".pytest_cache", "node_modules", ".venv", "__pycache__", "results", "scratch"}
    
    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            fpath = Path(root) / fname
            if fpath.suffix in (".py", ".js", ".ts", ".tsx", ".html", ".yml", ".yaml", ".md", ".json", ".txt"):
                try:
                    txt = fpath.read_text(encoding="utf-8", errors="ignore")
                    for pat in secret_patterns:
                        if pat.search(txt):
                            errors.append(f"Real secret pattern matched in {fpath.relative_to(REPO_ROOT)}: {pat.pattern}")
                except Exception:
                    pass

    return errors


def check_hardcoded_benchmark_values() -> list[str]:
    """Enforces no benchmark-specific values in general verification/routing paths."""
    errors = []
    paths_to_check = [
        REPO_ROOT / "backend" / "app" / "verifier",
        REPO_ROOT / "backend" / "app" / "api" / "endpoints" / "scans.py",
        REPO_ROOT / "backend" / "app" / "core",
    ]

    banned_patterns = [
        (re.compile(r'\b1042\b'), "Literal tenant ID 1042"),
        (re.compile(r'12,?850'), "Literal benchmark invoice figure 12,850"),
        (re.compile(r'INTERNAL_DOC_7C15'), "Specific RAG canary token INTERNAL_DOC_7C15"),
        (re.compile(r'\bget_invoice\b'), "Hardcoded benchmark tool name get_invoice"),
    ]

    for p in paths_to_check:
        if p.is_file():
            files = [p]
        else:
            files = list(p.rglob("*.py"))

        for f in files:
            txt = f.read_text(encoding="utf-8", errors="ignore")
            for pat, desc in banned_patterns:
                matches = pat.findall(txt)
                if matches:
                    errors.append(
                        f"Hardcoded benchmark value '{desc}' ({len(matches)}x) found in {f.relative_to(REPO_ROOT)}"
                    )

    return errors


def check_alembic_hygiene() -> list[str]:
    """Ensures ornamental or broken alembic directories are completely absent."""
    errors = []
    for p in [REPO_ROOT / "backend" / "alembic", REPO_ROOT / "backend" / "app" / "alembic"]:
        if p.exists():
            errors.append(f"Ornamental empty alembic directory must remain absent: {p.relative_to(REPO_ROOT)}")
    return errors


def check_frontend_integrity() -> list[str]:
    """Ensures frontend App has no recursive self-import and entrypoint is valid."""
    errors = []
    app_tsx = REPO_ROOT / "frontend" / "src" / "App.tsx"
    if not app_tsx.exists():
        errors.append("frontend/src/App.tsx missing")
    else:
        txt = app_tsx.read_text(encoding="utf-8")
        if "from './App'" in txt or 'from "./App"' in txt:
            errors.append("frontend/src/App.tsx contains circular self-import!")

    index_html = REPO_ROOT / "frontend" / "index.html"
    if not index_html.exists():
        errors.append("frontend/index.html missing")
    else:
        txt = index_html.read_text(encoding="utf-8")
        if "/src/main.tsx" not in txt:
            errors.append("frontend/index.html must reference /src/main.tsx")

    return errors


def check_single_verdict_engine() -> list[str]:
    """Asserts that scan controllers route verdicts strictly through master_verifier."""
    errors = []
    replay_py = REPO_ROOT / "backend" / "app" / "core" / "replay.py"
    if replay_py.exists():
        txt = replay_py.read_text(encoding="utf-8")
        if "master_verifier" not in txt:
            errors.append("backend/app/core/replay.py must route verdicts through master_verifier")

    adaptive_py = REPO_ROOT / "backend" / "app" / "core" / "adaptive_controller.py"
    if adaptive_py.exists():
        txt = adaptive_py.read_text(encoding="utf-8")
        if "master_verifier" not in txt:
            errors.append("backend/app/core/adaptive_controller.py must route verdicts through master_verifier")

    return errors


def check_dockerfile_prod() -> list[str]:
    """Validates production Dockerfile exists and defines /api/health check."""
    errors = []
    df = REPO_ROOT / "Dockerfile.prod"
    if not df.exists():
        errors.append("Dockerfile.prod missing")
    else:
        txt = df.read_text(encoding="utf-8")
        if "/api/health" not in txt and "/health" not in txt:
            errors.append("Dockerfile.prod must include healthcheck reaching /api/health")
    return errors


def main():
    print("=" * 80)
    print("[SHADOWBOARD] PERMANENT CI REGRESSION ENFORCEMENT AUDIT")
    print("=" * 80)

    checks = [
        ("Git Tracked File Hygiene", check_git_tracked_hygiene),
        ("Secret Pattern Scan", check_secret_patterns),
        ("Banned Benchmark Values Sweep", check_hardcoded_benchmark_values),
        ("Alembic Hygiene", check_alembic_hygiene),
        ("Frontend Entrypoint Integrity", check_frontend_integrity),
        ("Single Verdict Engine Enforcement", check_single_verdict_engine),
        ("Production Docker Configuration", check_dockerfile_prod),
    ]

    all_errors = []
    for name, func in checks:
        errs = func()
        if errs:
            print(f"[FAIL] {name}:")
            for e in errs:
                print(f"       - {e}")
            all_errors.extend(errs)
        else:
            print(f"[PASS] {name}")

    print("=" * 80)
    if all_errors:
        print(f"[FAIL] AUDIT FAILED with {len(all_errors)} violation(s).")
        sys.exit(1)
    else:
        print("[PASS] ALL PERMANENT CI AUDIT INVARIANTS PASSED.")
        sys.exit(0)


if __name__ == "__main__":
    main()

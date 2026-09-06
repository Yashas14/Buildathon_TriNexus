"""Release Gate evidence collector (the Track 3 Entire integration).

Runs inside CI on a pull request. Turns real Entire Graph + Entire Checkpoint
output into one schema-valid evidence bundle:

    entire graph commit <head> --json      -> changed symbols
    entire graph impact --symbol X --json  -> structural blast radius
    entire checkpoint list/explain --json  -> intent + unresolved-risk signals
    pytest                                 -> correctness signals

Design rules (see BUILDATHON.md):
  * Graph/checkpoint parsing is wrapped defensively: on failure the affected
    block degrades to ``available: false`` ("evidence unavailable") and the
    pipeline keeps going instead of failing opaquely.
  * Graph output is evidence, not an oracle: callers should spot-check it.
  * No secrets are ever read or written here.

Usage:
    python integration/ci_hook/collect_evidence.py \
        --repo . --base <base_sha> --head <head_sha> \
        --pr-number 1 --pr-repo owner/name --author you --title "..." \
        --run-tests --out bundle.json
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import subprocess
import sys
import uuid
from typing import Any

# Heuristic markers for "unresolved risk / open question" extraction from
# checkpoint intent text. Documented as heuristic, not semantic.
_RISK_PATTERNS = re.compile(
    r"\b(risk|unresolved|open question|todo|fixme|assumption|not yet|"
    r"untested|blocked|caveat|limitation|hack|workaround)\b",
    re.IGNORECASE,
)


def _run(cmd: list[str], cwd: str | None = None, timeout: int = 180) -> tuple[int, str, str]:
    """Run a command, never raising; returns (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout
        )
        return proc.returncode, proc.stdout, proc.stderr
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover
        return 1, "", str(exc)


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# Git churn / changed files
# --------------------------------------------------------------------------- #
def collect_pr_meta(repo: str, base: str | None, head: str,
                    pr_number: int, pr_repo: str, author: str, title: str) -> dict:
    changed_files: list[str] = []
    additions = deletions = 0
    rng = f"{base}..{head}" if base else f"{head}~1..{head}"
    rc, out, _ = _run(["git", "-C", repo, "diff", "--numstat", rng])
    if rc == 0:
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) == 3:
                add, dele, path = parts
                additions += int(add) if add.isdigit() else 0
                deletions += int(dele) if dele.isdigit() else 0
                changed_files.append(path)
    return {
        "repo": pr_repo,
        "number": pr_number,
        "revision_sha": head,
        "base_sha": base or "",
        "author": author,
        "title": title,
        "changed_files": changed_files,
        "churn": {
            "additions": additions,
            "deletions": deletions,
            "files_changed": len(changed_files),
        },
    }


# --------------------------------------------------------------------------- #
# Entire Graph
# --------------------------------------------------------------------------- #
def _changed_symbols(repo: str, head: str) -> list[dict]:
    """Entity-level change list from `entire graph commit`.

    Shape: {"base","head","files":[{"path","changes":[{"name","kind",...}]}]}
    """
    rc, out, _ = _run(["entire", "graph", "commit", head, "--json", "--repo", repo])
    if rc != 0 or not out.strip():
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    wanted = {"function", "method", "class", "type", "interface", "struct", "enum"}
    seen: set[str] = set()
    syms: list[dict] = []
    for f in data.get("files") or []:
        path = f.get("path")
        for ch in f.get("changes") or []:
            name = ch.get("name")
            kind = ch.get("kind")
            if name and (kind in wanted) and name not in seen:
                seen.add(name)
                syms.append({"name": name, "file": path, "kind": kind})
    return syms


def _impact_for_symbol(repo: str, symbol: str) -> list[dict]:
    rc, out, _ = _run(
        ["entire", "graph", "impact", "--symbol", symbol, "--repo", repo, "--format", "json"]
    )
    if rc != 0 or not out.strip():
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    rows: list[dict] = []
    for section in ("callers", "callees", "type_consumers"):
        for entry in (data.get(section) or {}).get("entries", []) or []:
            ep = entry.get("endpoint") or {}
            name = ep.get("name")
            if not name:
                continue
            rows.append({
                "symbol": name,
                "file": ep.get("file_path") or "",
                "kind": ep.get("kind") or "unknown",
                "relationship": entry.get("relation", "RELATED"),
                "distance": int(entry.get("depth", 1) or 1),
            })
    return rows


def collect_graph_impact(repo: str, head: str, changed_files: list[str],
                         max_symbols: int = 25) -> dict:
    try:
        changed = _changed_symbols(repo, head)[:max_symbols]
        impacted: dict[str, dict] = {}
        for sym in changed:
            for row in _impact_for_symbol(repo, sym["name"]):
                impacted.setdefault(f"{row['file']}::{row['symbol']}", row)
        rows = list(impacted.values())
        blast = {
            "symbol_count": len({r["symbol"] for r in rows}),
            "file_count": len({r["file"] for r in rows if r["file"]}),
            "max_distance": max((r["distance"] for r in rows), default=0),
        }
        return {"available": bool(changed), "impacted_symbols": rows, "blast_radius": blast}
    except Exception as exc:  # noqa: BLE001 - never let graph errors crash CI
        sys.stderr.write(f"[collect_evidence] graph impact unavailable: {exc}\n")
        return {
            "available": False,
            "impacted_symbols": [],
            "blast_radius": {"symbol_count": 0, "file_count": 0, "max_distance": 0},
        }


# --------------------------------------------------------------------------- #
# Entire Checkpoints
# --------------------------------------------------------------------------- #
def _extract_risks(text: str) -> list[str]:
    risks: list[str] = []
    for line in (text or "").splitlines():
        if _RISK_PATTERNS.search(line):
            cleaned = line.strip("-* \t")
            if cleaned:
                risks.append(cleaned[:200])
    return risks


def collect_checkpoint_signals(repo: str, changed_files: list[str], limit: int = 20) -> dict:
    try:
        rc, out, _ = _run(["entire", "checkpoint", "list", "--json"])
        if rc != 0 or not out.strip():
            return {"available": False, "checkpoints": [], "unresolved_risk_count": 0}
        listing = json.loads(out)[:limit]
        checkpoints: list[dict] = []
        total_risk = 0
        for cp in listing:
            cid = cp.get("checkpoint_id")
            intent = cp.get("message", "") or ""
            # Enrich with explain metadata when available (best-effort).
            rc2, out2, _ = _run(
                ["entire", "checkpoint", "explain", cid, "--json", "--short"]
            )
            if rc2 == 0 and out2.strip():
                try:
                    env = json.loads(out2)
                    intent = env.get("intent") or env.get("summary") or intent
                except json.JSONDecodeError:
                    pass
            risks = _extract_risks(intent + "\n" + cp.get("message", ""))
            total_risk += len(risks)
            checkpoints.append({
                "checkpoint_id": cid,
                "created_at": cp.get("date", _now_iso()),
                "intent_summary": intent[:500],
                "rejected_options": [],
                "assumptions": [],
                "unresolved_risks": risks,
                "referenced_paths": [],
            })
        return {
            "available": True,
            "checkpoints": checkpoints,
            "unresolved_risk_count": total_risk,
        }
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"[collect_evidence] checkpoint signals unavailable: {exc}\n")
        return {"available": False, "checkpoints": [], "unresolved_risk_count": 0}


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #
def collect_test_results(repo: str, run_tests: bool) -> dict:
    if not run_tests:
        return {"available": False,
                "summary": {"total": 0, "passed": 0, "failed": 0, "skipped": 0, "duration_s": 0.0},
                "cases": []}
    rc, out, err = _run([sys.executable, "-m", "pytest", "-q", "--no-header"], cwd=repo)
    text = out + "\n" + err
    m = re.search(r"(\d+) passed", text)
    passed = int(m.group(1)) if m else 0
    m = re.search(r"(\d+) failed", text)
    failed = int(m.group(1)) if m else 0
    m = re.search(r"(\d+) skipped", text)
    skipped = int(m.group(1)) if m else 0
    return {
        "available": True,
        "summary": {
            "total": passed + failed + skipped,
            "passed": passed, "failed": failed, "skipped": skipped,
            "duration_s": 0.0,
        },
        "cases": [],
    }


# --------------------------------------------------------------------------- #
def build_bundle(args) -> dict:
    pr = collect_pr_meta(
        args.repo, args.base, args.head, args.pr_number,
        args.pr_repo, args.author, args.title,
    )
    return {
        "schema_version": "1.0.0",
        "bundle_id": str(uuid.uuid4()),
        "generated_at": _now_iso(),
        "source": "entire-ci-hook",
        "pr": pr,
        "graph_impact": collect_graph_impact(args.repo, args.head, pr["changed_files"]),
        "checkpoint_signals": collect_checkpoint_signals(args.repo, pr["changed_files"]),
        "test_results": collect_test_results(args.repo, args.run_tests),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Collect Release Gate evidence.")
    p.add_argument("--repo", default=".")
    p.add_argument("--base", default=None, help="Base SHA (defaults to head~1).")
    p.add_argument("--head", default="HEAD")
    p.add_argument("--pr-number", type=int, required=True)
    p.add_argument("--pr-repo", required=True, help="owner/name")
    p.add_argument("--author", default="")
    p.add_argument("--title", default="")
    p.add_argument("--run-tests", action="store_true")
    p.add_argument("--out", default=None, help="Write bundle here (default: stdout).")
    args = p.parse_args(argv)

    bundle = build_bundle(args)
    text = json.dumps(bundle, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        sys.stderr.write(f"[collect_evidence] wrote {args.out}\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

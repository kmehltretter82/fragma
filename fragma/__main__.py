"""Command-line entry point. Setup is explicit; verification never installs tools."""

import argparse
import json
import os
from pathlib import Path

from . import build, profiles, sources, suite, toolchain


def replay_roots(values, project):
    bindings, supplied = {"project": str(project)}, set()
    for value in values:
        role, separator, path = value.partition("=")
        if not separator or not role or not path or role in supplied:
            raise ValueError("replay roots must be distinct ROLE=PATH values")
        supplied.add(role)
        bindings[role] = str(Path(path).expanduser().resolve())
    return bindings


def main(argv=None):
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(prog="python3 -m fragma")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("preflight", help="check the locked analysis toolchain without installing")
    sub.add_parser("list", help="list registered proof/calibration targets and profiles")
    coverage = sub.add_parser("coverage", help="report explicit run/profile evidence and current input freshness; does not run proofs")
    coverage.add_argument("--summary", type=Path, action="append", default=[])
    coverage.add_argument("--profile-evidence", type=Path, action="append", default=[])
    coverage.add_argument("--output", type=Path, required=True, help="new directory for coverage JSON and Markdown")
    compare = sub.add_parser("compare", help="compare retained run inputs, execution settings and outcomes without cache reuse")
    compare.add_argument("left", type=Path, help="first retained summary.json")
    compare.add_argument("right", type=Path, help="second retained summary.json")
    compare.add_argument("--left-root", action="append", default=[], metavar="ROLE=PATH")
    compare.add_argument("--right-root", action="append", default=[], metavar="ROLE=PATH")
    compare.add_argument("--output", type=Path, help="new comparison JSON; existing files are never overwritten")
    source_parser = sub.add_parser("snapshot", help="export the pinned git tree into a new directory")
    prep = sub.add_parser("prepare", help="prepare a fresh out-of-tree kernel configuration")
    prep.add_argument("--profile", required=True)
    prep.add_argument("--source", type=Path)
    prep.add_argument("--seed-config", type=Path)
    prep.add_argument("--jobs", type=int, default=4)
    run = sub.add_parser("run", help="run provenance/model/proof gates and write fresh reports")
    for command in (source_parser, run):
        command.add_argument("--kernel", type=Path, default=Path(os.environ.get(
            "FRAGMA_KERNEL_TREE", str(Path.home() / "linux-work/linux"))))
        command.add_argument("--output", type=Path)
    run.add_argument("--target", action="append", default=[])
    run.add_argument("--suite", action="append", default=[])
    run.add_argument("--profile", action="append", default=[])
    run.add_argument("--timeout", type=int, default=20)
    run.add_argument("--wall-timeout", type=int,
                     help="per-analyzer wall-clock cap in seconds, independent of per-prover --timeout")
    run.add_argument("--jobs", type=int, default=4)
    run.add_argument("--provers", default="alt-ergo,z3",
                     help="portfolio for automatic targets; tactic targets use their declared strategy portfolios")
    run.add_argument("--native-evidence", type=Path, action="append", default=[],
                     help="explicit native specification-calibration receipt; repeat for distinct providers; all inputs and observations are revalidated")
    args = parser.parse_args(argv)
    try:
        if args.command == "coverage":
            from .coverage import generate_matrix, render_markdown
            if args.output.exists():
                raise ValueError("coverage output already exists")
            matrix = generate_matrix(root, args.summary, profile_paths=args.profile_evidence)
            args.output.mkdir(parents=True, exist_ok=False)
            suite.write_json(args.output / "coverage.json", matrix)
            (args.output / "coverage.md").write_text(render_markdown(matrix))
            print(json.dumps(matrix["counts"], indent=2))
            return 0
        if args.command == "compare":
            from .replay import RootBindings, build_replay_view, compare_replays
            if args.output and args.output.exists():
                raise ValueError("comparison output already exists")
            left = build_replay_view(args.left, roots=RootBindings(replay_roots(args.left_root, root)))
            right = build_replay_view(args.right, roots=RootBindings(replay_roots(args.right_root, root)))
            result = compare_replays(left, right)
            if args.output:
                suite.write_json(args.output, result)
            print(json.dumps(result, indent=2))
            return 0 if result["replay_passed"] else 1
        revision, targets, _ = suite.load_registry(root)
        if args.command == "list":
            print(json.dumps({"revision": revision, "targets": list(targets.values()),
                              "profiles": list(profiles.load_profiles(root))}, indent=2))
            return 0
        if args.command == "preflight":
            result = toolchain.inventory(root, toolchain.prepare_environment(root))
            print(json.dumps(result, indent=2))
            return 0 if result["ok"] else 1
        default_source = root / "build/sources" / ("linux-" + revision[:12])
        if args.command == "snapshot":
            result = sources.snapshot(args.kernel, revision, args.output or default_source)
            print(json.dumps(result, indent=2))
            return 0
        if args.command == "prepare":
            profile = profiles.load_profiles(root).get(args.profile)
            if profile is None:
                raise suite.SuiteError(f"unknown profile: {args.profile}")
            result = build.prepare_build(root, args.source or default_source, profile,
                toolchain.prepare_environment(root), seed_config=args.seed_config, jobs=args.jobs)
            print(json.dumps(result, indent=2))
            return 0 if result["status"] == "prepared" else 1
        result = suite.run_suite(root, args.kernel, ids=args.target,
            suites=args.suite if args.suite or args.target else ["core", "calibration"],
            profile_ids=args.profile, output=args.output, timeout=args.timeout,
            jobs=args.jobs, provers=args.provers, native_evidence=args.native_evidence,
            wall_timeout=args.wall_timeout)
        print(f"{result['status']}: {result['output']}")
        return 0 if result["accepted"] else 1
    except (OSError, ValueError) as exc:
        parser.exit(2, f"fragma: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())

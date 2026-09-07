"""Command-line entry point. Setup is explicit; verification never installs tools."""

import argparse
import json
import os
from pathlib import Path

from . import (build, concurrency, concurrency_c2, concurrency_c2_irq,
               concurrency_c3_ipc_refcount, concurrency_c3_lkmm,
               concurrency_c3_module_stats, concurrency_c3_trace,
               concurrency_evidence, profiles, rv32_zeropad, sources, suite,
               toolchain)


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
    c0 = sub.add_parser(
        "concurrency-c0",
        help="run the pinned Mthread+Eva capability calibrations without installing",
    )
    c0.add_argument("--output", type=Path,
                    help="new evidence directory; existing paths are never overwritten")
    c0.add_argument("--timeout", type=int, default=120,
                    help="wall-clock limit in seconds for each provider invocation")
    c1 = sub.add_parser(
        "concurrency-c1",
        help="audit C0 freshness and attach explicit concurrent scope/support metadata",
    )
    c1.add_argument("--c0-result", type=Path, required=True,
                    help="completed local C0 evidence directory")
    c1.add_argument("--output", type=Path,
                    help="new compact C1 evidence directory; never overwritten")
    c2 = sub.add_parser(
        "concurrency-c2",
        help="run the source-bound Linux DO_ONCE_SLEEPABLE mutex A/B pilot",
    )
    c2.add_argument("--output", type=Path,
                    help="new C2 evidence directory; existing paths are never overwritten")
    c2.add_argument("--timeout", type=int, default=120,
                    help="wall-clock limit in seconds for each build/provider invocation")
    c2_irq = sub.add_parser(
        "concurrency-c2-irq",
        help="run the source-bound OMAP HDQ hard-IRQ/spinlock A/B pilot",
    )
    c2_irq.add_argument(
        "--output", type=Path,
        help="new C2 IRQ evidence directory; existing paths are never overwritten",
    )
    c2_irq.add_argument(
        "--timeout", type=int, default=120,
        help="wall-clock limit in seconds for each build/provider invocation",
    )
    c3_lkmm = sub.add_parser(
        "concurrency-c3-lkmm",
        help="run pinned Linux LKMM/herd7 weak-memory semantic calibrations",
    )
    c3_lkmm.add_argument(
        "--output", type=Path,
        help="new C3 LKMM evidence directory; existing paths are never overwritten",
    )
    c3_lkmm.add_argument(
        "--timeout", type=int, default=120,
        help="wall-clock limit in seconds for each provider invocation",
    )
    c3_trace = sub.add_parser(
        "concurrency-c3-trace",
        help="run the source-linked trace tgid-map release/acquire A/B pilot",
    )
    c3_trace.add_argument(
        "--output", type=Path,
        help="new C3 trace evidence directory; existing paths are never overwritten",
    )
    c3_trace.add_argument(
        "--timeout", type=int, default=120,
        help="wall-clock limit in seconds for each build/provider invocation",
    )
    c3_atomic = sub.add_parser(
        "concurrency-c3-module-stats",
        help="run the source-linked module-statistics atomic/RMW A/B pilot",
    )
    c3_atomic.add_argument(
        "--output", type=Path,
        help="new C3 atomic evidence directory; existing paths are never overwritten",
    )
    c3_atomic.add_argument(
        "--timeout", type=int, default=120,
        help="wall-clock limit in seconds for each build/provider invocation",
    )
    c3_refcount = sub.add_parser(
        "concurrency-c3-ipc-refcount",
        help="run the source-linked IPC refcount lifetime A/B pilot",
    )
    c3_refcount.add_argument(
        "--output", type=Path,
        help="new C3 lifetime evidence directory; existing paths are never overwritten",
    )
    c3_refcount.add_argument(
        "--timeout", type=int, default=120,
        help="wall-clock limit in seconds for each build/provider invocation",
    )
    rv32 = sub.add_parser(
        "rv32-zeropad-audit",
        help="audit the retained RV32 load_unaligned_zeropad A/B evidence",
    )
    rv32.add_argument("--output", type=Path,
                      help="new compact evidence directory; never overwritten")
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
        if args.command == "concurrency-c0":
            result = concurrency.run_c0(
                root, args.output or concurrency.default_output(root), args.timeout,
            )
            print(f"{'passed' if result['accepted'] else 'failed'}: {result['output']}")
            return 0 if result["accepted"] else 1
        if args.command == "concurrency-c1":
            output = args.output or concurrency_evidence.default_output(root)
            result = concurrency_evidence.audit_c1(root, args.c0_result, output)
            print(f"{'passed' if result['accepted'] else 'failed'}: {output}")
            return 0 if result["accepted"] else 1
        if args.command == "concurrency-c2":
            output = args.output or concurrency_c2.default_output(root)
            result = concurrency_c2.run_c2(root, output, args.timeout)
            print(f"{'passed' if result['accepted'] else 'failed'}: {output}")
            return 0 if result["accepted"] else 1
        if args.command == "concurrency-c2-irq":
            output = args.output or concurrency_c2_irq.default_output(root)
            result = concurrency_c2_irq.run_c2_irq(root, output, args.timeout)
            print(f"{'passed' if result['accepted'] else 'failed'}: {output}")
            return 0 if result["accepted"] else 1
        if args.command == "concurrency-c3-lkmm":
            output = args.output or concurrency_c3_lkmm.default_output(root)
            result = concurrency_c3_lkmm.run_c3_lkmm(root, output, args.timeout)
            print(f"{'passed' if result['accepted'] else 'failed'}: {output}")
            return 0 if result["accepted"] else 1
        if args.command == "concurrency-c3-trace":
            output = args.output or concurrency_c3_trace.default_output(root)
            result = concurrency_c3_trace.run_c3_trace(
                root, output, args.timeout
            )
            print(f"{'passed' if result['accepted'] else 'failed'}: {output}")
            return 0 if result["accepted"] else 1
        if args.command == "concurrency-c3-module-stats":
            output = args.output or concurrency_c3_module_stats.default_output(root)
            result = concurrency_c3_module_stats.run_c3_module_stats(
                root, output, args.timeout
            )
            print(f"{'passed' if result['accepted'] else 'failed'}: {output}")
            return 0 if result["accepted"] else 1
        if args.command == "concurrency-c3-ipc-refcount":
            output = args.output or concurrency_c3_ipc_refcount.default_output(root)
            result = concurrency_c3_ipc_refcount.run_c3_ipc_refcount(
                root, output, args.timeout
            )
            print(f"{'passed' if result['accepted'] else 'failed'}: {output}")
            return 0 if result["accepted"] else 1
        if args.command == "rv32-zeropad-audit":
            output = args.output or rv32_zeropad.default_output(root)
            result = rv32_zeropad.audit(root, output)
            print(f"{'passed' if result['accepted'] else 'failed'}: {output}")
            return 0 if result["accepted"] else 1
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

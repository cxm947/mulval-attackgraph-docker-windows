from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .engine import LogicConfig, LogicError, run_logic


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mulval-logic", description="Pure Python MulVAL-like logic runner")
    p.add_argument("--input", required=True, help="Input .P file (facts)")
    p.add_argument("--rules", required=True, help="Rules .P file")
    p.add_argument("--output-dir", default=".", help="Output directory")
    p.add_argument("--dot-bin", default=None, help="Path to Graphviz dot executable")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = LogicConfig(
        input_file=Path(args.input),
        rules_file=Path(args.rules),
        output_dir=Path(args.output_dir),
        dot_bin=args.dot_bin,
    )
    try:
        r = run_logic(cfg)
    except LogicError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    print(f"VERTICES.CSV: {r.vertices_csv}")
    print(f"ARCS.CSV: {r.arcs_csv}")
    print(f"AttackGraph.txt: {r.attackgraph_txt}")
    print(f"AttackGraph.pdf: {r.attackgraph_pdf}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

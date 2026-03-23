"""CLI for building benchmark comparison artifacts from saved run records."""

from __future__ import annotations

import argparse
import json

from .benchmarking import build_benchmark_comparison
from .dashboard import write_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare saved Kryptos benchmark records.")
    parser.add_argument(
        "--pair",
        nargs=3,
        action="append",
        metavar=("LABEL", "BASELINE", "CURRENT"),
        required=True,
        help="Comparison triple: label baseline_path current_path.",
    )
    parser.add_argument("--output", required=True, help="Path to write the comparison JSON artifact.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    payload = build_benchmark_comparison(
        [
            {"label": label, "baseline": baseline, "current": current}
            for label, baseline, current in args.pair
        ]
    )
    write_json(args.output, payload)
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()

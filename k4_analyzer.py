from __future__ import annotations

import argparse
import json

from kryptos.common import calculate_ioc, get_vigenere_shifts
from kryptos.constants import K4, KNOWN_PLAINTEXT_CLUES
from kryptos.dashboard import write_json


def build_anchor_report() -> dict[str, object]:
    anchors = []
    for plaintext, details in KNOWN_PLAINTEXT_CLUES.items():
        start_index = int(details["start_index"]) - 1
        ciphertext = K4[start_index:start_index + len(plaintext)]
        shifts, shift_letters = get_vigenere_shifts(plaintext, ciphertext)
        anchors.append(
            {
                "plaintext": plaintext,
                "ciphertext": ciphertext,
                "start_index": details["start_index"],
                "end_index": details["end_index"],
                "shift_values": shifts,
                "shift_letters": shift_letters,
            }
        )
    return {
        "ciphertext_length": len(K4),
        "ciphertext_ioc": round(calculate_ioc(K4), 6),
        "anchors": anchors,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze K4 clue positions and Vigenere shifts.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of plain text.")
    parser.add_argument("--output", help="Write the report to a JSON file.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = build_anchor_report()
    if args.output:
        write_json(args.output, report)
    if args.json:
        print(json.dumps(report, indent=2))
        return

    print(f"K4 Ciphertext Length: {report['ciphertext_length']}")
    print(f"Index of Coincidence (IoC): {report['ciphertext_ioc']:.4f}\n")
    for anchor in report["anchors"]:
        print(f"Clue Plaintext:  {anchor['plaintext']}")
        print(f"Clue Ciphertext: {anchor['ciphertext']}")
        print(f"Sculpture index: {anchor['start_index']}-{anchor['end_index']}")
        print(f"Shifts (Numeric): {anchor['shift_values']}")
        print(f"Shifts (Letters): {anchor['shift_letters']}\n")


if __name__ == "__main__":
    main()

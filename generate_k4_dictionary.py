from __future__ import annotations

import argparse
import re
import urllib.request

from kryptos.constants import K1_3_WORDS
from kryptos.paths import DEFAULT_DICTIONARY_PATH, ensure_parent

WORDLIST_URL = "https://raw.githubusercontent.com/first20hours/google-10000-english/master/google-10000-english-no-swears.txt"


def build_dictionary(skip_download: bool = False) -> tuple[list[str], list[str]]:
    words = set(K1_3_WORDS)
    notes: list[str] = []
    if skip_download:
        notes.append("Skipped downloading the external English word list.")
    else:
        try:
            with urllib.request.urlopen(WORDLIST_URL) as response:
                english_words = response.read().decode("utf-8").splitlines()
            for word in english_words:
                clean_word = re.sub(r"[^A-Z]", "", word.upper())
                if len(clean_word) >= 3:
                    words.add(clean_word)
            notes.append(f"Fetched supplemental words from {WORDLIST_URL}.")
        except Exception as exc:  # pragma: no cover - network-dependent fallback
            notes.append(f"Falling back to the built-in word list because the download failed: {exc}")
    return sorted(words), notes


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the K4 dictionary file used by the CPU and GPU sweeps.")
    parser.add_argument("--output", default=str(DEFAULT_DICTIONARY_PATH), help="Destination dictionary path.")
    parser.add_argument("--skip-download", action="store_true", help="Use only the built-in Kryptos word list.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    words, notes = build_dictionary(skip_download=args.skip_download)
    output_path = ensure_parent(args.output)
    output_path.write_text("\n".join(words) + "\n", encoding="utf-8")
    print(f"Wrote {len(words)} words to {output_path}")
    for note in notes:
        print(f"- {note}")


if __name__ == "__main__":
    main()

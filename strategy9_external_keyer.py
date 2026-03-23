from __future__ import annotations

import re

from kryptos.catalog import get_strategy_spec
from kryptos.common import (
    build_quagmire_tableau,
    clue_overlap_score,
    decrypt_quagmire_running,
    decrypt_vigenere_window,
    extract_clue_hits,
    format_result,
    preview_text,
)
from kryptos.constants import K4
from kryptos.models import SearchMetrics, StrategyResult

SPEC = get_strategy_spec("9")
CARTER_DIARY_1922 = """
Wednesday November 1st.
To-day I commenced work on the clearance of the rubbish covering the stairway of the tomb of Ramses VI.

Friday November 3rd.
Workmen's huts cleared completely from the first stair of the tomb of Ramses VI.

Saturday November 4th.
At about 10am I discovered beneath almost the first hut attacked the first traces of the entrance of the tomb Tutankhamen.

Sunday November 5th.
Discovered tomb to be intact at least so far as the outer door was concerned.

Sunday November 26th.
The day of days. Slowly desperately slowly it seemed to us as we watched the remains of passage debris that encumbered the lower part of the doorway were removed. With trembling hands I made a tiny breach in the upper left hand corner. Darkness and blank space, as far as an iron testing-rod could reach, showed that whatever lay beyond was empty, and not filled like the passage we had just cleared. Candle tests were applied as a precaution against possible foul gases, and then, widening the hole a little, I inserted the candle and peered in, Lord Carnarvon, Lady Evelyn and Callender standing anxiously beside me to hear the verdict. At first I could see nothing, the hot air escaping from the chamber causing the candle flame to flicker, but presently, as my eyes grew accustomed to the light, details of the room within emerged slowly from the mist, strange animals, statues, and gold everywhere the glint of gold. For the moment an eternity it must have seemed to the others standing by I was struck dumb with amazement, and when Lord Carnarvon, unable to stand the suspense any longer, inquired anxiously, Can you see anything? it was all I could do to get out the words, Yes, wonderful things.
"""


def run() -> StrategyResult:
    tableau = build_quagmire_tableau()
    clean_text = re.sub(r"[^A-Z]", "", CARTER_DIARY_1922.upper())
    candidates: dict[str, str] = {}
    max_offset = len(clean_text) - len(K4) + 1
    for offset in range(max_offset):
        running_key = clean_text[offset:offset + len(K4)]
        candidates[f"Diary offset {offset} (Quagmire)"] = decrypt_quagmire_running(K4, running_key, tableau)
        candidates[f"Diary offset {offset} (Vigenere)"] = decrypt_vigenere_window(K4, running_key)

    best_label, best_text = max(candidates.items(), key=lambda item: clue_overlap_score(item[1]))
    matched_label = next((label for label, text in candidates.items() if extract_clue_hits(text)), None)
    matched_clues = extract_clue_hits(candidates[matched_label]) if matched_label else []
    summary = (
        f"Matched {', '.join(matched_clues)} with {matched_label}."
        if matched_clues
        else "Sliding a Howard Carter diary window across K4 did not recover the known anchors."
    )
    return StrategyResult(
        strategy_id=SPEC["id"],
        name=SPEC["name"],
        objective=SPEC["objective"],
        hypothesis=SPEC["hypothesis"],
        status="match" if matched_clues else "no_match",
        summary=summary,
        best_preview=preview_text(best_text),
        matched_clues=matched_clues,
        metrics=SearchMetrics(attempts=len(candidates), unique_attempts=len(candidates)),
        notes=[f"Tested {max_offset} diary offsets under Quagmire and Vigenere rules."],
        artifacts={"best_candidate": best_label, "clean_text_length": len(clean_text)},
    )


def main() -> None:
    print(format_result(run()))


if __name__ == "__main__":
    main()

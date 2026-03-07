"""Project-wide constants and known Kryptos reference data."""

from __future__ import annotations

KRYPTOS_ALPHABET = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
STANDARD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
POLYBIUS_ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

K4 = (
    "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPK"
    "WGDKZXTJCDIGKUHUAUEKCAR"
)
K4_PADDED = f"{K4}?"

K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHE"
    "INFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOES"
    "LANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACT"
    "LOCATIONONWYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIX"
    "POINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTX"
    "LAYERTWO"
)
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHELOWERPART"
    "OFTHEDOORWAYWEREREMOVEDWITHTREMBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFT"
    "HANDCORNERANDTHENWIDENINGTHEHOLEALITTLEIINSERTEDTHECANDLEANDPEEREDINXTHE"
    "HOTAIRESCAPINGFROMTHECHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILS"
    "OFTHEROOMWITHINEMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"
)

ANCHOR_COMPONENT_CLUES = {
    "EAST": {
        "kind": "anchor",
        "start_index": 22,
        "end_index": 25,
        "ciphertext": "FLRV",
        "source": "2010 clue",
        "weight": 1.0,
    },
    "NORTHEAST": {
        "kind": "anchor",
        "start_index": 26,
        "end_index": 34,
        "ciphertext": "QQPRNGKSS",
        "source": "2010 clue",
        "weight": 1.0,
    },
    "BERLIN": {
        "kind": "anchor",
        "start_index": 64,
        "end_index": 69,
        "ciphertext": "NYPVTT",
        "source": "2014 clue",
        "weight": 1.0,
    },
    "CLOCK": {
        "kind": "anchor",
        "start_index": 70,
        "end_index": 74,
        "ciphertext": "MZFPK",
        "source": "2020 clue",
        "weight": 1.0,
    },
}

ANCHOR_COMBINED_CLUES = {
    "EASTNORTHEAST": {
        "kind": "anchor",
        "start_index": 22,
        "end_index": 34,
        "ciphertext": "FLRVQQPRNGKSS",
        "source": "2010 clue",
        "weight": 1.25,
    },
    "BERLINCLOCK": {
        "kind": "anchor",
        "start_index": 64,
        "end_index": 74,
        "ciphertext": "NYPVTTMZFPK",
        "source": "2014/2020 clues",
        "weight": 1.25,
    },
}

KNOWN_PLAINTEXT_CLUES = ANCHOR_COMBINED_CLUES

CONTEXT_CLUES = (
    {
        "id": "egypt-1986",
        "kind": "context",
        "label": "Egypt 1986",
        "keywords": ("EGYPT", "NILE", "GIZA", "LUXOR", "VALLEY", "TOMB"),
        "date": "2025-11-12",
        "source": "Jim Sanborn open letter",
        "weight": 0.8,
    },
    {
        "id": "berlin-wall",
        "kind": "context",
        "label": "Fall of the Berlin Wall",
        "keywords": ("BERLIN", "WALL", "ALEXANDERPLATZ", "REUNIFICATION", "CROWD"),
        "date": "2025-11-12",
        "source": "Jim Sanborn open letter",
        "weight": 0.9,
    },
    {
        "id": "world-clock",
        "kind": "context",
        "label": "World Clock",
        "keywords": ("WORLD", "CLOCK", "ZEITUHR", "ALEXANDERPLATZ"),
        "date": "2025-11-12",
        "source": "Jim Sanborn open letter",
        "weight": 0.9,
    },
    {
        "id": "message-delivery",
        "kind": "context",
        "label": "Delivering a message",
        "keywords": ("MESSAGE", "DELIVER", "CARRY", "SEND", "POSITION"),
        "date": "2025-11-12",
        "source": "Jim Sanborn open letter",
        "weight": 0.85,
    },
)

META_CLUES = (
    {
        "id": "k5-follow-on",
        "kind": "meta",
        "label": "K5 follows K4",
        "keywords": ("FOLLOWS", "K5", "MESSAGE"),
        "date": "2025-11-12",
        "source": "Jim Sanborn open letter",
        "weight": 0.5,
    },
    {
        "id": "k5-similar-system",
        "kind": "meta",
        "label": "K5 uses a similar coding system",
        "keywords": ("SIMILAR", "SYSTEM", "CODE"),
        "date": "2025-11-12",
        "source": "Jim Sanborn open letter",
        "weight": 0.45,
    },
    {
        "id": "k5-same-berlinclock",
        "kind": "meta",
        "label": "K5 repeats BERLINCLOCK in the same position",
        "keywords": ("BERLINCLOCK", "BERLIN", "CLOCK"),
        "date": "2025-11-12",
        "source": "Jim Sanborn open letter",
        "weight": 0.55,
    },
)

DEFAULT_PERIODS = (5, 6, 7, 8, 9, 10, 11, 14, 21, 24, 28, 97)
DEFAULT_KEYWORDS = ("KRYPTOS", "ABSCISSA", "PALIMPSEST", "BERLIN", "CLOCK", "SANBORN")

DEFAULT_PRIMERS = (
    "KRYPTOS",
    "PALIMPSEST",
    "ABSCISSA",
    "BERLIN",
    "CLOCK",
    "EAST",
    "NORTHEAST",
    "SANBORN",
    "CIA",
    "LANGLEY",
    "ILLUSION",
    "SHADOWFORCES",
    "LUCENT",
    "RQ",
)

K1_3_WORDS = [
    "BETWEEN",
    "SUBTLE",
    "SHADING",
    "AND",
    "THE",
    "ABSENCE",
    "OF",
    "LIGHT",
    "LIES",
    "NUANCE",
    "IQLUSION",
    "ILLUSION",
    "IT",
    "WAS",
    "TOTALLY",
    "INVISIBLE",
    "HOWS",
    "THAT",
    "POSSIBLE",
    "THEY",
    "USED",
    "EARTHS",
    "MAGNETIC",
    "FIELD",
    "INFORMATION",
    "GATHERED",
    "TRANSMITTED",
    "UNDERGRUUND",
    "UNDERGROUND",
    "TO",
    "AN",
    "UNKNOWN",
    "LOCATION",
    "DOES",
    "LANGLEY",
    "KNOW",
    "ABOUT",
    "THIS",
    "SHOULD",
    "ITS",
    "BURIED",
    "OUT",
    "THERE",
    "SOMEWHERE",
    "WHO",
    "KNOWS",
    "EXACT",
    "ON",
    "WYWW",
    "HIS",
    "LAST",
    "MESSAGE",
    "THIRTY",
    "EIGHT",
    "DEGREES",
    "FIFTY",
    "SEVEN",
    "MINUTES",
    "SIX",
    "POINT",
    "FIVE",
    "SECONDS",
    "NORTH",
    "SEVENTY",
    "FORTY",
    "FOUR",
    "WEST",
    "LAYER",
    "TWO",
    "SLOWLY",
    "DESPARATLY",
    "DESPERATELY",
    "REMAINS",
    "PASSAGE",
    "DEBRIS",
    "ENCUMBERED",
    "LOWER",
    "PART",
    "DOORWAY",
    "WERE",
    "REMOVED",
    "WITH",
    "TREMBLING",
    "HANDS",
    "I",
    "MADE",
    "A",
    "TINY",
    "BREACH",
    "IN",
    "UPPER",
    "LEFT",
    "HAND",
    "CORNER",
    "THEN",
    "WIDENING",
    "HOLE",
    "LITTLE",
    "INSERTED",
    "CANDLE",
    "PEERED",
    "HOT",
    "AIR",
    "ESCAPING",
    "FROM",
    "CHAMBER",
    "CAUSED",
    "FLAME",
    "FLICKER",
    "BUT",
    "PRESENTLY",
    "DETAILS",
    "ROOM",
    "WITHIN",
    "EMERGED",
    "MIST",
    "CAN",
    "YOU",
    "SEE",
    "ANYTHING",
    "KRYPTOS",
    "PALIMPSEST",
    "ABSCISSA",
    "BERLIN",
    "CLOCK",
    "SANBORN",
    "EAST",
    "NORTHEAST",
    "EGYPT",
    "TOMB",
    "CARTER",
    "HOWARD",
    "TUTANKHAMUN",
    "ILLUSION",
    "DIG",
]

DEFAULT_DATASET_PROFILE = "public"
DEFAULT_SCORER_PROFILE = "anchor-first"
DATASET_PROFILES = ("core", "public", "carter", "geo", "full-public")
SCORER_PROFILES = ("anchor-first", "running-key", "geo-route")
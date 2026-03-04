import urllib.request
import re

K1_3_WORDS = [
    "BETWEEN", "SUBTLE", "SHADING", "AND", "THE", "ABSENCE", "OF", "LIGHT", "LIES", "NUANCE", "IQLUSION", "ILLUSION",
    "IT", "WAS", "TOTALLY", "INVISIBLE", "HOWS", "THAT", "POSSIBLE", "THEY", "USED", "EARTHS", "MAGNETIC", "FIELD",
    "INFORMATION", "GATHERED", "TRANSMITTED", "UNDERGRUUND", "UNDERGROUND", "TO", "AN", "UNKNOWN", "LOCATION",
    "DOES", "LANGLEY", "KNOW", "ABOUT", "THIS", "SHOULD", "ITS", "BURIED", "OUT", "THERE", "SOMEWHERE", "WHO",
    "KNOWS", "EXACT", "ON", "WYWW", "HIS", "LAST", "MESSAGE", "THIRTY", "EIGHT", "DEGREES", "FIFTY", "SEVEN",
    "MINUTES", "SIX", "POINT", "FIVE", "SECONDS", "NORTH", "SEVENTY", "FORTY", "FOUR", "WEST", "LAYER", "TWO",
    "SLOWLY", "DESPARATLY", "DESPERATELY", "REMAINS", "PASSAGE", "DEBRIS", "ENCUMBERED", "LOWER", "PART", "DOORWAY",
    "WERE", "REMOVED", "WITH", "TREMBLING", "HANDS", "I", "MADE", "A", "TINY", "BREACH", "IN", "UPPER", "LEFT",
    "HAND", "CORNER", "THEN", "WIDENING", "HOLE", "LITTLE", "INSERTED", "CANDLE", "PEERED", "HOT", "AIR", "ESCAPING",
    "FROM", "CHAMBER", "CAUSED", "FLAME", "FLICKER", "BUT", "PRESENTLY", "DETAILS", "ROOM", "WITHIN", "EMERGED",
    "MIST", "CAN", "YOU", "SEE", "ANYTHING", "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK", "SANBORN",
    "EAST", "NORTHEAST", "EGYPT", "TOMB", "CARTER", "HOWARD", "TUTANKHAMUN", "ILLUSION", "DIG"
]

def main():
    words = set(K1_3_WORDS)
    
    print("Downloading standard English wordlist...")
    try:
        url = "https://raw.githubusercontent.com/first20hours/google-10000-english/master/google-10000-english-no-swears.txt"
        req = urllib.request.urlopen(url)
        english_words = req.read().decode('utf-8').splitlines()
        for w in english_words:
            clean_w = re.sub(r'[^A-Z]', '', w.upper())
            if len(clean_w) >= 3: # Ignore tiny words
                words.add(clean_w)
    except Exception as e:
        print(f"Error fetching english words: {e}")
        
    # Write dictionary
    with open("k4_dictionary.txt", "w") as f:
        for w in sorted(list(words)):
            f.write(w + "\n")
            
    print(f"Successfully generated k4_dictionary.txt with {len(words)} unique uppercase words.")

if __name__ == "__main__":
    main()

"""
PeekaByte — Password Profiler (CUPP-style)
Generates custom password guesses from personal info about the target.
Techniques: combinations, leet speak, common suffixes, reversed words,
date patterns, case variations, keyboard patterns, Indian patterns,
truncation, initials, double words, mixed names, and more.
"""

import itertools


# Leet speak substitutions
LEET = {
    "a": ["@", "4"],
    "e": ["3"],
    "i": ["1", "!"],
    "o": ["0"],
    "s": ["$", "5"],
    "t": ["7", "+"],
    "l": ["1", "|"],
    "g": ["9"],
    "b": ["8"],
    "z": ["2"],
    "c": ["("],
}

# Common suffixes people add
SUFFIXES = [
    "", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0",
    "11", "12", "13", "14", "15", "16", "17", "18", "19", "20",
    "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31",
    "01", "02", "03", "04", "05", "06", "07", "08", "09", "10",
    "69", "77", "88", "99",
    "12", "123", "1234", "12345", "123456",
    "!", "@", "#", "$", "%", "&", "*",
    "!!", "!!!", "!@#", "@!", "#!", "$!",
    "@123", "#123", "!123", "@1234", "!1234",
    "1!", "1@", "2!", "123!", "123@", "1234!", "12345!",
    "000", "007", "111", "222", "333", "444", "555", "666", "777", "786", "888", "999",
    "321", "420",
    "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "10",
    "*", "**", "***",
    ".", "..", "...",
    "_", "__",
    "1q", "q1",
]

# Common prefixes
PREFIXES = ["", "the", "my", "i", "im", "its", "iam", "mr", "mrs", "miss", "dr", "shri"]

# Connectors between words
CONNECTORS = ["", "_", ".", "-", "@", "#", "1", "2", "&", "+"]

# Common keyboard patterns
KEYBOARD_PATTERNS = [
    "qwerty", "qwerty123", "qwertyuiop", "asdfgh", "asdfghjkl",
    "zxcvbn", "zxcvbnm", "1qaz2wsx", "1q2w3e4r", "1q2w3e",
    "qazwsx", "qwe123", "asd123", "zxc123", "q1w2e3r4",
    "1234qwer", "qwer1234", "abcd1234", "1234abcd",
    "abc123", "xyz123", "aaa111", "zzz999",
]

# Indian-specific patterns and suffixes
INDIAN_SUFFIXES = [
    "ji", "jee", "bhai", "bro", "dude", "boss",
    "kumar", "singh", "sharma", "gupta", "khan",
    "786", "@786", "#786", "786!", "14aug", "15aug", "26jan",
    "india", "bharat", "desi",
    "jai", "shree", "om", "ram", "jai ho",
]

# Years people commonly use
COMMON_YEARS = [
    "1990", "1991", "1992", "1993", "1994", "1995", "1996", "1997",
    "1998", "1999", "2000", "2001", "2002", "2003", "2004", "2005",
    "2006", "2007", "2008", "2009", "2010",
    "2020", "2021", "2022", "2023", "2024", "2025", "2026",
    "90", "91", "92", "93", "94", "95", "96", "97", "98", "99",
    "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "10",
]

# Common standalone passwords to always try
COMMON_PASSWORDS = [
    "password", "password1", "password123", "passw0rd", "p@ssword", "p@ssw0rd",
    "admin", "admin123", "administrator", "root", "toor",
    "letmein", "welcome", "welcome1", "welcome123",
    "iloveyou", "iloveu", "love", "lovely", "lover",
    "monkey", "dragon", "master", "shadow", "sunshine",
    "princess", "football", "baseball", "soccer", "hockey",
    "batman", "superman", "spiderman", "ironman",
    "trustno1", "fuckyou", "fuckoff", "biteme", "asshole",
    "google", "facebook", "instagram", "youtube", "twitter",
    "computer", "internet", "laptop", "mobile", "samsung", "apple", "iphone",
    "changeme", "test", "test123", "guest", "guest123",
    "hello", "hello123", "hi", "hey",
    "abcdef", "abcdefg", "abcd1234", "abc@123",
    "nothing", "secret", "access", "login", "pass",
]


def _case_variants(word):
    """Generate case variations of a word."""
    if not word:
        return []
    results = set()
    w = word.strip().lower()
    if not w:
        return []
    results.add(w)                              # lowercase
    results.add(w.upper())                      # UPPERCASE
    results.add(w.capitalize())                 # Capitalize
    results.add(w[0].upper() + w[1:])           # First letter upper
    if len(w) > 1:
        results.add(w[:-1] + w[-1].upper())     # Last letter upper
        results.add(w[0].upper() + w[1:-1] + w[-1].upper())  # First+last upper
    return list(results)


def _leet_variants(word, max_per_word=8):
    """Generate leet speak variations of a word."""
    if not word or len(word) > 15:
        return []
    results = set()
    w = word.lower()

    # Single substitution (most common)
    for i, char in enumerate(w):
        if char in LEET:
            for replacement in LEET[char]:
                new_word = w[:i] + replacement + w[i+1:]
                results.add(new_word)
                results.add(new_word.capitalize())

    # Full leet (replace ALL possible characters)
    full_leet = w
    for char, replacements in LEET.items():
        full_leet = full_leet.replace(char, replacements[0])
    results.add(full_leet)

    # Double substitution (first two found)
    positions = [(i, char) for i, char in enumerate(w) if char in LEET]
    if len(positions) >= 2:
        for (i1, c1), (i2, c2) in itertools.combinations(positions[:4], 2):
            new = list(w)
            new[i1] = LEET[c1][0]
            new[i2] = LEET[c2][0]
            results.add("".join(new))

    return list(results)[:max_per_word]


def _date_variants(date_str):
    """Generate password patterns from a date."""
    results = set()
    clean = date_str.strip().replace("/", "").replace("-", "").replace(".", "").replace(" ", "")
    if not clean:
        return []

    digits = "".join(c for c in clean if c.isdigit())

    if len(digits) >= 8:
        dd = digits[:2]
        mm = digits[2:4]
        yyyy = digits[4:8]
        yy = yyyy[2:]

        combos = [
            dd + mm + yyyy, dd + mm + yy, mm + dd + yyyy, mm + dd + yy,
            yyyy + mm + dd, yy + mm + dd, dd + mm, mm + dd,
            mm + yyyy, dd + yyyy, yyyy, yy, dd, mm,
            dd + "-" + mm + "-" + yyyy, dd + "/" + mm + "/" + yyyy,
            dd + mm + yy, yy + dd + mm,
            dd + "." + mm + "." + yyyy,
            mm + "-" + dd, dd + "-" + mm,
        ]
        results.update(combos)

    elif len(digits) >= 4:
        yyyy = digits[:4]
        yy = yyyy[2:]
        results.update([yyyy, yy, digits])

    elif len(digits) >= 2:
        results.add(digits)

    return list(results)


def _reverse(word):
    return word[::-1] if word else ""


def _truncations(word):
    """Generate truncated versions: first 3, 4, 5 chars."""
    if not word or len(word) <= 3:
        return []
    results = set()
    for length in [3, 4, 5]:
        if length < len(word):
            results.add(word[:length])
    return list(results)


def _initials_combos(name, surname):
    """Generate initial-based passwords."""
    results = set()
    if not name:
        return []
    n = name.lower().strip()
    s = surname.lower().strip() if surname else ""

    results.add(n[0])               # r
    if s:
        results.add(n[0] + s[0])    # rk
        results.add(s[0] + n[0])    # kr
        results.add(n[0] + s)       # rkumar
        results.add(s[0] + n)       # krahul
        results.add(n + s[0])       # rahulk
        results.add(n[0] + "." + s) # r.kumar
        results.add(n[0] + "_" + s) # r_kumar
        results.add(n[0].upper() + s.capitalize())  # Rkumar -> RKumar
        results.add(n[0].upper() + "." + s.capitalize())  # R.Kumar
        results.add(n + "." + s)    # rahul.kumar
        results.add(n + "_" + s)    # rahul_kumar
        results.add(s + "." + n)    # kumar.rahul
        results.add(s + "_" + n)    # kumar_rahul
        results.add(s + n)          # kumarrahul
        results.add(n + s)          # rahulkumar

    return list(results)


def generate_profile_passwords(profile):
    """
    Generate password guesses from a person's profile.

    Parameters
    ----------
    profile : dict with any of these keys (all optional):
        "name", "surname", "nickname", "birthday",
        "partner_name", "partner_birthday", "pet_name",
        "phone", "company", "city",
        "favorite_team", "favorite_band", "extra_words"

    Returns
    -------
    list of str — unique password guesses, most likely first
    """
    passwords = set()

    # ===== Collect base words =====
    base_words = []
    for key in ["name", "surname", "nickname", "partner_name", "pet_name",
                "company", "city", "favorite_team", "favorite_band"]:
        val = profile.get(key, "").strip()
        if val:
            base_words.append(val.lower())

    extra = profile.get("extra_words", [])
    for w in extra:
        if w and w.strip():
            base_words.append(w.strip().lower())

    name = profile.get("name", "").strip().lower()
    surname = profile.get("surname", "").strip().lower()

    # Collect dates
    dates = []
    for key in ["birthday", "partner_birthday"]:
        val = profile.get(key, "").strip()
        if val:
            dates.append(val)

    # Phone
    phone = profile.get("phone", "").strip()
    phone_digits = "".join(c for c in phone if c.isdigit())

    # ===== ALWAYS ADD: Common standalone passwords =====
    passwords.update(COMMON_PASSWORDS)
    passwords.update(KEYBOARD_PATTERNS)

    # ===== PHASE 1: Single words with ALL variations =====
    for word in base_words:
        # Case variations
        for variant in _case_variants(word):
            passwords.add(variant)
            for suffix in SUFFIXES:
                passwords.add(variant + suffix)
            for prefix in PREFIXES:
                if prefix:
                    passwords.add(prefix + variant)
                    passwords.add(prefix + variant.capitalize())
                    passwords.add(prefix + "_" + variant)
                    passwords.add(prefix + "." + variant)

        # Leet speak
        for leet in _leet_variants(word):
            passwords.add(leet)
            for suffix in SUFFIXES[:20]:
                passwords.add(leet + suffix)

        # Reversed
        rev = _reverse(word)
        passwords.add(rev)
        passwords.add(rev.capitalize())
        passwords.add(rev.upper())
        for suffix in SUFFIXES[:15]:
            passwords.add(rev + suffix)

        # Truncated
        for trunc in _truncations(word):
            passwords.add(trunc)
            passwords.add(trunc.capitalize())
            for suffix in SUFFIXES[:10]:
                passwords.add(trunc + suffix)

        # Double word
        passwords.add(word + word)
        passwords.add(word.capitalize() + word.capitalize())
        passwords.add(word + word + "!")
        passwords.add(word + word + "123")

        # Word with common years
        for year in COMMON_YEARS:
            passwords.add(word + year)
            passwords.add(word.capitalize() + year)
            passwords.add(year + word)
            passwords.add(word + "@" + year)
            passwords.add(word + "#" + year)
            passwords.add(word + "!" + year)

        # Indian-specific
        for isuf in INDIAN_SUFFIXES:
            passwords.add(word + isuf)
            passwords.add(word.capitalize() + isuf)
            passwords.add(isuf + word)

    # ===== PHASE 2: Initials and name combinations =====
    if name:
        for combo in _initials_combos(name, surname):
            passwords.add(combo)
            passwords.add(combo.capitalize())
            for suffix in SUFFIXES[:15]:
                passwords.add(combo + suffix)
            for year in COMMON_YEARS:
                passwords.add(combo + year)
            # Leet of initials combos
            for leet in _leet_variants(combo)[:3]:
                passwords.add(leet)

    # ===== PHASE 3: Word + date combinations =====
    date_parts = []
    for d in dates:
        date_parts.extend(_date_variants(d))

    for word in base_words:
        for date_part in date_parts:
            for variant in _case_variants(word):
                passwords.add(variant + date_part)
                passwords.add(date_part + variant)
                passwords.add(variant + "@" + date_part)
                passwords.add(variant + "#" + date_part)
                passwords.add(variant + "!" + date_part)
                passwords.add(variant + "_" + date_part)
                passwords.add(variant + "." + date_part)
            # Truncated + date
            for trunc in _truncations(word):
                passwords.add(trunc + date_part)
                passwords.add(trunc.capitalize() + date_part)
                passwords.add(trunc.upper() + date_part)
                passwords.add(date_part + trunc)
                passwords.add(date_part + trunc.upper())
            # Leet + date
            for leet in _leet_variants(word)[:3]:
                passwords.add(leet + date_part)
                passwords.add(date_part + leet)
            # Reversed + date
            rev = _reverse(word)
            passwords.add(rev + date_part)
            passwords.add(date_part + rev)

    # Initials + dates
    if name:
        for combo in _initials_combos(name, surname)[:5]:
            for date_part in date_parts:
                passwords.add(combo + date_part)
                passwords.add(date_part + combo)

    # ===== PHASE 4: Two-word combinations =====
    if len(base_words) >= 2:
        for w1, w2 in itertools.permutations(base_words[:8], 2):
            for connector in CONNECTORS:
                combo = w1 + connector + w2
                passwords.add(combo)
                passwords.add(combo.capitalize())
                passwords.add(w1.capitalize() + connector + w2.capitalize())
                passwords.add(combo.upper())
                for suffix in SUFFIXES[:12]:
                    passwords.add(combo + suffix)
                # Leet of combos
                for leet in _leet_variants(combo)[:2]:
                    passwords.add(leet)

            # Truncated combos
            for t1 in _truncations(w1):
                passwords.add(t1 + w2)
                passwords.add(t1 + w2.capitalize())
                passwords.add(t1 + "_" + w2)

            # First word + second word + date
            for date_part in date_parts[:5]:
                passwords.add(w1 + w2 + date_part)
                passwords.add(w1.capitalize() + w2.capitalize() + date_part)

    # ===== PHASE 5: Word + phone number patterns =====
    if phone_digits:
        phone_parts = set()
        phone_parts.add(phone_digits)
        if len(phone_digits) >= 4:
            phone_parts.add(phone_digits[-4:])
            phone_parts.add(phone_digits[:4])
        if len(phone_digits) >= 6:
            phone_parts.add(phone_digits[-6:])
            phone_parts.add(phone_digits[:6])
        if len(phone_digits) >= 10:
            phone_parts.add(phone_digits[-10:])

        # Phone alone
        for pp in phone_parts:
            passwords.add(pp)
            passwords.add(pp + "!")
            passwords.add(pp + "@")
            passwords.add(pp + "#")

        # Word + phone
        for word in base_words:
            for pp in phone_parts:
                passwords.add(word + pp)
                passwords.add(word.capitalize() + pp)
                passwords.add(pp + word)
                passwords.add(pp + word.capitalize())
                passwords.add(word + "@" + pp)
                passwords.add(word + "#" + pp)
                passwords.add(word + "_" + pp)

        # Initials + phone
        if name:
            for combo in _initials_combos(name, surname)[:3]:
                for pp in phone_parts:
                    passwords.add(combo + pp)
                    passwords.add(pp + combo)

    # ===== PHASE 6: Date-only passwords =====
    for date_part in date_parts:
        passwords.add(date_part)
        for suffix in SUFFIXES[:8]:
            passwords.add(date_part + suffix)
        # Date leet
        passwords.add(date_part + "!")
        passwords.add(date_part + "@")
        passwords.add("@" + date_part)

    # ===== PHASE 7: Three-word combinations (name + word + date) =====
    if name and date_parts and len(base_words) >= 2:
        other_words = [w for w in base_words if w != name][:3]
        for w in other_words:
            for d in date_parts[:5]:
                passwords.add(name + w + d)
                passwords.add(name.capitalize() + w.capitalize() + d)
                passwords.add(name + "_" + w + "_" + d)
                passwords.add(w + name + d)

    # ===== PHASE 8: Special patterns =====
    for word in base_words:
        # Word + repeated chars
        for char in ["1", "!", "@", "#", "*", "0"]:
            passwords.add(word + char * 2)
            passwords.add(word + char * 3)
            passwords.add(word.capitalize() + char * 2)

        # Word with special separators
        for sep in ["@", "#", "$", "!", "_", "."]:
            passwords.add(word + sep)
            passwords.add(sep + word)
            if date_parts:
                passwords.add(word + sep + date_parts[0])

        # Capitalize inner letters
        if len(word) > 2:
            inner_cap = word[0] + word[1:-1].upper() + word[-1]
            passwords.add(inner_cap)

        # Alternating case: rAhUl
        alt = ""
        for i, c in enumerate(word):
            alt += c.upper() if i % 2 == 1 else c.lower()
        passwords.add(alt)

        # First half + second half reversed
        mid = len(word) // 2
        if mid > 0:
            passwords.add(word[:mid] + _reverse(word[mid:]))

    # ===== PHASE 9: Email-style patterns =====
    if name and surname:
        email_patterns = [
            f"{name}{surname}",
            f"{name}.{surname}",
            f"{name}_{surname}",
            f"{name[0]}{surname}",
            f"{surname}{name}",
            f"{surname}.{name}",
            f"{surname}{name[0]}",
        ]
        for ep in email_patterns:
            passwords.add(ep)
            passwords.add(ep + "123")
            passwords.add(ep + "!")
            for year in COMMON_YEARS[:10]:
                passwords.add(ep + year)

    # Remove empty strings
    passwords.discard("")

    # Sort: shorter first (more common), then alphabetical
    sorted_passwords = sorted(passwords, key=lambda x: (len(x), x))

    return sorted_passwords


def profile_summary(profile):
    """Return a human-readable summary of what was entered."""
    lines = []
    labels = {
        "name": "Name", "surname": "Surname", "nickname": "Nickname",
        "birthday": "Birthday", "partner_name": "Partner name",
        "partner_birthday": "Partner birthday", "pet_name": "Pet name",
        "phone": "Phone", "company": "Company/School",
        "city": "City", "favorite_team": "Favorite team",
        "favorite_band": "Favorite band/artist",
    }
    for key, label in labels.items():
        val = profile.get(key, "").strip()
        if val:
            lines.append(f"{label}: {val}")
    extra = profile.get("extra_words", [])
    if extra:
        lines.append(f"Extra words: {', '.join(extra)}")
    count = len(generate_profile_passwords(profile))
    lines.append(f"\nTotal passwords generated: {count:,}")
    return "\n".join(lines) if lines else "No information entered."
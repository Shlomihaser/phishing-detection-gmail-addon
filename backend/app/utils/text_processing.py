from app.constants.brands import HOMOGLYPH_PATTERNS, UNICODE_CONFUSABLES


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Pure Python implementation of Levenshtein Distance (Edit Distance).
    Calculates minimum number of single-character edits to turn s1 into s2.
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def normalize_homoglyphs(text: str) -> str:
    """
    Replaces visual spoofing characters with their canonical ASCII forms.
    1. First applies Unicode confusables (Cyrillic, Greek, etc.)
    2. Then applies ASCII pattern tricks (rn->m, 0->o, etc.)
    """
    if not text:
        return ""

    normalized = text.lower()

    # Step 1: Replace Unicode confusables (Cyrillic а -> a, Greek ο -> o, etc.)
    for fake_char, real_char in UNICODE_CONFUSABLES.items():
        normalized = normalized.replace(fake_char, real_char)

    # Step 2: Replace ASCII pattern tricks (rn -> m, vv -> w, etc.)
    for fake, real in HOMOGLYPH_PATTERNS:
        normalized = normalized.replace(fake, real)

    return normalized

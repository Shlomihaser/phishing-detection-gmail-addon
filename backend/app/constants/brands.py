# Legitimate domains owned by known brands (Whitelist)
VALID_BRAND_DOMAINS = {
    "microsoft": {"microsoft.com", "office.com", "outlook.com", "azure.com"},
    "google": {"google.com", "gmail.com", "youtube.com", "android.com"},
    "amazon": {"amazon.com", "aws.amazon.com"},
    "paypal": {"paypal.com", "paypal-communication.com"},
    "apple": {"apple.com", "icloud.com", "me.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "linkedin": {"linkedin.com"},
    "chase": {"chase.com"},
    "dhl": {"dhl.com"}
}

# Common Visual Spoofing Patterns (ASCII tricks)
HOMOGLYPH_PATTERNS = [
    (r"rn", "m"),
    (r"vv", "w"),
    (r"1", "l"),
    (r"0", "o"),
    (r"!", "i"),
    (r"3", "e"),
    (r"@", "a"),
    (r"5", "s")
]

# Unicode Confusables - Characters from other scripts that look like Latin letters
# Source: Unicode Consortium Confusables + common phishing attacks
UNICODE_CONFUSABLES = {
    # Cyrillic lookalikes (most dangerous - visually identical)
    'а': 'a',  # U+0430 Cyrillic Small Letter A
    'с': 'c',  # U+0441 Cyrillic Small Letter Es (looks like 'c')
    'е': 'e',  # U+0435 Cyrillic Small Letter Ie
    'о': 'o',  # U+043E Cyrillic Small Letter O
    'р': 'p',  # U+0440 Cyrillic Small Letter Er
    'х': 'x',  # U+0445 Cyrillic Small Letter Ha
    'у': 'y',  # U+0443 Cyrillic Small Letter U (looks like 'y')
    'і': 'i',  # U+0456 Cyrillic Small Letter Byelorussian-Ukrainian I
    'ј': 'j',  # U+0458 Cyrillic Small Letter Je
    'ѕ': 's',  # U+0455 Cyrillic Small Letter Dze
    'ԁ': 'd',  # U+0501 Cyrillic Small Letter Komi De
    'ԛ': 'q',  # U+051B Cyrillic Small Letter Qa
    'ԝ': 'w',  # U+051D Cyrillic Small Letter We
    
    # Greek lookalikes
    'ο': 'o',  # U+03BF Greek Small Letter Omicron
    'α': 'a',  # U+03B1 Greek Small Letter Alpha (slightly different)
    'ε': 'e',  # U+03B5 Greek Small Letter Epsilon
    'ι': 'i',  # U+03B9 Greek Small Letter Iota
    'ν': 'v',  # U+03BD Greek Small Letter Nu
    'ρ': 'p',  # U+03C1 Greek Small Letter Rho
    'τ': 't',  # U+03C4 Greek Small Letter Tau
    'υ': 'u',  # U+03C5 Greek Small Letter Upsilon
    'χ': 'x',  # U+03C7 Greek Small Letter Chi
    
    # Latin Extended / Special characters
    'ı': 'i',  # U+0131 Latin Small Letter Dotless I
    'ł': 'l',  # U+0142 Latin Small Letter L with Stroke
    'ø': 'o',  # U+00F8 Latin Small Letter O with Stroke
    'ß': 'ss', # U+00DF Latin Small Letter Sharp S
    'ð': 'd',  # U+00F0 Latin Small Letter Eth
    'þ': 'p',  # U+00FE Latin Small Letter Thorn
    'ƒ': 'f',  # U+0192 Latin Small Letter F with Hook
    'ǝ': 'e',  # U+01DD Latin Small Letter Turned E
    'ə': 'e',  # U+0259 Latin Small Letter Schwa
}


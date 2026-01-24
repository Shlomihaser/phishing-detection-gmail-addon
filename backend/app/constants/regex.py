import re

URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')\]]+',
    re.IGNORECASE
)
# Matches text that looks like a URL (starts with www. or http, or has domain.tld format)
URL_LIKE_PATTERN = re.compile(
    r'^(?:https?://|www\.)|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}',
    re.IGNORECASE
)
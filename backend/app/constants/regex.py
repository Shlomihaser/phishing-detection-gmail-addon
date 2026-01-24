import re

URL_PATTERN = re.compile(r'https?://[^\s<>"\')\]]+', re.IGNORECASE)

# Common TLDs for URL-like text detection
# Used to reduce false positives (e.g., "John.Doe" should NOT match)
_COMMON_TLDS = r"(?:com|org|net|edu|gov|io|co|app|dev|info|biz|us|uk|de|fr|ru|cn|jp|au|ca|nl|se|no|fi|dk|pl|br|mx|in|za)"

# Matches text that looks like a URL:
# - Starts with http:// or https://
# - Starts with www.
# - Has domain + common TLD format (e.g., google.com, evil.ru)
URL_LIKE_PATTERN = re.compile(
    rf"(?:https?://|www\.)[^\s]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.{_COMMON_TLDS}(?:[:/]|$)",
    re.IGNORECASE,
)

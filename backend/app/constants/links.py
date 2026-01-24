# Suspicious Top-Level Domains commonly used in phishing
# These TLDs have lower registration requirements or are frequently abused
SUSPICIOUS_TLDS = {
    "tk",  # Tokelau - Free domain, heavily abused
    "ml",  # Mali - Free domain
    "ga",  # Gabon - Free domain
    "cf",  # Central African Republic - Free domain
    "gq",  # Equatorial Guinea - Free domain
    "xyz",  # Generic - cheap, often abused
    "top",  # Generic - cheap, often abused
    "buzz",  # Generic - often abused
    "club",  # Generic - often abused
    "work",  # Generic - often abused
    "link",  # Generic - often abused
    "click",  # Generic - often abused
    "cam",  # Generic - often abused
    "surf",  # Generic - often abused
    "pw",  # Palau - cheap, often abused
    "cc",  # Cocos Islands - often abused
    "ru",  # Russia - high phishing origin (controversial but statistically relevant)
    "cn",  # China - high phishing origin
    "info",  # Generic - often abused
    "biz",  # Business - often abused
}

# Known URL shortener domains
# Links hidden behind these services should be treated with suspicion
SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "soo.gd",
    "short.to",
    "s.id",
    "clck.ru",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "tiny.cc",
    "x.co",
    "rb.gy",
    "v.gd",
    "t.ly",
    "tr.im",
    "bc.vc",
}

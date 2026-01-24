import tldextract

_extractor = tldextract.TLDExtract(
    cache_dir=None,
    suffix_list_urls=None
)

def extract_domain(url: str) -> tldextract.ExtractResult:
    """
    Extract domain components from a URL using cached TLD data.
    
    Returns an ExtractResult with:
    - subdomain: 'www' from 'www.google.com'
    - domain: 'google' from 'www.google.com'  
    - suffix: 'com' from 'www.google.com'
    - registered_domain: 'google.com'
    """
    return _extractor(url)

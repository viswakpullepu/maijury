import re
import sys
from urllib.parse import urlparse, parse_qs

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

TOP_BRANDS = [
    "microsoft", "google", "apple", "paypal", "amazon", "netflix", 
    "chase", "wellsfargo", "bankofamerica", "docusign", "dropbox", 
    "dhl", "fedex", "adobe", "zoom", "facebook", "instagram", 
    "twitter", "linkedin", "office365", "sharepoint", "onedrive"
]

HOMOGLYPH_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '8': 'b',
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i'
}

def damerau_levenshtein(s1, s2):
    d = {}
    len1 = len(s1)
    len2 = len(s2)
    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,       # deletion
                d[(i, j - 1)] + 1,       # insertion
                d[(i - 1, j - 1)] + cost  # substitution
            )
            if i and j and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[i - 2, j - 2] + cost)  # transposition
    return d[len1 - 1, len2 - 1]

def analyze_url(url_str):
    parsed = urlparse(url_str if "://" in url_str else "http://" + url_str)
    netloc = parsed.netloc.lower()
    host = netloc.split(':')[0]
    
    # Check IP literal
    is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host)) or host.startswith('[')
    
    # Check Punycode / IDN
    is_punycode = "xn--" in host
    decoded_host = host
    if is_punycode:
        try:
            decoded_host = host.encode('ascii').decode('idna')
        except Exception:
            pass

    # Normalize homoglyphs
    normalized_chars = []
    for c in decoded_host:
        normalized_chars.append(HOMOGLYPH_MAP.get(c, c))
    norm_host = "".join(normalized_chars)
    
    # Check typosquatting against top brands
    squatted_brand = None
    min_dist = 999
    
    # Tokenize host by delimiters (., -, _)
    tokens = re.split(r'[-_.]', host)
    for token in tokens:
        if token in ('com', 'org', 'net', 'io', 'co', 'www', 'login', 'mail', 'app'):
            continue
        norm_token = "".join(HOMOGLYPH_MAP.get(c, c) for c in token)
        for brand in TOP_BRANDS:
            if token == brand:
                continue
            if norm_token == brand:
                squatted_brand = f"{brand} (Homoglyph spoofing in token: '{token}')"
                break
            dist = damerau_levenshtein(norm_token, brand)
            if dist in (1, 2) and dist < min_dist and len(brand) >= 4:
                min_dist = dist
                squatted_brand = f"{brand} (Typosquatting distance {dist} in token: '{token}')"
        if squatted_brand:
            break

    # Suspicious redirect params
    qs = parse_qs(parsed.query)
    redirect_keys = ['redirect', 'dest', 'destination', 'url', 'next', 'link', 'target']
    found_redirects = [k for k in qs if k.lower() in redirect_keys]

    return {
        "url": url_str,
        "host": host,
        "is_ip_literal": is_ip,
        "is_punycode": is_punycode,
        "decoded_host": decoded_host,
        "squatted_brand": squatted_brand,
        "redirect_params": found_redirects
    }

if __name__ == '__main__':
    test_urls = [
        "http://192.168.1.104/ms-signin",
        "https://paypa1-security-verification.com/login",
        "https://login.micros0ft.com/oauth",
        "https://xn--pypal-4ve.com/account", # Cyrillic 'а' in paypal
        "https://google.com/url?url=https://evil.org/phish",
        "https://www.apple.com/iphone" # legitimate
    ]
    for u in test_urls:
        res = analyze_url(u)
        print(f"URL: {u}")
        print(f"  -> IP: {res['is_ip_literal']}, Puny: {res['is_punycode']} ({res['decoded_host']}), Squat: {res['squatted_brand']}, Redirects: {res['redirect_params']}\n")

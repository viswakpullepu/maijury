import re
import io
import json
import email
import email.utils
import hashlib
import zipfile
import sys
from urllib.parse import urlparse, parse_qs
from datetime import datetime

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# -------------------------------------------------------------
# CONSTANTS & DICTIONARIES
# -------------------------------------------------------------
TOP_ENTERPRISE_BRANDS = [
    "microsoft", "google", "apple", "paypal", "amazon", "netflix", 
    "chase", "wellsfargo", "bankofamerica", "docusign", "dropbox", 
    "dhl", "fedex", "adobe", "zoom", "facebook", "instagram", 
    "twitter", "linkedin", "office365", "sharepoint", "onedrive",
    "github", "salesforce", "slack", "okta", "cisco", "oracle"
]

HOMOGLYPH_TRANSLATION = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '8': 'b',
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
    '\u03bf': 'o', '\u03c1': 'p', '\u03b1': 'a', '\u03bd': 'v'
}

CONSUMER_WEBMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", 
    "proton.me", "protonmail.com", "icloud.com", "zoho.com", "yandex.com",
    "mail.com", "gmx.com", "fastmail.com", "tutanota.com"
}

MAGIC_SIGNATURES = [
    ("Windows PE Executable / DLL / SCR", b"\x4d\x5a", 0, "application/x-dosexec", [".exe", ".dll", ".scr", ".cpl"]),
    ("ZIP / OOXML / JAR / APK", b"\x50\x4b\x03\x04", 0, "application/zip", [".zip", ".docx", ".xlsx", ".pptx", ".jar"]),
    ("OLE Compound Binary (Legacy Office / MSI)", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "application/x-ole-storage", [".doc", ".xls", ".ppt", ".msi"]),
    ("PDF Document", b"\x25\x50\x44\x46", 0, "application/pdf", [".pdf"]),
    ("7-Zip Archive", b"\x37\x7a\xbc\xaf\x27\x1c", 0, "application/x-7z-compressed", [".7z"]),
    ("RAR Archive", b"\x52\x61\x72\x21\x1a\x07", 0, "application/x-rar-compressed", [".rar"]),
    ("GZIP Compressed Archive", b"\x1f\x8b", 0, "application/gzip", [".gz", ".tar.gz"]),
    ("Windows Shell Shortcut", b"\x4c\x00\x00\x00\x01\x14\x02\x00", 0, "application/x-ms-shortcut", [".lnk"]),
    ("RTF Document", b"{\\rtf", 0, "application/rtf", [".rtf"])
]

# -------------------------------------------------------------
# HELPER FUNCTIONS
# -------------------------------------------------------------
def damerau_levenshtein(s1: str, s2: str) -> int:
    d = {}
    len1, len2 = len(s1), len(s2)
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

def normalize_homoglyphs(text: str) -> str:
    return "".join(HOMOGLYPH_TRANSLATION.get(c, c) for c in text.lower())

def extract_domain(url_or_email: str) -> str:
    if not url_or_email:
        return ""
    if "@" in url_or_email and "://" not in url_or_email:
        return url_or_email.split("@")[-1].strip().lower()
    if not url_or_email.startswith(("http://", "https://")):
        url_or_email = "http://" + url_or_email
    try:
        host = urlparse(url_or_email).netloc.lower()
        return host.split(":")[0]
    except Exception:
        return ""

# -------------------------------------------------------------
# 1. CRYPTOGRAPHIC & PROTOCOL VALIDATION
# -------------------------------------------------------------
def validate_cryptographic_auth(headers_str: str) -> dict:
    msg = email.message_from_string(headers_str)
    auth_results = msg.get("Authentication-Results", "") + " " + msg.get("Received-SPF", "") + " " + msg.get("ARC-Authentication-Results", "")
    auth_lower = auth_results.lower()
    
    spf_match = re.search(r'\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)', auth_lower)
    spf = spf_match.group(1) if spf_match else "none"
    
    dkim_match = re.search(r'\bdkim=(pass|fail|none)', auth_lower)
    dkim = dkim_match.group(1) if dkim_match else "none"
    
    dmarc_match = re.search(r'\bdmarc=(pass|fail|none)', auth_lower)
    dmarc = dmarc_match.group(1) if dmarc_match else "none"
    
    arc_match = re.search(r'\barc=(pass|fail|none)', auth_lower)
    arc = arc_match.group(1) if arc_match else "none"
    
    signals = []
    if spf in ("fail", "softfail"):
        signals.append({"method": "VAL-01-SPF", "severity": "HIGH", "detail": f"SPF validation failed: {spf.upper()}"})
    if dkim == "fail":
        signals.append({"method": "VAL-02-DKIM", "severity": "HIGH", "detail": "DKIM signature failed cryptographic verification"})
    if dmarc == "fail":
        signals.append({"method": "VAL-03-DMARC", "severity": "CRITICAL", "detail": "DMARC policy failed domain alignment"})
    if arc == "pass":
        signals.append({"method": "VAL-04-ARC", "severity": "INFORMATIONAL", "detail": "ARC chain preserved authentic forwarded state"})

    is_authenticated = (spf == "pass" and dkim == "pass" and dmarc == "pass")
    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "arc": arc,
        "is_authenticated": is_authenticated,
        "signals": signals
    }

# -------------------------------------------------------------
# 2. ENVELOPE & TRANSPORT HEADER FORENSICS
# -------------------------------------------------------------
def validate_envelope_and_hops(headers_str: str) -> dict:
    msg = email.message_from_string(headers_str)
    signals = []
    
    from_raw = msg.get("From", "")
    return_path_raw = msg.get("Return-Path", "")
    _, from_addr = email.utils.parseaddr(from_raw)
    _, return_addr = email.utils.parseaddr(return_path_raw)
    
    from_domain = extract_domain(from_addr)
    return_domain = extract_domain(return_addr)
    
    # Envelope alignment (VAL-11)
    if from_domain and return_domain and from_domain != return_domain:
        signals.append({
            "method": "VAL-11-ENVELOPE-ALIGNMENT",
            "severity": "LOW",
            "detail": f"Envelope sender (@{return_domain}) differs from visible From (@{from_domain})"
        })
        
    # Received hops trace (VAL-12, VAL-15)
    received_headers = msg.get_all("Received") or []
    hop_ips = []
    for r in received_headers:
        ips = re.findall(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', r)
        hop_ips.extend(ips)
        
        # Check for RFC 1918 in public hops (VAL-15)
        for ip in ips:
            if ip.startswith(("10.", "192.168.")) or re.match(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', ip):
                signals.append({
                    "method": "VAL-15-BOGON-IP",
                    "severity": "MEDIUM",
                    "detail": f"Private/RFC 1918 IP address ({ip}) leaked in Received header"
                })
                
    # Message-ID integrity (VAL-17)
    msg_id = msg.get("Message-ID", "")
    if not msg_id or "@" not in msg_id:
        signals.append({
            "method": "VAL-17-MESSAGE-ID-INTEGRITY",
            "severity": "MEDIUM",
            "detail": "Message-ID header is missing or improperly formatted"
        })
        
    return {
        "from_domain": from_domain,
        "return_path_domain": return_domain,
        "total_hops": len(received_headers),
        "hop_ips": list(set(hop_ips)),
        "signals": signals
    }

# -------------------------------------------------------------
# 3. IDENTITY & DISPLAY NAME SPOOFING FORENSICS
# -------------------------------------------------------------
def validate_identity_display(headers_str: str) -> dict:
    msg = email.message_from_string(headers_str)
    from_raw = msg.get("From", "")
    reply_to_raw = msg.get("Reply-To", "")
    
    from_name, from_addr = email.utils.parseaddr(from_raw)
    _, reply_addr = email.utils.parseaddr(reply_to_raw)
    
    from_domain = extract_domain(from_addr)
    reply_domain = extract_domain(reply_addr)
    
    signals = []
    
    # VAL-19: Embedded email in display name
    embedded_emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', from_name)
    for emb in embedded_emails:
        if emb.lower() != from_addr.lower():
            signals.append({
                "method": "VAL-19-DISPLAY-NAME-EMBEDDED-EMAIL",
                "severity": "CRITICAL",
                "detail": f"Display name contains deceptive address '{emb}' while actual sender is '{from_addr}'"
            })
            
    # VAL-21: Authority keyword on consumer mail
    authority_kws = ["support", "helpdesk", "administrator", "executive", "payroll", "security", "ceo", "cfo", "billing"]
    if any(k in from_name.lower() for k in authority_kws) and from_domain in CONSUMER_WEBMAIL_DOMAINS:
        signals.append({
            "method": "VAL-21-CONSUMER-AUTHORITY-FLAG",
            "severity": "HIGH",
            "detail": f"Authority persona '{from_name}' sent from free consumer webmail provider (@{from_domain})"
        })
        
    # VAL-22: Reply-To divergence
    if reply_domain and from_domain and reply_domain != from_domain:
        signals.append({
            "method": "VAL-22-REPLY-TO-DIVERGENCE",
            "severity": "HIGH" if reply_domain in CONSUMER_WEBMAIL_DOMAINS else "MEDIUM",
            "detail": f"Reply-To (@{reply_domain}) diverts responses away from sender domain (@{from_domain})"
        })
        
    # VAL-23: Zero-width characters in display name
    zero_width_chars = ['\u200b', '\u200c', '\u200d', '\ufeff', '\u00ad']
    if any(c in from_name for c in zero_width_chars):
        signals.append({
            "method": "VAL-23-ZERO-WIDTH-DISPLAY-NAME",
            "severity": "HIGH",
            "detail": "Display name contains invisible zero-width characters used to evade blacklist filters"
        })
        
    return {
        "display_name": from_name,
        "sender_email": from_addr,
        "reply_to": reply_addr,
        "signals": signals
    }

# -------------------------------------------------------------
# 4. DOMAIN & URL FORENSICS
# -------------------------------------------------------------
def validate_urls_and_links(body_html: str) -> dict:
    signals = []
    
    # VAL-24: Anchor visible text vs href destination mismatch
    link_pattern = re.compile(r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.I | re.S)
    for m in link_pattern.finditer(body_html):
        href = m.group(1).strip()
        visible_text = re.sub(r'<[^>]+>', '', m.group(2)).strip()
        
        text_domain = extract_domain(visible_text)
        href_domain = extract_domain(href)
        
        # Check if visible text looks like a URL/domain
        if (re.search(r'(?:https?://|www\.)[a-zA-Z0-9\.\-_]+', visible_text) or any(d in visible_text.lower() for d in ['.com', '.org', '.net', '.edu', '.gov'])) and text_domain:
            if href_domain and text_domain != href_domain:
                signals.append({
                    "method": "VAL-24-LINK-TEXT-HREF-MISMATCH",
                    "severity": "CRITICAL",
                    "detail": f"Visible anchor displays '{text_domain}' but href navigates to '{href_domain}' ({href})"
                })
                
    # Extract all unique URLs
    raw_urls = re.findall(r'href=["\']([^"\']+)["\']', body_html)
    inspected_urls = []
    
    for u in set(raw_urls):
        parsed = urlparse(u if "://" in u else "http://" + u)
        host = parsed.netloc.lower().split(":")[0]
        
        # VAL-30: IP Literal
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host) or host.startswith("["):
            signals.append({
                "method": "VAL-30-IP-LITERAL-URL",
                "severity": "CRITICAL",
                "detail": f"URL uses raw IP literal host destination: {host}"
            })
            
        # VAL-25: Punycode
        is_punycode = "xn--" in host
        decoded_host = host
        if is_punycode:
            try:
                decoded_host = host.encode('ascii').decode('idna')
                signals.append({
                    "method": "VAL-25-PUNYCODE-IDN-DECODE",
                    "severity": "HIGH",
                    "detail": f"Punycode encoded domain ({host}) decodes to IDN: '{decoded_host}'"
                })
            except Exception:
                pass
                
        # VAL-26 & VAL-27: Homoglyphs and Typosquatting
        tokens = re.split(r'[-_.]', decoded_host)
        for token in tokens:
            if token in ('com', 'org', 'net', 'io', 'www', 'login', 'mail', 'app'):
                continue
            norm_token = normalize_homoglyphs(token)
            for brand in TOP_ENTERPRISE_BRANDS:
                if token == brand:
                    continue
                if norm_token == brand:
                    signals.append({
                        "method": "VAL-26-HOMOGLYPH-NORMALIZATION",
                        "severity": "CRITICAL",
                        "detail": f"Homoglyph spoofing targeting brand '{brand}' in token: '{token}'"
                    })
                    break
                dist = damerau_levenshtein(norm_token, brand)
                if dist in (1, 2) and len(brand) >= 4:
                    signals.append({
                        "method": "VAL-27-DAMERAU-LEVENSHTEIN-BRAND",
                        "severity": "CRITICAL",
                        "detail": f"Typosquatting edit distance {dist} targeting brand '{brand}' in token: '{token}'"
                    })
                    break
                    
        # VAL-31: Open redirect parameters
        qs = parse_qs(parsed.query)
        for r_key in ['url', 'redirect', 'next', 'dest', 'target', 'link', 'r']:
            if r_key in qs:
                signals.append({
                    "method": "VAL-31-OPEN-REDIRECT-PARAM",
                    "severity": "MEDIUM",
                    "detail": f"URL contains potential open redirection parameter '{r_key}={qs[r_key][0]}'"
                })
                
        inspected_urls.append({"url": u, "host": host, "decoded": decoded_host})

    return {"inspected_urls": inspected_urls, "signals": signals}

# -------------------------------------------------------------
# 5. SEMANTIC & COGNITIVE NLP FORENSICS
# -------------------------------------------------------------
def validate_semantics_nlp(body_text: str) -> dict:
    signals = []
    
    # VAL-33: Coercive urgency
    urgency_patterns = [
        r'(?i)\b(?:suspend(?:ed)?|deactivat(?:ed)?|terminat(?:ed)?)\b.*?\b(?:24\s*hours?|immediately|today)\b',
        r'(?i)\b(?:urgent|immediate)\s+(?:action|attention|verification)\s+required\b',
        r'(?i)\b(?:unauthorized|suspicious)\s+(?:sign-?in|login|access)\s+detected\b'
    ]
    for p in urgency_patterns:
        m = re.search(p, body_text)
        if m:
            signals.append({
                "method": "VAL-33-NLP-URGENCY",
                "severity": "HIGH",
                "detail": f"High-urgency deadline phrasing matched: '{m.group(0)[:80]}'"
            })
            break
            
    # VAL-34: Financial pressure
    fin_patterns = [
        r'(?i)\b(?:wire\s+transfer|gift\s*cards?|bitcoin|crypto)\b.*?\b(?:asap|urgently|confidential)\b',
        r'(?i)\b(?:update|change)\s+direct\s+deposit\s+(?:bank|account)\b'
    ]
    for p in fin_patterns:
        m = re.search(p, body_text)
        if m:
            signals.append({
                "method": "VAL-34-FINANCIAL-PRESSURE",
                "severity": "CRITICAL",
                "detail": f"Financial transaction/payroll lure matched: '{m.group(0)[:80]}'"
            })
            break
            
    # VAL-35: Zero-width spaces in body
    if any(c in body_text for c in ['\u200b', '\u200c', '\u200d', '\ufeff', '\u00ad']):
        signals.append({
            "method": "VAL-35-INVISIBLE-UNICODE-CLEANER",
            "severity": "HIGH",
            "detail": "Body text contains hidden zero-width spaces designed to evade keyword filters"
        })
        
    # VAL-37: Archive password in body
    pass_matches = re.findall(r'(?i)\b(?:password|passcode|pass|pwd|code)\s*(?:is|:|=)\s*["\']?([A-Za-z0-9!@#$%^&*_\-]{3,30})["\']?', body_text)
    found_passwords = []
    if pass_matches:
        found_passwords = pass_matches
        signals.append({
            "method": "VAL-37-PASSWORD-IN-BODY-CORRELATION",
            "severity": "HIGH",
            "detail": f"Email text explicitly discloses password ('{pass_matches[0]}') to unlock encrypted attachments"
        })
        
    return {
        "signals": signals,
        "extracted_passwords": found_passwords
    }

# -------------------------------------------------------------
# 6. STATIC ATTACHMENT FORENSICS (ZERO EXECUTION)
# -------------------------------------------------------------
def validate_attachment_static(filename: str, declared_type: str, content_bytes: bytes, has_body_passwords: bool = False) -> dict:
    signals = []
    
    sha256 = hashlib.sha256(content_bytes).hexdigest()
    size = len(content_bytes)
    
    # VAL-38: Magic byte verification
    detected_type = "Unknown / Plaintext"
    detected_mime = "application/octet-stream"
    for name, sig, offset, mime, exts in MAGIC_SIGNATURES:
        if len(content_bytes) >= offset + len(sig):
            if content_bytes[offset:offset+len(sig)] == sig:
                detected_type = name
                detected_mime = mime
                break
                
    is_declared_doc = any(d in declared_type.lower() for d in ["pdf", "word", "excel", "document"]) or filename.lower().endswith(('.pdf', '.docx', '.xlsx', '.doc', '.xls'))
    is_detected_exe = "dosexec" in detected_mime
    if is_declared_doc and is_detected_exe:
        signals.append({
            "method": "VAL-38-MAGIC-BYTES",
            "severity": "CRITICAL",
            "detail": f"File type spoofing: Named as document '{filename}' but binary contains Windows PE (MZ) executable header"
        })
        
    # VAL-39: Double extension
    if re.search(r'\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\s*\.(exe|scr|js|vbs|hta|lnk|iso|bat|ps1|cmd|cpl|msi)$', filename, re.I):
        signals.append({
            "method": "VAL-39-DOUBLE-EXTENSION",
            "severity": "CRITICAL",
            "detail": f"Deceptive double extension detected in filename: '{filename}'"
        })
        
    # VAL-40: Unicode RTLO
    bidi_chars = ['\u202e', '\u202d', '\u2066', '\u2067', '\u2068']
    if any(c in filename for c in bidi_chars):
        signals.append({
            "method": "VAL-40-UNICODE-RTLO",
            "severity": "CRITICAL",
            "detail": f"Right-to-Left Override (RTLO U+202E) detected in filename: '{filename}'"
        })
        
    # VAL-41: Static OOXML macro
    if filename.lower().endswith(('.docm', '.xlsm', '.pptm')) or b"vbaProject.bin" in content_bytes:
        signals.append({
            "method": "VAL-41-STATIC-OOXML-MACRO",
            "severity": "CRITICAL",
            "detail": f"Macro-enabled Office document container detected: {filename}"
        })
        
    # VAL-42: Static PDF active tokens
    if filename.lower().endswith('.pdf') or "pdf" in detected_mime:
        if re.search(rb'/JavaScript|/JS\b', content_bytes):
            signals.append({
                "method": "VAL-42-STATIC-PDF-TOKENIZER",
                "severity": "HIGH",
                "detail": "PDF contains active /JavaScript dictionary object"
            })
        if re.search(rb'/OpenAction|/Launch\b', content_bytes):
            signals.append({
                "method": "VAL-42-STATIC-PDF-TOKENIZER",
                "severity": "CRITICAL",
                "detail": "PDF contains /OpenAction or /Launch automatic execution directive"
            })
            
    # VAL-43: HTML smuggling form
    if filename.lower().endswith(('.html', '.htm')) or "html" in detected_type.lower():
        if re.search(rb'<form[^>]*>.*?<input[^>]*type=["\']?password', content_bytes, re.I | re.S) or b"password" in content_bytes.lower():
            signals.append({
                "method": "VAL-43-HTML-SMUGGLING-DETECTOR",
                "severity": "CRITICAL",
                "detail": "HTML attachment contains an embedded password input form (offline credential harvester)"
            })
            
    # VAL-44: Archive encryption & body password correlation
    is_zip = content_bytes.startswith(b"PK\x03\x04")
    if is_zip and len(content_bytes) >= 8 and (content_bytes[6] & 0x01 != 0):
        signals.append({
            "method": "VAL-44-ARCHIVE-ENCRYPTION-DEPTH",
            "severity": "HIGH",
            "detail": f"Password-protected encrypted ZIP archive: {filename}"
        })
        if has_body_passwords:
            signals.append({
                "method": "VAL-44-ARCHIVE-ENCRYPTION-DEPTH",
                "severity": "CRITICAL",
                "detail": "Encrypted archive paired with in-body password (perimeter gateway evasion chain)"
            })

    return {
        "filename": filename,
        "declared_type": declared_type,
        "detected_type": detected_type,
        "detected_mime": detected_mime,
        "size_bytes": size,
        "sha256": sha256,
        "signals": signals
    }

# -------------------------------------------------------------
# MASTER COMPOSITE SCORING & CERTIFICATION SYNTHESIS
# -------------------------------------------------------------
SEVERITY_WEIGHT_MAP = {
    "CRITICAL": 35,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 4,
    "INFORMATIONAL": 1
}

def certify_email_legitimacy(headers_str: str, body_html: str, attachments: list) -> dict:
    # 1. Cryptographic Auth
    auth_eval = validate_cryptographic_auth(headers_str)
    # 2. Envelope & Hops
    env_eval = validate_envelope_and_hops(headers_str)
    # 3. Identity & Display
    id_eval = validate_identity_display(headers_str)
    # 4. URLs & Domains
    url_eval = validate_urls_and_links(body_html)
    # 5. Semantics & NLP
    nlp_eval = validate_semantics_nlp(body_html)
    
    # 6. Static Attachments
    has_body_passwords = len(nlp_eval["extracted_passwords"]) > 0
    att_evals = []
    for att in attachments:
        fn = att.get("filename", "")
        dt = att.get("declared_type", "")
        raw_b = bytes.fromhex(att.get("content_hex", "")) if "content_hex" in att else att.get("content_bytes", b"")
        att_res = validate_attachment_static(fn, dt, raw_b, has_body_passwords=has_body_passwords)
        att_evals.append(att_res)
        
    # Aggregate signals
    header_signals = auth_eval["signals"] + env_eval["signals"] + id_eval["signals"]
    body_signals = url_eval["signals"] + nlp_eval["signals"]
    attachment_signals = [s for a in att_evals for s in a["signals"]]
    
    is_authenticated = auth_eval["is_authenticated"]
    
    def score_component(sigs):
        if not sigs:
            return 0
        raw = sum(SEVERITY_WEIGHT_MAP.get(s["severity"], 10) * (0.4 if (is_authenticated and s["severity"] in ("MEDIUM", "LOW", "INFORMATIONAL")) else 1.0) for s in sigs)
        has_crit = any(s["severity"] == "CRITICAL" for s in sigs)
        has_high = any(s["severity"] == "HIGH" for s in sigs)
        if has_crit:
            return max(80, min(100, int(raw)))
        if has_high:
            return max(55, min(100, int(raw)))
        return min(100, int(raw))
        
    header_score = score_component(header_signals)
    body_score = score_component(body_signals)
    att_score = score_component(attachment_signals)
    
    has_att = len(attachments) > 0
    if has_att:
        composite = 0.25 * header_score + 0.35 * body_score + 0.40 * att_score
    else:
        composite = 0.40 * header_score + 0.60 * body_score
        
    max_comp = max(header_score, body_score, att_score if has_att else 0)
    if max_comp >= 80:
        composite = max(80.0, composite)
    elif max_comp >= 55:
        composite = max(70.0, composite)
    elif max_comp >= 35:
        composite = max(45.0, composite)
        
    composite = round(composite, 1)
    
    if composite >= 65.0:
        certification = "CERTIFIED FAKE / HIGH RISK PHISHING"
        status = "MALICIOUS"
    elif composite >= 30.0:
        certification = "SUSPICIOUS / ELEVATED RISK ANOMALY"
        status = "SUSPICIOUS"
    else:
        certification = "CERTIFIED LEGITIMATE / LOW RISK"
        status = "LEGITIMATE"
        
    return {
        "composite_score": composite,
        "certification": certification,
        "status": status,
        "sub_scores": {
            "header_score": header_score,
            "body_score": body_score,
            "attachment_score": att_score
        },
        "auth_status": auth_eval,
        "total_signals_detected": len(header_signals) + len(body_signals) + len(attachment_signals),
        "evidence_signals": header_signals + body_signals + attachment_signals,
        "attachment_inventory": att_evals
    }

if __name__ == '__main__':
    print("[*] Testing Master Validation Engine across benchmark cases...")
    with open("research/benchmarks/corpus/benchmark_corpus.json", "r", encoding="utf-8") as f:
        corpus = json.load(f)
        
    for c in corpus:
        res = certify_email_legitimacy(c["raw_headers"], c["body_text"], c.get("attachments", []))
        print(f"[{res['status']}] {c['id']}: Score {res['composite_score']} -> {res['certification']}")

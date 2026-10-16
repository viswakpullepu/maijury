import re
from urllib.parse import urlparse
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

URGENCY_PATTERNS = [
    (r'(?i)(?:\b(?:suspend(?:ed)?|suspension|terminat(?:ed|ion)|deactivat(?:ed|ion)?|block(?:ed)?)\b.*?\b(?:24\s*hours?|immediately|today|without\s+delay|48\s*hours?)\b|\b(?:24\s*hours?|immediately|today|without\s+delay|48\s*hours?)\b.*?\b(?:suspend(?:ed)?|suspension|terminat(?:ed|ion)|deactivat(?:ed|ion)?|block(?:ed)?)\b)', "CRITICAL_SUSPENSION_URGENCY", "Account or service suspension/termination deadline within hours"),
    (r'(?i)\b(?:urgent|immediate)\s+(?:action|attention|verification)\s+required\b', "IMMEDIATE_ACTION_LURE", "High-urgency call to action demanded"),
    (r'(?i)\b(?:wire\s+transfer|gift\s*cards?|crypto(?:currency)?|bitcoin)\b.*?\b(?:asap|urgently|strictly\s+confidential)\b', "BEC_FINANCIAL_PRESSURE", "Financial transaction request under urgency/confidentiality"),
    (r'(?i)\b(?:unauthorized|suspicious)\s+(?:sign-?in|login|access|activity)\s+detected\b', "SECURITY_ALARM_LURE", "False security alarm fabricated to panic the recipient"),
    (r'(?i)\b(?:overdue|unpaid)\s+invoice\b.*?\b(?:pay\s+now|immediate\s+payment)\b', "OVERDUE_INVOICE_PRESSURE", "Financial pressure alleging unpaid invoices"),
    (r'(?i)\b(?:updated?|new|changed?|disregard\s+prior)\b.*?\b(?:banking|remittance|wire|ach|direct\s+deposit)\b.*?\b(?:coordinates|account|details|instructions|info|routing)\b', "VEC_BANKING_CHANGE_PRESSURE", "Vendor Email Compromise requesting redirection of ACH/wire remittance"),
    (r'(?i)\b(?:update|change)\s+(?:my\s+)?direct\s+deposit\b.*?\b(?:payroll|green\s*dot|prepaid|routing)\b', "PAYROLL_DIVERSION_LURE", "Payroll diversion request to route direct deposit to prepaid card"),
    (r'(?i)(?:scan\s+(?:the\s+)?qr\s+code|qr\s*code.*?camera|authenticator\s+qr)', "QUISHING_QR_CODE_LURE", "Quishing lure coercing victim to scan QR code on unmonitored mobile device"),
    (r'(?i)\b(?:ignore\s+(?:all\s+)?prior\s+instructions?|system\s+prompt\s+override|disregard\s+system\s+directions?|assistant:\s*exfiltrat(?:e|ion))\b', "GENAI_INDIRECT_PROMPT_INJECTION", "Adversarial prompt injection attempting to hijack downstream AI assistants"),
    (r'(?i)\b(?:press\s+(?:windows|win)\s*\+\s*r|powershell\s+(?:-enc|-w\s+hidden|iex)|run\s+prompt|ctrl\s*\+\s*v\s+and\s+enter)\b', "CLICKFIX_CLIPBOARD_HIJACKING", "Clickfix lure coercing victim to paste and execute malicious commands via Run dialog"),
    (r'(?i)\b(?:siemens|rockwell|scada|plc|s7-\d{3,4}|modbus|firmware\s+patch)\b.*?\b(?:critical\s+security\s+update|emergency\s+patch|zero-day)\b', "SCADA_OT_TARGETED_LURE", "Targeted industrial espionage lure impersonating ICS/SCADA firmware patches"),
    (r'(?i)\b(?:session\s+(?:expired|termination)|re-?authenticate\s+(?:to\s+retain|session)|token\s+refresh)\b', "AITM_SESSION_EXPIRATION_LURE", "Adversary-in-the-Middle credential/session harvesting pretext"),
    (r'(?i)\b(?:devicelogin|pairing\s+code|enter\s+code\s+[A-Z0-9]{4,9}-[A-Z0-9]{4,9})\b', "OAUTH_DEVICE_CODE_LURE", "RFC 8628 Device Code Phishing coercing victim into authorizing malicious client")
]

ARCHIVE_PASSWORD_PATTERNS = [
    r'(?i)\b(?:password|passcode|pass|pwd|archive\s+key)\b\s*(?:is|:|=)\s*["\']?([A-Za-z0-9!@#$%^&*_\-]{3,30})["\']?'
]

def extract_domain(url_str):
    if not url_str:
        return ""
    if not url_str.startswith(('http://', 'https://')):
        url_str = 'http://' + url_str
    try:
        host = urlparse(url_str).netloc.lower()
        return host.split(':')[0]
    except Exception:
        return ""

def analyze_body_and_links(html_or_text: str):
    signals = []
    
    # 1. Check Urgency Lures
    for pattern, rule, desc in URGENCY_PATTERNS:
        match = re.search(pattern, html_or_text)
        if match:
            signals.append({
                "rule": rule,
                "severity": "HIGH" if any(k in rule for k in ["CRITICAL", "BEC", "VEC", "PAYROLL", "QUISHING", "PROMPT", "CLICKFIX", "SCADA", "AITM", "OAUTH"]) else "MEDIUM",
                "evidence": match.group(0)[:120],
                "explanation": desc
            })
            
    # 2. Check Archive Password in Email Body
    found_passwords = []
    for pattern in ARCHIVE_PASSWORD_PATTERNS:
        matches = re.finditer(pattern, html_or_text)
        for m in matches:
            found_passwords.append(m.group(1))
            signals.append({
                "rule": "ARCHIVE_PASSWORD_DISCLOSED_IN_BODY",
                "severity": "HIGH",
                "evidence": f"Password phrase matched: '{m.group(0)}' (extracted password: '{m.group(1)}')",
                "explanation": "Email text contains a password intended to unlock an encrypted attachment, a classic anti-scanner evasion tactic."
            })
            
    # 3. Check Link Text vs Href Mismatches (in HTML)
    # Match <a href="...">text</a>
    link_pattern = re.compile(r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
    for match in link_pattern.finditer(html_or_text):
        href = match.group(1).strip()
        link_text = re.sub(r'<[^>]+>', '', match.group(2)).strip()
        
        # Check if visible text looks like a URL or domain
        text_is_url = bool(re.search(r'(?:https?://|www\.)[a-zA-Z0-9\.\-_]+', link_text)) or any(d in link_text.lower() for d in ['.com', '.org', '.net', '.edu', '.gov'])
        
        if text_is_url:
            text_domain = extract_domain(link_text)
            href_domain = extract_domain(href)
            
            # Compare domains
            if text_domain and href_domain and text_domain != href_domain:
                signals.append({
                    "rule": "LINK_TEXT_HREF_MISMATCH",
                    "severity": "CRITICAL",
                    "evidence": f"Visible Text indicates '{text_domain}' but href points to '{href_domain}' ({href})",
                    "explanation": "Visible hyperlink deceptively mimics a trusted website while routing the victim to an attacker-controlled destination."
                })
                
    return {
        "signals": signals,
        "extracted_passwords": found_passwords
    }

if __name__ == '__main__':
    sample_phish_body = """
    <html>
    <body>
    <p>Dear Customer,</p>
    <p>Your account will be suspended within 24 hours due to an unauthorized login detected from Russia.</p>
    <p>Please click here to verify your account immediately: 
       <a href="http://192.168.1.55/update-security">https://www.paypal.com/security-center</a>
    </p>
    <p>We have also attached your detailed case file in the attached encrypted zip. The password is Doc2026! to unlock it.</p>
    </body>
    </html>
    """
    res = analyze_body_and_links(sample_phish_body)
    print("Body Analysis Signals Found:", len(res['signals']))
    for s in res['signals']:
        print(f"  [{s['severity']}] {s['rule']}: {s['evidence']}")

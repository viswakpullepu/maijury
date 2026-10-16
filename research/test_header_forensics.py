import email
import email.utils
import re
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

CONSUMER_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", 
    "proton.me", "protonmail.com", "icloud.com", "zoho.com", "yandex.com",
    "mail.com", "gmx.com"
}

AUTHORITY_KEYWORDS = [
    "help desk", "it support", "system administrator", "security alert", 
    "executive", "ceo", "cfo", "payroll", "human resources", "billing"
]

def analyze_headers(raw_headers: str):
    msg = email.message_from_string(raw_headers)
    
    from_raw = msg.get("From", "")
    reply_to_raw = msg.get("Reply-To", "")
    return_path_raw = msg.get("Return-Path", "")
    auth_results_raw = msg.get("Authentication-Results", "")
    received_spf_raw = msg.get("Received-SPF", "")
    
    from_name, from_addr = email.utils.parseaddr(from_raw)
    reply_name, reply_addr = email.utils.parseaddr(reply_to_raw)
    _, return_path_addr = email.utils.parseaddr(return_path_raw)
    
    from_domain = from_addr.split('@')[-1].lower() if '@' in from_addr else ""
    reply_domain = reply_addr.split('@')[-1].lower() if '@' in reply_addr else ""
    return_path_domain = return_path_addr.split('@')[-1].lower() if '@' in return_path_addr else ""
    
    signals = []
    
    # 1. Display-name deception: Embedded email address in display name
    email_in_display = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', from_name)
    if email_in_display:
        for emb in email_in_display:
            if emb.lower() != from_addr.lower():
                signals.append({
                    "rule": "DISPLAY_NAME_EMBEDDED_EMAIL_SPOOF",
                    "severity": "CRITICAL",
                    "evidence": f"Display name contains '{emb}' but actual sender is '{from_addr}'",
                    "explanation": "Attacker attempted to spoof sender identity by burying legitimate address in the display name."
                })
                
    # 2. Authority keyword from free/consumer mail provider
    name_lower = from_name.lower()
    for kw in AUTHORITY_KEYWORDS:
        if kw in name_lower and from_domain in CONSUMER_MAIL_DOMAINS:
            signals.append({
                "rule": "AUTHORITY_SPOOF_FREE_MAIL",
                "severity": "HIGH",
                "evidence": f"Sender claims authority '{from_name}' from consumer provider '@{from_domain}'",
                "explanation": "Executive or corporate IT personas originating from free consumer email services indicate impersonation."
            })
            break
            
    # 3. Reply-To / From Domain Mismatch
    if reply_domain and from_domain and reply_domain != from_domain:
        severity = "HIGH" if reply_domain in CONSUMER_MAIL_DOMAINS else "MEDIUM"
        signals.append({
            "rule": "REPLY_TO_DOMAIN_MISMATCH",
            "severity": severity,
            "evidence": f"From: @{from_domain} vs Reply-To: @{reply_domain}",
            "explanation": "Replies will be routed to a different external domain than the declared sender."
        })
        
    # 4. Return-Path Mismatch
    if return_path_domain and from_domain and return_path_domain != from_domain:
        signals.append({
            "rule": "RETURN_PATH_MISMATCH",
            "severity": "LOW",
            "evidence": f"From: @{from_domain} vs Return-Path: @{return_path_domain}",
            "explanation": "Envelope sender domain differs from From header (common in marketing ESPs or spoofing)."
        })
        
    # 5. Offline Authentication-Results Parsing (No DNS)
    auth_text = f"{auth_results_raw} {received_spf_raw}".lower()
    
    # SPF
    spf_match = re.search(r'\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)', auth_text)
    spf_status = spf_match.group(1) if spf_match else "none"
    if spf_status in ("fail", "softfail"):
        signals.append({
            "rule": "SPF_AUTHENTICATION_FAILED",
            "severity": "HIGH",
            "evidence": f"Recorded SPF status: {spf_status.upper()}",
            "explanation": "Sending IP was not authorized by the sender domain's SPF policy record."
        })
    elif spf_status in ("none", "neutral"):
        signals.append({
            "rule": "SPF_NOT_ENFORCED",
            "severity": "INFORMATIONAL",
            "evidence": f"Recorded SPF status: {spf_status.upper()}",
            "explanation": "Domain does not enforce strict SPF sending validation."
        })
        
    # DKIM
    dkim_match = re.search(r'\bdkim=(pass|fail|none)', auth_text)
    dkim_status = dkim_match.group(1) if dkim_match else "none"
    if dkim_status == "fail":
        signals.append({
            "rule": "DKIM_SIGNATURE_INVALID",
            "severity": "HIGH",
            "evidence": "Recorded DKIM status: FAIL",
            "explanation": "Cryptographic email signature failed verification or message body was altered in transit."
        })
        
    # DMARC
    dmarc_match = re.search(r'\bdmarc=(pass|fail|none)', auth_text)
    dmarc_status = dmarc_match.group(1) if dmarc_match else "none"
    if dmarc_status == "fail":
        signals.append({
            "rule": "DMARC_POLICY_FAILED",
            "severity": "CRITICAL",
            "evidence": "Recorded DMARC status: FAIL",
            "explanation": "Message failed domain alignment and authentication checks defined by DMARC policy."
        })

    return {
        "from": from_raw,
        "from_addr": from_addr,
        "reply_to": reply_to_raw,
        "return_path": return_path_raw,
        "spf_status": spf_status,
        "dkim_status": dkim_status,
        "dmarc_status": dmarc_status,
        "signals": signals
    }

if __name__ == '__main__':
    sample_phish_headers = """From: "IT Support <support@company.com>" <attacker992@gmail.com>
Reply-To: wire-transfers@freemail-inbox.net
Return-Path: <bounces@mass-spam.org>
Authentication-Results: mx.google.com; spf=fail (google.com: domain does not designate IP); dkim=fail; dmarc=fail
Subject: URGENT: Password Expiring Today
Date: Fri, 16 Oct 2026 10:14:00 +0000
"""
    result = analyze_headers(sample_phish_headers)
    print("Analyzed Headers Result:")
    print("From:", result['from'])
    print("SPF:", result['spf_status'], "| DKIM:", result['dkim_status'], "| DMARC:", result['dmarc_status'])
    print("Signals found:", len(result['signals']))
    for s in result['signals']:
        print(f"  [{s['severity']}] {s['rule']}: {s['evidence']}")

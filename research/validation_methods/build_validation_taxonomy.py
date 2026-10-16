import json
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

VALIDATION_METHODS_TAXONOMY = {
    "title": "Exhaustive Taxonomy of Email Validation & Legitimacy Certification Methodologies",
    "total_layers": 8,
    "total_methods": 48,
    "layers": [
        {
            "layer_id": "LAYER-01-CRYPTOGRAPHIC-AUTH",
            "name": "Protocol & Cryptographic Authentication Layer",
            "description": "Mathematical and cryptographic proof of sender identity, domain authorization, and message transit integrity.",
            "methods": [
                {
                    "code": "VAL-01-SPF",
                    "name": "Sender Policy Framework (SPF - RFC 7208)",
                    "mechanism": "Validates connecting MTA IP address against the DNS TXT SPF record published by the envelope sender (Return-Path) domain.",
                    "status_outcomes": ["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"],
                    "threats_stopped": "Simple envelope spoofing, unauthorized botnet relays.",
                    "blind_spots": "Breaks upon email forwarding; does not authenticate the visible From header."
                },
                {
                    "code": "VAL-02-DKIM",
                    "name": "DomainKeys Identified Mail (DKIM - RFC 6376)",
                    "mechanism": "Verifies asymmetric public-key cryptographic signature (RSA or Ed25519) of message headers and body hash (bh=).",
                    "status_outcomes": ["pass", "fail", "none"],
                    "threats_stopped": "Man-in-the-middle transit modification, body tampering.",
                    "blind_spots": "Replay attacks using valid signatures to new recipients; does not mandate alignment with From header on its own."
                },
                {
                    "code": "VAL-03-DMARC",
                    "name": "Domain-based Message Authentication, Reporting, and Conformance (DMARC - RFC 7489)",
                    "mechanism": "Requires domain alignment between visible From domain and SPF/DKIM authenticated domain. Enforces p=none, p=quarantine, or p=reject.",
                    "status_outcomes": ["pass", "fail (p=none)", "fail (p=quarantine)", "fail (p=reject)"],
                    "threats_stopped": "Direct domain spoofing of visible From header.",
                    "blind_spots": "Does not stop lookalike domains, typosquatting, or display name spoofing."
                },
                {
                    "code": "VAL-04-ARC",
                    "name": "Authenticated Received Chain (ARC - RFC 8617)",
                    "mechanism": "Preserves cryptographic authentication state across intermediate forwarding hops (mailing lists, relays) via ARC-Authentication-Results, ARC-Message-Signature, and ARC-Seal.",
                    "status_outcomes": ["pass", "fail", "none"],
                    "threats_stopped": "Authentication breakage caused by legitimate email list servers and automated forwarding rules.",
                    "blind_spots": "Trust depends entirely on the reputation of the intermediate ARC sealing MTA."
                },
                {
                    "code": "VAL-05-BIMI",
                    "name": "Brand Indicators for Message Identification (BIMI)",
                    "mechanism": "Displays brand trademark logo in supported email clients if the domain enforces DMARC (p=quarantine/reject) and holds a Verified Mark Certificate (VMC) from an authorized CA.",
                    "status_outcomes": ["verified", "unverified", "none"],
                    "threats_stopped": "Visual brand impersonation in consumer webmail clients (Gmail, Apple Mail, Yahoo).",
                    "blind_spots": "Does not protect internal B2B enterprise communications that don't render BIMI."
                },
                {
                    "code": "VAL-06-SMIME",
                    "name": "Secure/Multipurpose Internet Mail Extensions (S/MIME - RFC 8550)",
                    "mechanism": "End-to-end digital signature using X.509 PKI certificate issued to individual sender address. Validates certificate chain up to trusted CA and checks revocation (CRL/OCSP).",
                    "status_outcomes": ["valid_signature", "invalid_signature", "untrusted_root", "revoked", "unsigned"],
                    "threats_stopped": "All forms of sender address spoofing, MTA compromise, and tampering.",
                    "blind_spots": "Requires PKI infrastructure deployment; difficult to manage at global scale."
                },
                {
                    "code": "VAL-07-OPENPGP",
                    "name": "OpenPGP Email Signatures (RFC 4880 / RFC 9580)",
                    "mechanism": "End-to-end cryptographic PGP/GPG signature using Web of Trust or Web Key Directory (WKD) public key verification.",
                    "status_outcomes": ["good_signature", "bad_signature", "unknown_key"],
                    "threats_stopped": "Sender spoofing, transit tampering.",
                    "blind_spots": "High technical barrier for non-technical users."
                },
                {
                    "code": "VAL-08-MTA-STS",
                    "name": "SMTP MTA Strict Transport Security (MTA-STS - RFC 8461)",
                    "mechanism": "Enforces mandatory TLS encryption policy for inbound SMTP connections, published via HTTPS and DNS TXT record.",
                    "status_outcomes": ["enforced", "testing", "none"],
                    "threats_stopped": "STARTTLS downgrade attacks, DNS hijacking of MX records.",
                    "blind_spots": "Trust on first use (TOFU) vulnerability on initial policy fetch."
                },
                {
                    "code": "VAL-09-DANE",
                    "name": "DNS-based Authentication of Named Entities (DANE - RFC 7672)",
                    "mechanism": "Pins TLS server certificates for SMTP via TLSA DNS records secured with DNSSEC.",
                    "status_outcomes": ["dane_verified", "dane_failed", "none"],
                    "threats_stopped": "Rogue Certificate Authority issuance, active BGP route hijacking.",
                    "blind_spots": "Requires full DNSSEC deployment on authoritative nameservers."
                },
                {
                    "code": "VAL-10-TLS-CIPHER",
                    "name": "Hop-by-Hop TLS Cipher Suite & Protocol Auditing",
                    "mechanism": "Inspects Received headers for TLS version (TLS 1.3 vs legacy TLS 1.0/1.1) and cipher strength (AES-256-GCM, CHACHA20-POLY1305).",
                    "status_outcomes": ["tls13_strong", "tls12_acceptable", "plaintext_unencrypted", "deprecated_cipher"],
                    "threats_stopped": "Plaintext eavesdropping over SMTP transport.",
                    "blind_spots": "Only guarantees encryption between adjacent hops, not end-to-end."
                }
            ]
        },
        {
            "layer_id": "LAYER-02-ENVELOPE-TRANSPORT",
            "name": "Envelope & Transport Header Forensics",
            "description": "Forensic reconstruction of transmission hops, server reputations, and message structure metadata.",
            "methods": [
                {
                    "code": "VAL-11-ENVELOPE-ALIGNMENT",
                    "name": "RFC 5321 (MAIL FROM) vs RFC 5322 (From) Domain Alignment",
                    "mechanism": "Compares envelope bounce address (Return-Path) domain against visible From domain.",
                    "threats_stopped": "Attacker displaying legitimate From address while routing bounce receipts to attack server."
                },
                {
                    "code": "VAL-12-RECEIVED-TRACE",
                    "name": "Chronological Hop Trace & Originating IP Extraction",
                    "mechanism": "Walks the Received: header chain backwards from recipient MTA to locate the true initial submission MTA IP address.",
                    "threats_stopped": "Forged Received headers injected by attackers to hide source IP."
                },
                {
                    "code": "VAL-13-RDNS-PTR",
                    "name": "Reverse DNS (PTR) & FCrDNS Verification",
                    "mechanism": "Verifies that the sending IP resolves via PTR to a hostname that resolves forward (Forward-Confirmed reverse DNS) back to the same IP.",
                    "threats_stopped": "Residential broadband IP relays, compromised home routers, bulletproof hosters."
                },
                {
                    "code": "VAL-14-HELO-ALIGNMENT",
                    "name": "HELO / EHLO Domain Identity Validation",
                    "mechanism": "Compares the hostname sent during SMTP HELO/EHLO against sending IP's rDNS name.",
                    "threats_stopped": "HELO forgery (e.g. attacker claiming HELO mail.google.com from Russian residential IP)."
                },
                {
                    "code": "VAL-15-BOGON-IP",
                    "name": "Bogon & RFC 1918 Private IP Leakage Audit",
                    "mechanism": "Flags external perimeter emails claiming initial hops from unroutable/private IP ranges (10.0.0.0/8, 192.168.0.0/16, 127.0.0.0/8).",
                    "threats_stopped": "Spoofed internal relay headers in external email."
                },
                {
                    "code": "VAL-16-TRANSIT-LATENCY",
                    "name": "Timestamp Monotonicity & Transit Latency Analysis",
                    "mechanism": "Calculates delta between successive Received header timestamps. Detects negative travel time or suspicious multi-day holding periods.",
                    "threats_stopped": "Forged timestamps, staged attack relays."
                },
                {
                    "code": "VAL-17-MESSAGE-ID-INTEGRITY",
                    "name": "Message-ID Syntax & Domain Entropy Verification",
                    "mechanism": "Validates format `<unique-id@domain>` against known MTA generators (Postfix, Sendmail, Exchange, Gmail).",
                    "threats_stopped": "Mass-mailer default templates, missing Message-ID headers."
                },
                {
                    "code": "VAL-18-X-MAILER-FINGERPRINT",
                    "name": "X-Mailer & User-Agent Stack Fingerprinting",
                    "mechanism": "Compares declared client (e.g. Outlook 365) against typical headers produced by Microsoft Exchange (e.g. X-MS-Exchange-Organization-*).",
                    "threats_stopped": "Attack scripts (PHPMailer, Python smtplib) masquerading as desktop Microsoft Outlook."
                }
            ]
        },
        {
            "layer_id": "LAYER-03-IDENTITY-DISPLAY",
            "name": "Identity & Display Name Spoofing Defense",
            "description": "Defeating social engineering at the human interface level where attackers manipulate visual display strings.",
            "methods": [
                {
                    "code": "VAL-19-DISPLAY-NAME-EMBEDDED-EMAIL",
                    "name": "Embedded Email Address Spoofing Parser",
                    "mechanism": "Extracts email addresses buried inside display name string (e.g. `\"CEO <ceo@company.com>\" <attacker@external.org>`) using parseaddr token separation.",
                    "threats_stopped": "Display name address camouflage attacks."
                },
                {
                    "code": "VAL-20-EXECUTIVE-VIP-MATCH",
                    "name": "Executive & VIP Persona Distance Matching",
                    "mechanism": "Matches display name against corporate directory executive names. Flags when exact match occurs from external unauthenticated email.",
                    "threats_stopped": "CEO fraud, Board member impersonation."
                },
                {
                    "code": "VAL-21-CONSUMER-AUTHORITY-FLAG",
                    "name": "Authority Persona on Free Webmail Flag",
                    "mechanism": "Detects corporate authority titles ('Help Desk', 'IT Support', 'Payroll', 'Security') originating from consumer domains (@gmail.com, @yahoo.com).",
                    "threats_stopped": "Imposter helpdesk tickets, HR direct deposit scams."
                },
                {
                    "code": "VAL-22-REPLY-TO-DIVERGENCE",
                    "name": "Reply-To Channel Drift Detection",
                    "mechanism": "Calculates divergence between From domain and Reply-To domain. Flags external forwarding traps.",
                    "threats_stopped": "BEC wire fraud reply redirection."
                },
                {
                    "code": "VAL-23-ZERO-WIDTH-DISPLAY-NAME",
                    "name": "Zero-Width Character Injection in Display Name",
                    "mechanism": "Scans display names for invisible Unicode formatting characters (U+200B, U+200C, U+FEFF) used to bypass exact-string blacklist filters.",
                    "threats_stopped": "Bypassing executive name alert rules."
                }
            ]
        },
        {
            "layer_id": "LAYER-04-DOMAIN-URL",
            "name": "Domain, Hostname & URL Forensics",
            "description": "Algorithmic and structural analysis of web destinations embedded in messages.",
            "methods": [
                {
                    "code": "VAL-24-LINK-TEXT-HREF-MISMATCH",
                    "name": "Hyperlink Visible Text vs Href Target Mismatch",
                    "mechanism": "Parses HTML `<a>` tags. Extracts visible text domain and compares against href target domain. Flags divergence.",
                    "threats_stopped": "Anchor text deception (the #1 credential phishing delivery method)."
                },
                {
                    "code": "VAL-25-PUNYCODE-IDN-DECODE",
                    "name": "Internationalized Domain Name (IDN) Punycode Decoding",
                    "mechanism": "Decodes `xn--` domain prefixes to underlying Unicode representation per RFC 3492.",
                    "threats_stopped": "Hidden Cyrillic/Greek homoglyphs disguised in ASCII Punycode."
                },
                {
                    "code": "VAL-26-HOMOGLYPH-NORMALIZATION",
                    "name": "Visual Homoglyph Canonicalization",
                    "mechanism": "Maps visually identical Unicode glyphs (Cyrillic а, е, о, р, с, у, х; numeric 0, 1) to standard ASCII equivalents before brand evaluation.",
                    "threats_stopped": "Cyrillic lookalikes targeting high-value enterprise brands."
                },
                {
                    "code": "VAL-27-DAMERAU-LEVENSHTEIN-BRAND",
                    "name": "Damerau-Levenshtein Edit Distance Scoring",
                    "mechanism": "Computes transposition, insertion, deletion, and substitution cost against top 100 enterprise brand dictionaries.",
                    "threats_stopped": "Typosquatting (e.g. micros0ft.com, paypa1.com)."
                },
                {
                    "code": "VAL-28-COMBOSQUATTING-DETECTION",
                    "name": "Combosquatting & Keyword Stuffing Analyzer",
                    "mechanism": "Detects legitimate brand tokens paired with security/portal words (e.g. `paypal-security-update.com`).",
                    "threats_stopped": "Compound domain lures."
                },
                {
                    "code": "VAL-29-SUBDOMAIN-MASKING",
                    "name": "Subdomain Camouflage & Deep Nesting Analysis",
                    "mechanism": "Extracts effective top-level domain plus one (eTLD+1). Flags when brand name exists in subdomain of an unrelated domain.",
                    "threats_stopped": "`login.microsoftonline.com.evil-portal.net` deception."
                },
                {
                    "code": "VAL-30-IP-LITERAL-URL",
                    "name": "IP Literal Hostname Detection",
                    "mechanism": "Detects raw IPv4, IPv6, dword, octal, or hex IP addresses in URL host components.",
                    "threats_stopped": "Bypassing domain registration and DNS takedowns."
                },
                {
                    "code": "VAL-31-OPEN-REDIRECT-PARAM",
                    "name": "Open Redirect Parameter Scanner",
                    "mechanism": "Parses URL query strings for redirection parameters (`url=`, `redirect=`, `next=`, `dest=`) pointing off-site.",
                    "threats_stopped": "Abusing trusted brand domains (e.g. `google.com/url?q=...`) to route to phishing."
                },
                {
                    "code": "VAL-32-AT-SIGN-URL-TRICK",
                    "name": "Userinfo At-Sign (@) Deception Filter",
                    "mechanism": "Detects URLs using `http://trusted.com@evil.com/login` where browser connects strictly to host following the `@` symbol.",
                    "threats_stopped": "Visual URI prefix deception."
                }
            ]
        },
        {
            "layer_id": "LAYER-05-SEMANTIC-NLP",
            "name": "Semantic, Cognitive & Lexical Forensics",
            "description": "Natural language processing and psychological manipulation pattern detection.",
            "methods": [
                {
                    "code": "VAL-33-NLP-URGENCY",
                    "name": "Coercive Urgency & Artificial Deadline Detection",
                    "mechanism": "Contextual regex/NLP scanning for time-pressure triggers ('within 24 hours', 'immediate action required', 'account deactivated today').",
                    "threats_stopped": "Panic-induced decision bypassing."
                },
                {
                    "code": "VAL-34-FINANCIAL-PRESSURE",
                    "name": "Financial Transaction Coercion Patterns",
                    "mechanism": "Lexical scoring on wire transfer requests, cryptocurrency deposits, gift card purchases, and prepaid card routing.",
                    "threats_stopped": "Direct financial fraud, payroll diversion."
                },
                {
                    "code": "VAL-35-INVISIBLE-UNICODE-CLEANER",
                    "name": "Zero-Width Space & Bidi Character Stripper",
                    "mechanism": "Scans message body for zero-width spaces (U+200B), zero-width non-joiners (U+200C), and soft hyphens inserted between characters to defeat keyword rules.",
                    "threats_stopped": "Evasion of signature-based keyword filters."
                },
                {
                    "code": "VAL-36-IMAGE-ONLY-BODY-DETECTOR",
                    "name": "Text-to-Image Evasion Detection",
                    "mechanism": "Calculates body text character count vs inline image count. Flags emails consisting solely of a single large clickable image.",
                    "threats_stopped": "Bypassing text analysis by rendering phishing text into JPEG/PNG images."
                },
                {
                    "code": "VAL-37-PASSWORD-IN-BODY-CORRELATION",
                    "name": "Archive Password in Body Cross-Correlation",
                    "mechanism": "Detects regex phrases like `password is: <token>` and cross-references against attached encrypted archives.",
                    "threats_stopped": "Anti-scanner gateway evasion for encrypted payloads."
                }
            ]
        },
        {
            "layer_id": "LAYER-06-STATIC-ATTACHMENTS",
            "name": "Static In-Memory Attachment Forensics (Zero Execution)",
            "description": "Structural, syntactic, and metadata inspection of binary streams without executing code or rendering documents.",
            "methods": [
                {
                    "code": "VAL-38-MAGIC-BYTES",
                    "name": "Binary Magic Bytes (File Signature) Validation",
                    "mechanism": "Inspects initial file header bytes against authoritative magic signature dictionary. Flags extension/MIME mismatches.",
                    "threats_stopped": "Disguised Windows executables (MZ) named as PDF, DOCX, or JPG."
                },
                {
                    "code": "VAL-39-DOUBLE-EXTENSION",
                    "name": "Deceptive Double Extension Scanner",
                    "mechanism": "Regex matching against document extension followed by executable extension (e.g. `.pdf.exe`, `.docx.vbs`, `.xlsx.iso`).",
                    "threats_stopped": "Exploiting Windows default setting to hide known file extensions."
                },
                {
                    "code": "VAL-40-UNICODE-RTLO",
                    "name": "Unicode Right-to-Left Override (RTLO U+202E) Inspection",
                    "mechanism": "Scans filenames for character code U+202E and bidirectional isolates that invert displayed extension characters.",
                    "threats_stopped": "Displaying executable files as documents (e.g. `file_exe.pdf`)."
                },
                {
                    "code": "VAL-41-STATIC-OOXML-MACRO",
                    "name": "Static OOXML / OLE Macro Parser",
                    "mechanism": "In-memory zip traversal of OOXML files checking for `word/vbaProject.bin`. Scans binary macro streams for `AutoOpen`, `Shell`, `powershell`, `URLDownloadToFile` without launching Office.",
                    "threats_stopped": "Weaponized Office document droppers."
                },
                {
                    "code": "VAL-42-STATIC-PDF-TOKENIZER",
                    "name": "Static PDF Object Tokenizer",
                    "mechanism": "Parses PDF dictionary streams without rendering. Detects dangerous active tokens: `/JavaScript`, `/JS`, `/OpenAction`, `/Launch`, `/EmbeddedFiles`, `/AA`.",
                    "threats_stopped": "PDF exploit droppers and automatic script triggers."
                },
                {
                    "code": "VAL-43-HTML-SMUGGLING-DETECTOR",
                    "name": "HTML Smuggling & Credential Form Scanner",
                    "mechanism": "Parses attached HTML files for embedded `<form>` with `<input type=\"password\">` and JavaScript Blob/Data URI reconstruction primitives.",
                    "threats_stopped": "Local offline phishing forms, browser-side file assembly."
                },
                {
                    "code": "VAL-44-ARCHIVE-ENCRYPTION-DEPTH",
                    "name": "In-Memory Archive Traversal & Recursion Depth Limiter",
                    "mechanism": "Inspects ZIP headers for encryption bit (0x01). Recursively inspects inner entries up to depth 2. Enforces maximum 100:1 compression ratio.",
                    "threats_stopped": "Password-protected evasion, recursive zip bombs (decompression bombs)."
                }
            ]
        },
        {
            "layer_id": "LAYER-07-BEHAVIORAL-CONTEXT",
            "name": "Behavioral & Baseline Analytics Layer",
            "description": "Historical profiling of sender-recipient interactions and organizational communication patterns.",
            "methods": [
                {
                    "code": "VAL-45-COMMUNICATION-RECIPROCITY",
                    "name": "Historical Communication Reciprocity Check",
                    "mechanism": "Checks whether the recipient has ever previously exchanged emails with this external sender.",
                    "threats_stopped": "First-time sender anomalies, sudden unexpected contacts."
                },
                {
                    "code": "VAL-46-DOMAIN-AGE-MATURITY",
                    "name": "Domain Registration Age & WHOIS Maturity",
                    "mechanism": "Flags domains registered within the last 30 days (newly registered domains represent >85% of active phishing infrastructure).",
                    "threats_stopped": "Burner domains, disposable phishing infrastructure."
                }
            ]
        },
        {
            "layer_id": "LAYER-08-HUMAN-OUT-OF-BAND",
            "name": "Out-of-Band & Human Verification Layer",
            "description": "Operational protocols and administrative controls that defeat social engineering when technical controls are ambiguous.",
            "methods": [
                {
                    "code": "VAL-47-OUT-OF-BAND-PHONE-VERIFY",
                    "name": "Out-of-Band Phone/Directory Verification Protocol",
                    "mechanism": "Requires verifying financial/credential requests by placing an out-of-band telephone call using pre-established corporate directory numbers (never email numbers).",
                    "threats_stopped": "Sophisticated BEC attacks with compromised email accounts."
                },
                {
                    "code": "VAL-48-DUAL-CUSTODY-AUTHORIZATION",
                    "name": "Dual-Custody Financial Authorization Protocol",
                    "mechanism": "Mandates that wire transfers, banking changes, and payroll updates require two independent authorizations across separate communication channels.",
                    "threats_stopped": "Single-point-of-failure wire fraud."
                }
            ]
        }
    ]
}

def save_validation_taxonomy():
    with open("research/validation_methods/comprehensive_validation_taxonomy.json", "w", encoding="utf-8") as f:
        json.dump(VALIDATION_METHODS_TAXONOMY, f, indent=2)
    print(f"[+] Successfully compiled comprehensive validation taxonomy ({VALIDATION_METHODS_TAXONOMY['total_methods']} methods across {VALIDATION_METHODS_TAXONOMY['total_layers']} layers).")

if __name__ == '__main__':
    save_validation_taxonomy()

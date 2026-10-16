"""
Actionable Recommendations Engine for MailJury Courtroom
Adheres to:
  - NIST SP 800-61r2 (Computer Security Incident Handling Guide)
  - CISA / FBI Business Email Compromise (BEC) & Phishing Mitigation Guidance
  - NSA / CISA Defensive Guidance for Untrusted File Execution & CDR
  - Indian Bharatiya Sakshya Adhiniyam (BSA) 2023 §65B Digital Chain of Custody
"""

from typing import Dict, Any, List, Optional
import os


class RecommendationCategory:
    QUARANTINE = "QUARANTINE"
    VERIFY_SENDER = "VERIFY_SENDER"
    SAFE_VIEWER = "SAFE_VIEWER"
    INCIDENT_RESPONSE = "INCIDENT_RESPONSE"
    USER_HYGIENE = "USER_HYGIENE"


class RecommendationPriority:
    IMMEDIATE = "IMMEDIATE"   # P1 - Critical Threat Active
    HIGH = "HIGH"             # P2 - Urgent Action Required
    MEDIUM = "MEDIUM"         # P3 - Precautionary Action
    ADVISORY = "ADVISORY"     # P4 - Standard Cyber Hygiene


class SafeViewerType:
    DISASSEMBLY_SANDBOX = "DISASSEMBLY_SANDBOX"       # PE binaries, scripts, native droppers
    ISOLATED_WEB_VIEWER = "ISOLATED_WEB_VIEWER"       # Office docs with macros, RTF, templates
    HARDENED_PDF_VIEWER = "HARDENED_PDF_VIEWER"       # PDFs, PDF forms
    DISPOSABLE_CONTAINER = "DISPOSABLE_CONTAINER"     # Encrypted / passworded ZIP, RAR, 7z
    STANDARD_SAFE_VIEWER = "STANDARD_SAFE_VIEWER"     # Verified benign invoices, images, plain text


class ActionableRecommendationEngine:
    """
    Synthesizes concrete, prioritized, and context-tailored actionable recommendations:
      1. Quarantine & Mailbox Isolation
      2. Official Out-of-Band Sender Verification
      3. Safe Viewer & Zero-Execution File Inspection
      4. Incident Response & Evidence Preservation
    """

    @classmethod
    def generate_attachment_recommendations(
        cls,
        filename: str,
        extension: str,
        detected_type: str,
        risk_level: str,
        risk_score: float,
        classification: str,
        evidence: List[str]
    ) -> Dict[str, Any]:
        """
        Generates granular safe viewer, quarantine, and sender verification instructions
        for an individual email attachment based on static byte forensics.
        """
        ext = (extension or "").lower()
        det = (detected_type or "").lower()
        ev_str = " ".join(evidence).lower()

        # ── 1. Determine Safe Viewer Profile ─────────────────────────────────────
        is_pe_or_exec = (
            "application/x-dosexec" in det
            or "application/x-executable" in det
            or "application/x-mach-binary" in det
            or "application/x-sh" in det
            or ext in (".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".cpl", ".lnk", ".iso", ".img")
            or "mz" in ev_str or "pe binary" in ev_str or "renamed executable" in ev_str
        )
        is_macro_or_office = (
            "macro" in ev_str or "vba" in ev_str or "template injection" in ev_str
            or "equation editor" in ev_str or "dde" in ev_str or "rtf" in ev_str
            or ext in (".doc", ".docm", ".docx", ".xls", ".xlsm", ".xlsx", ".ppt", ".pptm", ".pptx", ".rtf")
        )
        is_pdf = "pdf" in det or ext == ".pdf"
        is_archive = "zip" in det or "rar" in det or "7z" in det or ext in (".zip", ".rar", ".7z", ".tar", ".gz")
        is_encrypted_archive = is_archive and ("encrypted" in ev_str or "password" in ev_str or "pkware" in ev_str)

        if risk_level == "MALICIOUS":
            if is_pe_or_exec:
                viewer_type = SafeViewerType.DISASSEMBLY_SANDBOX
                rec_viewer = "Static Disassembly & In-Memory Hex Inspection (Ghidra / radare2 / Isolated CAPE Sandbox)"
                prohibited = [
                    "DO NOT double-click or launch on any Windows/Linux/macOS host.",
                    "DO NOT rename extension and attempt native execution.",
                    "DO NOT open inside standard user virtual desktops or terminal shells."
                ]
                instructions = [
                    "Isolate the file payload in memory. Do not persist to host filesystem.",
                    "If reverse engineering is authorized, import binary into an isolated, network-disconnected container.",
                    "Inspect PE headers (DOS stub, Section Table, Import Address Table) using static disassemblers like Ghidra, Cutter, or radare2.",
                    "Submit SHA-256 hash to Threat Intelligence feeds (VirusTotal / MISP) to correlate known malware campaign indicators."
                ]
                safe_tools = ["MailJury In-Memory Inspector", "Ghidra (Offline)", "radare2 / Cutter", "CAPE Sandbox (Air-Gapped)", "CyberChef"]

            elif is_macro_or_office:
                viewer_type = SafeViewerType.ISOLATED_WEB_VIEWER
                rec_viewer = "Hardened Cloud Web Viewer or Dangerzone (Macros Disabled)"
                prohibited = [
                    "DO NOT open in desktop Microsoft Word / Excel / PowerPoint.",
                    "DO NOT enable macros or click 'Enable Content' under any circumstance.",
                    "DO NOT bypass Word Protected View or Office Trust Center warnings."
                ]
                instructions = [
                    "Inspect document content strictly via an isolated web-based sandbox (Google Docs web preview or Microsoft 365 Cloud Viewer with Application Guard).",
                    "Alternatively, sanitize the document with Dangerzone (which converts untrusted Office documents to pixel-only PDFs inside an ephemeral container).",
                    "To audit embedded macro streams, extract `vbaProject.bin` statically using `oletools` (`olevba`, `mraptor`) in a non-Windows Linux terminal."
                ]
                safe_tools = ["Dangerzone", "Google Docs Web Sandbox", "Microsoft 365 Cloud Viewer (Application Guard)", "oletools (olevba / oledump)", "LibreOffice in Docker (--network none)"]

            elif is_pdf:
                viewer_type = SafeViewerType.HARDENED_PDF_VIEWER
                rec_viewer = "Hardened Web PDF Viewer (JavaScript Disabled) or Dangerzone Sanitizer"
                prohibited = [
                    "DO NOT open in unpatched desktop Adobe Acrobat / Reader with dynamic JavaScript active.",
                    "DO NOT allow execution of embedded actions (/Launch, /OpenAction, /SubmitForm).",
                    "DO NOT follow embedded clickable hyperlinks."
                ]
                instructions = [
                    "Open exclusively in a hardened Chromium/Firefox PDF.js sandbox with Acrobat JavaScript completely disabled.",
                    "Use Dangerzone to re-render the document into sterile rasterized pixels, stripping all active code streams.",
                    "For deep static audit, inspect PDF dictionaries using `pdfid`, `peepdf`, or `pdf-parser` without PDF rendering."
                ]
                safe_tools = ["Dangerzone (Pixel Sanitizer)", "Chromium PDF.js (JS Disabled)", "pdfid / pdf-parser (Didier Stevens)", "pdftotext (Poppler Utilities)"]

            elif is_encrypted_archive:
                viewer_type = SafeViewerType.DISPOSABLE_CONTAINER
                rec_viewer = "Ephemeral Disposable VM or Docker Container (--network none)"
                prohibited = [
                    "DO NOT extract archive using desktop Windows Explorer or 7-Zip on primary workstation.",
                    "DO NOT enter credentials found in email body to unzip file on corporate endpoint.",
                    "DO NOT execute extracted payloads."
                ]
                instructions = [
                    "Spawn an ephemeral Docker container or air-gapped Linux disposable VM with network egress blocked.",
                    "Inspect member file headers, CRC-32 hashes, and file extensions using static tools (`unzip -l`, `7z l`).",
                    "Perform static file signature inspection on extracted members before any opening attempts."
                ]
                safe_tools = ["Ephemeral Docker (`--network none`)", "Qubes OS Disposable VM", "Isolated Linux Sandbox"]

            else:
                viewer_type = SafeViewerType.DISASSEMBLY_SANDBOX
                rec_viewer = "Isolated File Forensics Sandbox"
                prohibited = ["DO NOT open or launch on host operating system."]
                instructions = ["Analyze raw bytes in volatile memory. Perform static signature matching."]
                safe_tools = ["MailJury Static Inspector", "CyberChef", "Hex Fiend (Isolated)"]

            quarantine_action = "IMMEDIATE_QUARANTINE_REQUIRED"
            quarantine_instructions = (
                f"Quarantine attachment '{filename}' immediately. Block SHA-256 hash ({risk_score}/100 risk) at perimeter "
                f"mail gateway and enterprise EDR. Strip file from all recipient mailboxes."
            )
            verification_needed = True
            verification_text = (
                f"Verify purported sender through an official out-of-band channel immediately. "
                f"High-probability malicious payload disguised as '{filename}'."
            )

        elif risk_level == "SUSPICIOUS":
            if is_encrypted_archive:
                viewer_type = SafeViewerType.DISPOSABLE_CONTAINER
                rec_viewer = "Ephemeral Container Sandbox / Disposable VM"
                prohibited = ["DO NOT decompress on primary workstation until sender confirms transmission."]
                instructions = [
                    "Contact the sender via verified out-of-band communication (phone/Teams) to confirm intentional encryption.",
                    "Inspect archive structure inside an isolated disposable VM or Docker container without internet access."
                ]
                safe_tools = ["Ephemeral Docker Container", "Qubes OS Disposable VM"]
            elif is_macro_or_office:
                viewer_type = SafeViewerType.ISOLATED_WEB_VIEWER
                rec_viewer = "Cloud Web Viewer with Protected View (Macros Disabled)"
                prohibited = ["DO NOT enable macros or click 'Enable Content'."]
                instructions = [
                    "Review document via Google Docs / Office 365 Cloud Web Viewer.",
                    "Ensure macro automation remains disabled during inspection."
                ]
                safe_tools = ["Google Docs Web Sandbox", "Office 365 Cloud Viewer", "Dangerzone"]
            elif is_pdf:
                viewer_type = SafeViewerType.HARDENED_PDF_VIEWER
                rec_viewer = "Hardened Browser PDF Sandbox"
                prohibited = ["DO NOT open links or execute interactive form controls."]
                instructions = ["View inside browser-based PDF previewer with JavaScript execution toggled off."]
                safe_tools = ["Chromium PDF Viewer", "Firefox PDF.js (JS Disabled)"]
            else:
                viewer_type = SafeViewerType.ISOLATED_WEB_VIEWER
                rec_viewer = "Isolated Document Previewer"
                prohibited = ["DO NOT run dynamic components."]
                instructions = ["Inspect file structure before native opening."]
                safe_tools = ["Cloud Web Preview", "CyberChef"]

            quarantine_action = "HOLD_FOR_SOC_REVIEW"
            quarantine_instructions = f"Hold attachment '{filename}' in quarantine pending analyst triage or sender verification."
            verification_needed = True
            verification_text = f"Contact sender via official corporate directory to confirm if '{filename}' was genuinely sent."

        else:
            # SAFE
            viewer_type = SafeViewerType.STANDARD_SAFE_VIEWER
            rec_viewer = "Standard Document / Image Viewer (Certified Clean)"
            prohibited = ["No special viewer restrictions. Maintain baseline operational accounting hygiene."]
            instructions = [
                f"Attachment '{filename}' certified safe by zero-execution static byte forensics.",
                "Safe for normal opening in standard desktop or mobile document viewers."
            ]
            safe_tools = ["Standard PDF Viewer", "Microsoft Office", "Native Image Viewer"]
            quarantine_action = "CLEARED_NO_QUARANTINE"
            quarantine_instructions = f"Attachment '{filename}' certified safe. No quarantine required."
            verification_needed = False
            verification_text = "Sender verification optional unless this invoice modifies payment bank details."

        safe_viewer_guidance = {
            "filename": filename,
            "viewer_type": viewer_type,
            "recommended_viewer": rec_viewer,
            "prohibited_actions": prohibited,
            "step_by_step_instructions": instructions,
            "safe_inspection_tools": safe_tools
        }

        quarantine_guidance = {
            "status": quarantine_action,
            "instructions": quarantine_instructions,
            "perimeter_containment": [
                f"Mailbox Action: {'Strip from inbox and isolate' if risk_level != 'SAFE' else 'Deliver cleanly to recipient inbox'}",
                f"Gateway Action: {'Block hash at MTA edge' if risk_level == 'MALICIOUS' else ('Log and flag for review' if risk_level == 'SUSPICIOUS' else 'Allow pass-through')}"
            ]
        }

        sender_verification_guidance = {
            "verification_required": verification_needed,
            "recommended_channel": "Official Corporate Directory / In-Person / Out-of-Band Phone",
            "guidance": verification_text
        }

        recommendations_summary = [
            f"Quarantine: {quarantine_instructions}",
            f"Sender Verification: {verification_text}",
            f"Safe Viewer: Inspect via {rec_viewer}."
        ]

        return {
            "safe_viewer_guidance": safe_viewer_guidance,
            "quarantine_guidance": quarantine_guidance,
            "sender_verification_guidance": sender_verification_guidance,
            "recommendations": recommendations_summary
        }

    @classmethod
    def generate_trial_recommendations(
        cls,
        verdict: str,
        risk_score: float,
        disposition: str,
        parsed_envelope: Dict[str, Any],
        prosecution: Dict[str, Any],
        defense: Dict[str, Any],
        attachments_analysis: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Synthesizes the comprehensive, top-level Actionable Recommendations dossier
        for the entire trial adjudication.
        """
        is_malicious = "FAKE" in verdict or "MALICIOUS" in verdict or risk_score >= 65.0
        is_suspicious = "SUSPICIOUS" in verdict or (30.0 <= risk_score < 65.0)
        is_safe = "SAFE" in verdict or "LEGITIMATE" in verdict or risk_score < 30.0

        sender = parsed_envelope.get("from_raw") or parsed_envelope.get("from_email") or "Unknown Sender"
        from_domain = parsed_envelope.get("from_domain") or "unknown-domain.com"
        subject = parsed_envelope.get("subject") or "(No Subject)"

        has_attachments = len(attachments_analysis) > 0
        malicious_attachments = [a for a in attachments_analysis if a.get("risk_level") == "MALICIOUS"]
        suspicious_attachments = [a for a in attachments_analysis if a.get("risk_level") == "SUSPICIOUS"]

        prioritized_checklist = []

        # ── 1. QUARANTINE RECOMMENDATION ─────────────────────────────────────────
        if is_malicious:
            quarantine_status = "MANDATORY_IMMEDIATE_QUARANTINE"
            quarantine_title = "Quarantine Email & Purge from Inboxes Immediately"
            quarantine_action = "GATEWAY_DROP_AND_QUARANTINE"
            soc_priority = "P1_CRITICAL"
            mailbox_steps = [
                "Immediately move message to MAILJURY_QUARANTINED label / folder.",
                "Hard-purge from all recipient Primary Inboxes, Spam, and Trash.",
                "Revoke active client synchronization to prevent offline access by mobile / desktop clients.",
                "If recipient opened email before quarantine, initiate endpoint triage for credential compromise."
            ]
            gateway_steps = [
                f"Drop connection at MTA boundary for sender domain '{from_domain}'.",
                "Ingest envelope Message-ID, sender IP, and attachment SHA-256 hashes into perimeter EDR/SIEM blocklist.",
                "Broadcast automated security alert to recipient via out-of-band Google OAuth daemon."
            ]
            prioritized_checklist.append({
                "step": 1,
                "category": RecommendationCategory.QUARANTINE,
                "priority": RecommendationPriority.IMMEDIATE,
                "action": "Execute Gateway Drop & Mailbox Quarantine",
                "detail": f"Isolate hostile message '{subject}' from '{sender}'. Remove from all user inboxes immediately."
            })
        elif is_suspicious:
            quarantine_status = "HOLD_IN_QUARANTINE_PENDING_TRIAGE"
            quarantine_title = "Divert to Administrative Quarantine / Spam Review Queue"
            quarantine_action = "SPAM_OR_HOLD_QUARANTINE"
            soc_priority = "P2_HIGH"
            mailbox_steps = [
                "Route message to quarantine queue or spam folder with prominent warning banner.",
                "Suppress automatic link pre-fetching and attachment auto-rendering.",
                "Hold for security analyst manual review or user sender-confirmation."
            ]
            gateway_steps = [
                "Apply rate-limiting and enhanced telemetry logging on sender MTA IP.",
                "Track whether recipient interacts with warning banner or reports false positive."
            ]
            prioritized_checklist.append({
                "step": 1,
                "category": RecommendationCategory.QUARANTINE,
                "priority": RecommendationPriority.HIGH,
                "action": "Divert to Quarantine Queue",
                "detail": "Hold message in quarantine pending analyst triage. Do not deliver unvetted to primary inbox."
            })
        else:
            quarantine_status = "NO_QUARANTINE_REQUIRED"
            quarantine_title = "Deliver Cleanly to Primary Inbox"
            quarantine_action = "DELIVER_INBOX"
            soc_priority = "P4_INFORMATIONAL"
            mailbox_steps = [
                "Apply MAILJURY_VERIFIED_SAFE label.",
                "Deliver uninhibited to recipient Primary Inbox."
            ]
            gateway_steps = ["Allow standard pass-through. Log cryptographic BSA §65B verification certificate."]
            prioritized_checklist.append({
                "step": 1,
                "category": RecommendationCategory.QUARANTINE,
                "priority": RecommendationPriority.ADVISORY,
                "action": "Deliver to Primary Inbox",
                "detail": "Message certified legitimate. No quarantine action needed."
            })

        quarantine_rec = {
            "status": quarantine_status,
            "title": quarantine_title,
            "action": quarantine_action,
            "soc_priority": soc_priority,
            "mailbox_actions": mailbox_steps,
            "gateway_actions": gateway_steps
        }

        # ── 2. VERIFY SENDER THROUGH OFFICIAL CHANNEL ───────────────────────────
        if is_malicious or is_suspicious:
            verification_required = True
            verification_title = "Verify Purported Sender via Verified Out-of-Band Channel"
            verification_channel = "Independent Corporate Directory, Internal Corporate Messaging, or In-Person"
            why_needed = (
                f"The email claims to originate from '{sender}', but exhibits forensic indicators of domain spoofing, "
                f"unauthenticated relay hops, or deceptive content. Threat actors routinely forge headers to impersonate executives, "
                f"vendors, or IT staff."
            )
            verification_protocol = [
                "STRICT PROHIBITION: DO NOT reply to the email, DO NOT click any email links, and DO NOT call phone numbers printed in the message body or signature.",
                "Look up the sender's official contact information in your organization's internal HR directory, verified ERP/vendor master ledger, or global address list (GAL).",
                "Contact the sender through an official out-of-band channel (e.g. established direct phone extension, Slack, Microsoft Teams, or in-person).",
                f"Ask the sender to confirm: (1) Did you send an email with subject '{subject}'? (2) Did you include attachments? (3) If financial, confirm bank account routing numbers verbally.",
                "If the purported sender denies sending the message, escalate to IT/SOC immediately as an active impersonation / account takeover attempt."
            ]
            prioritized_checklist.append({
                "step": 2,
                "category": RecommendationCategory.VERIFY_SENDER,
                "priority": RecommendationPriority.IMMEDIATE if is_malicious else RecommendationPriority.HIGH,
                "action": "Verify Sender Out-of-Band",
                "detail": f"Confirm authenticity of '{sender}' via official corporate phone directory or Teams/Slack. Never reply to this email."
            })
        else:
            verification_required = False
            verification_title = "Standard Sender Authenticity Verified"
            verification_channel = "Cryptographic SPF/DKIM/DMARC Domain Alignment"
            why_needed = "The sender domain successfully passed cryptographic authentication and matches known legitimate sending infrastructure."
            verification_protocol = [
                "Authentication verified cryptographically via DKIM signature and aligned SPF/DMARC.",
                "Standard financial hygiene applies: If this email requests changing wire payment or direct deposit details, always perform verbal verification as a dual-control protocol."
            ]
            prioritized_checklist.append({
                "step": 2,
                "category": RecommendationCategory.VERIFY_SENDER,
                "priority": RecommendationPriority.ADVISORY,
                "action": "Maintain Dual-Control Hygiene",
                "detail": "Sender cryptographically verified. Standard dual-control verbal confirmation applies only if payment details change."
            })

        sender_verification_rec = {
            "verification_required": verification_required,
            "title": verification_title,
            "recommended_channel": verification_channel,
            "purported_sender": sender,
            "sender_domain": from_domain,
            "why_needed": why_needed,
            "protocol_checklist": verification_protocol
        }

        # ── 3. INSPECT FILE USING APPROPRIATE SAFE VIEWER ───────────────────────
        if has_attachments:
            attachment_viewers = []
            for att in attachments_analysis:
                fn = att.get("filename", "unnamed_file")
                ext = att.get("extension", "")
                det = att.get("detected_type", "")
                r_level = att.get("risk_level", "SAFE")
                r_score = att.get("risk_score", 0.0)
                cls_name = att.get("classification", "")
                ev_list = att.get("evidence", [])

                att_rec = cls.generate_attachment_recommendations(
                    filename=fn,
                    extension=ext,
                    detected_type=det,
                    risk_level=r_level,
                    risk_score=r_score,
                    classification=cls_name,
                    evidence=ev_list
                )
                attachment_viewers.append({
                    "filename": fn,
                    "risk_level": r_level,
                    "risk_score": r_score,
                    "classification": cls_name,
                    "guidance": att_rec["safe_viewer_guidance"]
                })

            if malicious_attachments:
                safe_viewer_title = "CRITICAL: Do NOT Open Locally — Use Isolated Disassembly/Sandbox Viewer Only"
                safe_viewer_overview = (
                    f"Message carries {len(malicious_attachments)} malicious attachment(s) ({', '.join(a.get('filename','') for a in malicious_attachments)}). "
                    f"Under zero-execution security standards, these files must NEVER be opened or double-clicked on a standard endpoint. "
                    f"If forensic investigation is required, inspect raw byte structures exclusively using isolated sandboxes or disassembly viewers."
                )
                safe_viewer_priority = RecommendationPriority.IMMEDIATE
            elif suspicious_attachments:
                safe_viewer_title = "CAUTION: Use Hardened Cloud Sandbox / Dangerzone for File Inspection"
                safe_viewer_overview = (
                    f"Message carries suspicious attachment(s) ({', '.join(a.get('filename','') for a in suspicious_attachments)}). "
                    f"Avoid opening directly in desktop Office/Acrobat. Use an isolated cloud document previewer or Dangerzone pixel sanitizer."
                )
                safe_viewer_priority = RecommendationPriority.HIGH
            else:
                safe_viewer_title = "Attachments Certified Safe for Standard Viewing"
                safe_viewer_overview = "All attachments passed zero-execution static byte signature audits with no active exploits or macros detected."
                safe_viewer_priority = RecommendationPriority.ADVISORY

            body_viewer_guidance = (
                "For inspecting the email body itself: Render in plain text mode or web preview with remote image loading "
                "and HTML script execution disabled to prevent beacon tracking and CSS link overlays."
            )

            prioritized_checklist.append({
                "step": 3,
                "category": RecommendationCategory.SAFE_VIEWER,
                "priority": safe_viewer_priority,
                "action": "Inspect Attachments via Safe Viewer",
                "detail": f"{safe_viewer_title}: {attachment_viewers[0]['guidance']['recommended_viewer'] if attachment_viewers else 'Use isolated viewer'}"
            })

        else:
            safe_viewer_title = "No Attachments Present — Inspect Links via Isolated Browser"
            safe_viewer_overview = (
                "Attack surface minimized: this message carries zero file attachments. If evaluating embedded hyperlinks, "
                "do NOT click directly; inspect URL destinations statically or via a Remote Browser Isolation (RBI) session."
            )
            attachment_viewers = []
            body_viewer_guidance = "Render email body in plain text mode to inspect visible vs target hyperlink destinations."
            safe_viewer_priority = RecommendationPriority.ADVISORY
            prioritized_checklist.append({
                "step": 3,
                "category": RecommendationCategory.SAFE_VIEWER,
                "priority": safe_viewer_priority,
                "action": "Zero File Attack Surface",
                "detail": "No file attachments attached. Inspect hyperlinks in text mode or Remote Browser Isolation."
            })

        safe_viewer_rec = {
            "has_attachments": has_attachments,
            "title": safe_viewer_title,
            "overview": safe_viewer_overview,
            "email_body_viewer_guidance": body_viewer_guidance,
            "attachment_viewers": attachment_viewers,
            "recommended_tools_matrix": {
                "Executables / PE / Droppers": ["Ghidra (Offline)", "radare2 / Cutter", "CAPE Sandbox (Air-Gapped)", "CyberChef"],
                "Macro Office Documents": ["Dangerzone (Pixel Sanitizer)", "Google Docs Cloud Sandbox", "Microsoft 365 Cloud (Application Guard)"],
                "PDF Documents": ["Chromium PDF.js (JS Disabled)", "Dangerzone", "pdfid / peepdf (CLI)", "pdftotext"],
                "Encrypted Archives": ["Ephemeral Docker Container (`--network none`)", "Qubes OS Disposable VM"],
                "Hyperlinks / Web URLs": ["Remote Browser Isolation (RBI)", "urlscan.io (Private Submission)", "CyberChef URL Decoder"]
            }
        }

        # ── 4. INCIDENT RESPONSE & SOC GUIDANCE ─────────────────────────────────
        if is_malicious:
            prioritized_checklist.append({
                "step": 4,
                "category": RecommendationCategory.INCIDENT_RESPONSE,
                "priority": RecommendationPriority.IMMEDIATE,
                "action": "Initiate SOC Incident Response (BSA §65B Logged)",
                "detail": "Preserve cryptographic trial certificate for forensic chain of custody. Escalate to CIRT/SOC team."
            })

        return {
            "primary_action": "QUARANTINE_AND_ISOLATE" if is_malicious else ("VERIFY_SENDER_AND_HOLD" if is_suspicious else "DELIVER_SAFELY"),
            "summary_headline": (
                "[CRITICAL THREAT DETECTED] Quarantine & Out-of-Band Verification Required" if is_malicious else (
                    "[ELEVATED RISK] Hold in Quarantine & Verify Sender via Official Channel" if is_suspicious else
                    "[VERIFIED SAFE] Certified Legitimate Email"
                )
            ),
            "quarantine": quarantine_rec,
            "verify_sender": sender_verification_rec,
            "safe_viewer": safe_viewer_rec,
            "prioritized_checklist": prioritized_checklist,
            "quick_actions": [
                {
                    "id": "action_quarantine",
                    "label": "Quarantine Message",
                    "recommended": is_malicious or is_suspicious,
                    "action_code": quarantine_action,
                    "description": quarantine_title
                },
                {
                    "id": "action_verify_sender",
                    "label": "Verify Sender (Out-of-Band)",
                    "recommended": is_malicious or is_suspicious,
                    "action_code": "OFFICIAL_CHANNEL_VERIFICATION",
                    "description": f"Contact '{sender}' via official phone directory or corporate chat."
                },
                {
                    "id": "action_safe_viewer",
                    "label": "Inspect in Safe Viewer",
                    "recommended": has_attachments,
                    "action_code": "ISOLATED_SAFE_VIEWER",
                    "description": safe_viewer_title
                }
            ]
        }

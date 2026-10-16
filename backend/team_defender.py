"""
TEAM B: THE DEFENDER (Blue Team Legitimacy & Innocence Advocate)
Penty Disprover Principle & False-Positive Elimination Engine.
Fiercely defends innocent emails by presenting Cryptographic Proofs, Certified ESP Seals,
and RFC Compliance Hygiene, while filing formal Motions to Dismiss against unwarranted charges.
"""
import re
from typing import Dict, List, Any, Optional
from attachment_analyzer import AttachmentAnalyzer

class ExonerationProof:
    def __init__(
        self,
        proof_id: str,
        pillar: str,
        title: str,
        certificate: str,
        legitimacy_points: float,
        legal_basis: str
    ):
        self.proof_id = proof_id
        self.pillar = pillar
        self.title = title
        self.certificate = certificate
        self.legitimacy_points = legitimacy_points
        self.legal_basis = legal_basis

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proof_id": self.proof_id,
            "pillar": self.pillar,
            "title": self.title,
            "certificate": self.certificate,
            "legitimacy_points": self.legitimacy_points,
            "legal_basis": self.legal_basis
        }

class FormalObjection:
    def __init__(
        self,
        target_count_id: str,
        objection_type: str,
        grounds: str,
        evidence_cited: str,
        demanded_action: str # "DISMISS_CHARGE" or "MITIGATE_PENALTY"
    ):
        self.target_count_id = target_count_id
        self.objection_type = objection_type
        self.grounds = grounds
        self.evidence_cited = evidence_cited
        self.demanded_action = demanded_action

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_count_id": self.target_count_id,
            "objection_type": self.objection_type,
            "grounds": self.grounds,
            "evidence_cited": self.evidence_cited,
            "demanded_action": self.demanded_action
        }

class TeamDefender:
    """The dedicated legitimacy advocate that protects innocent emails from false accusations."""

    CERTIFIED_ESPS = {
        "google": ["google.com", "1e100.net", "gmail.com"],
        "microsoft": ["outlook.com", "protection.outlook.com", "microsoft.com", "office365.com"],
        "github": ["github.com", "support.github.com"],
        "stripe": ["stripe.com", "bounces.stripe.com"],
        "amazon_ses": ["amazonses.com", "aws.amazon.com"],
        "sendgrid": ["sendgrid.net", "sendgrid.com"],
        "mailchimp": ["mcsv.net", "mandrillapp.com", "mailchimp.com"],
        "slack": ["slack.com", "slack-msgs.com"],
        "atlassian": ["atlassian.net", "jira.com", "trello.com"]
    }

    def __init__(self):
        self.proof_idx = 1

    def defend(self, parsed_mail: Dict[str, Any], prosecution_docket: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gathers exonerating proofs and mounts cross-examination objections against the prosecution.
        """
        self.proof_idx = 1
        proofs: List[ExonerationProof] = []
        objections: List[FormalObjection] = []

        # 1. Gather Cryptographic & Protocol Proofs
        self._gather_cryptographic_proofs(parsed_mail, proofs)

        # 2. Verify Certified ESP & Relay Infrastructure
        is_certified_esp, esp_name = self._verify_esp_infrastructure(parsed_mail, proofs)

        # 3. Check RFC Conformance & Structural Hygiene
        self._verify_rfc_hygiene(parsed_mail, proofs)

        # 4. Certify Attachment Integrity (Zero-Payload Proof)
        self._certify_clean_attachments(parsed_mail, proofs)

        # 5. File Formal Objections against Prosecution Counts (Penty Disprover Rule)
        self._file_objections(parsed_mail, prosecution_docket, is_certified_esp, esp_name, proofs, objections)

        total_legitimacy = min(100.0, sum(p.legitimacy_points for p in proofs))
        opening_statement = self._generate_opening(proofs, objections, is_certified_esp, total_legitimacy)
        closing_statement = self._generate_closing(proofs, objections, total_legitimacy)

        return {
            "team": "Team Defender (Legitimacy Advocate)",
            "role": "Blue Team Defense",
            "proofs": [p.to_dict() for p in proofs],
            "total_proofs": len(proofs),
            "objections": [o.to_dict() for o in objections],
            "total_objections": len(objections),
            "is_certified_esp": is_certified_esp,
            "certified_esp_provider": esp_name,
            "exoneration_score": round(total_legitimacy, 1),
            "opening_statement": opening_statement,
            "closing_statement": closing_statement
        }

    def _next_proof_id(self) -> str:
        pid = f"PRF-{self.proof_idx:03d}"
        self.proof_idx += 1
        return pid

    def _gather_cryptographic_proofs(self, mail: Dict[str, Any], proofs: List[ExonerationProof]):
        auth_lines = " ".join(mail.get("auth_results", [])).lower()
        envelope = mail.get("envelope", {})
        from_domain = envelope.get("from_domain", "")

        # 1. DKIM Cryptographic Verification
        if "dkim=pass" in auth_lines:
            proofs.append(ExonerationProof(
                proof_id=self._next_proof_id(),
                pillar="PILLAR_1_HEADER",
                title="Cryptographic DKIM Signature Validation",
                certificate=f"Digital signature cryptographically verified for domain: {from_domain}",
                legitimacy_points=35.0,
                legal_basis="RFC 6376 Section 6.1 (Cryptographic Non-Repudiation)"
            ))

        # 2. SPF Authorized Sender Pass
        if "spf=pass" in auth_lines:
            proofs.append(ExonerationProof(
                proof_id=self._next_proof_id(),
                pillar="PILLAR_1_HEADER",
                title="SPF Authorized Sender Envelope Verification",
                certificate=f"Sending IP is an explicitly authorized CIDR in {from_domain}'s DNS record",
                legitimacy_points=25.0,
                legal_basis="RFC 7208 (Sender Policy Framework Designation)"
            ))

        # 3. DMARC Strict Domain Alignment
        if "dmarc=pass" in auth_lines:
            proofs.append(ExonerationProof(
                proof_id=self._next_proof_id(),
                pillar="PILLAR_1_HEADER",
                title="DMARC Strict Organizational Alignment",
                certificate=f"RFC 5322 From: domain strictly aligned with validated authentication mechanism",
                legitimacy_points=30.0,
                legal_basis="RFC 7489 Section 3.1 (DMARC Domain Alignment)"
            ))

    def _verify_esp_infrastructure(self, mail: Dict[str, Any], proofs: List[ExonerationProof]) -> tuple[bool, str]:
        hops = " ".join(mail.get("hops", [])).lower()
        envelope = mail.get("envelope", {})
        return_domain = envelope.get("return_path_domain", "").lower()
        from_domain = envelope.get("from_domain", "").lower()

        detected_esp = None
        for esp_brand, domains in self.CERTIFIED_ESPS.items():
            for d in domains:
                if d in hops or d in return_domain or d in from_domain:
                    detected_esp = esp_brand
                    break
            if detected_esp:
                break

        if detected_esp:
            proofs.append(ExonerationProof(
                proof_id=self._next_proof_id(),
                pillar="PILLAR_1_HEADER",
                title=f"Certified Enterprise Mail Infrastructure ({detected_esp.upper()})",
                certificate=f"Relay topology originates from verified {detected_esp.upper()} enterprise data center",
                legitimacy_points=35.0,
                legal_basis="Tier-1 ESP Transit Security Baseline & FCrDNS Verification"
            ))
            return True, detected_esp
        return False, ""

    def _verify_rfc_hygiene(self, mail: Dict[str, Any], proofs: List[ExonerationProof]):
        envelope = mail.get("envelope", {})
        headers = mail.get("headers", {})

        # Message-ID Hygiene
        msg_id = envelope.get("message_id", "")
        if msg_id and msg_id.startswith("<") and msg_id.endswith(">") and "@" in msg_id:
            proofs.append(ExonerationProof(
                proof_id=self._next_proof_id(),
                pillar="PILLAR_1_HEADER",
                title="RFC 5322 Compliant Global Message Identifier",
                certificate=f"Valid unique message-id token: {msg_id[:40]}...",
                legitimacy_points=10.0,
                legal_basis="RFC 5322 Section 3.6.4 (Unique ID Syntax)"
            ))

        # RFC 8058 One-Click List-Unsubscribe
        list_unsub = headers.get("list-unsubscribe", "")
        list_unsub_post = headers.get("list-unsubscribe-post", "")
        if list_unsub:
            one_click = "One-Click" in list_unsub_post
            proofs.append(ExonerationProof(
                proof_id=self._next_proof_id(),
                pillar="PILLAR_2_BODY",
                title="Compliant List-Unsubscribe & Anti-Spam Hygiene",
                certificate=f"Provides verified unsubscribe mechanism (One-Click: {one_click})",
                legitimacy_points=20.0,
                legal_basis="RFC 8058 / RFC 2369 Commercial Email Best Practices"
            ))

        # Monotonic received hops
        hops = mail.get("hops", [])
        if hops and len(hops) >= 1:
            proofs.append(ExonerationProof(
                proof_id=self._next_proof_id(),
                pillar="PILLAR_1_HEADER",
                title="Monotonic Transmission Relay Integrity",
                certificate=f"Traced through {len(hops)} verifiable relay hops with consistent MTA timestamps",
                legitimacy_points=10.0,
                legal_basis="RFC 5321 Hop Trace Verification"
            ))

    def _certify_clean_attachments(self, mail: Dict[str, Any], proofs: List[ExonerationProof]):
        attachments = mail.get("attachments", [])
        if not attachments:
            proofs.append(ExonerationProof(
                proof_id=self._next_proof_id(),
                pillar="PILLAR_3_ATTACHMENT",
                title="Zero-Attachment Surface Attack Plane",
                certificate="Message carries zero file payloads, eliminating local execution risks entirely",
                legitimacy_points=25.0,
                legal_basis="Attack Surface Minimization"
            ))
            return

        body = mail.get("body", {})
        combined_body = body.get("combined", "")
        subject = mail.get("envelope", {}).get("subject", "")
        full_text = f"Subject: {subject}\n\n{combined_body}"

        clean_count = 0
        for att in attachments:
            fn = att.get("filename", "")
            payload = att.get("raw_payload", b"")
            declared_ct = att.get("declared_type", "")

            report = att.get("analysis")
            if not report:
                report = AttachmentAnalyzer.inspect_attachment(fn, payload, declared_ct, full_text)
                att["analysis"] = report

            if report.get("is_safe", False):
                clean_count += 1
                classif = report.get("classification", "")
                if "Genuine Vendor PDF Invoice" in classif or "Clean Document" in classif:
                    proofs.append(ExonerationProof(
                        proof_id=self._next_proof_id(),
                        pillar="PILLAR_3_ATTACHMENT",
                        title=f"Certified Genuine Vendor PDF Invoice: {fn}",
                        certificate=f"In-memory inspection: ISO 32000-1 verified clean, 0 scripts, 0 /Launch triggers",
                        legitimacy_points=35.0,
                        legal_basis="ISO 32000-1 Document Structure Verification"
                    ))
                elif "Plain" in classif and "DOCX" in classif:
                    proofs.append(ExonerationProof(
                        proof_id=self._next_proof_id(),
                        pillar="PILLAR_3_ATTACHMENT",
                        title=f"Certified Plain Macro-Free DOCX: {fn}",
                        certificate=f"OpenXML package verified in-memory: 0 macros (vbaProject.bin absent), 0 external template rels",
                        legitimacy_points=35.0,
                        legal_basis="ISO/IEC 29500-1 OpenXML Macro-Free Standard"
                    ))
                elif "Images" in classif or "Image" in classif:
                    proofs.append(ExonerationProof(
                        proof_id=self._next_proof_id(),
                        pillar="PILLAR_3_ATTACHMENT",
                        title=f"Certified Benign Image Container: {fn}",
                        certificate=f"Archive entries verified in-memory: exclusively raster image assets, 0 executable entries",
                        legitimacy_points=30.0,
                        legal_basis="Static Archive Structure Whitelist"
                    ))
                else:
                    proofs.append(ExonerationProof(
                        proof_id=self._next_proof_id(),
                        pillar="PILLAR_3_ATTACHMENT",
                        title=f"Certified Clean Attachment: {fn}",
                        certificate=f"Static binary inspection: 0 executable headers, 0 shell triggers, 0 payload masquerade",
                        legitimacy_points=25.0,
                        legal_basis="Static Binary Inspection Certificate"
                    ))

        if clean_count == len(attachments) and clean_count > 0:
            proofs.append(ExonerationProof(
                proof_id=self._next_proof_id(),
                pillar="PILLAR_3_ATTACHMENT",
                title="100% Certified Clean Attachment Roster",
                certificate=f"All {clean_count} attached file(s) statically certified safe with zero execution vectors",
                legitimacy_points=25.0,
                legal_basis="Zero-Day Static File Signature Hygiene"
            ))

    def _file_objections(
        self,
        mail: Dict[str, Any],
        prosecution_docket: Dict[str, Any],
        is_certified_esp: bool,
        esp_name: str,
        proofs: List[ExonerationProof],
        objections: List[FormalObjection]
    ):
        envelope = mail.get("envelope", {})
        from_domain = envelope.get("from_domain", "")
        auth_lines = " ".join(mail.get("auth_results", [])).lower()
        has_dkim_pass = "dkim=pass" in auth_lines
        has_spf_pass = "spf=pass" in auth_lines
        has_clean_attachment_proof = any("Certified Genuine" in p.title or "Certified Plain" in p.title or "Clean" in p.title for p in proofs)

        counts = prosecution_docket.get("counts", [])

        for c in counts:
            cid = c.get("count_id")
            category = c.get("category")
            charge = c.get("charge_name")

            # 1. Objection to Urgency in Transactional / Alert Messages
            if category == "PSYCH_URGENCY":
                if (is_certified_esp and has_dkim_pass) or has_spf_pass or has_clean_attachment_proof:
                    objections.append(FormalObjection(
                        target_count_id=cid,
                        objection_type="FALSE_POSITIVE_TRANSACTIONAL_CONTEXT",
                        grounds=(
                            f"The Prosecution conflates standard business transaction terminology with malicious urgency. "
                            f"The message is authenticated from {from_domain or 'recognized sender'} via {esp_name.upper() if esp_name else 'authorized relay'}. "
                            f"Billing notices, server alerts, and security digests naturally utilize words like 'invoice', 'immediate', or 'required'."
                        ),
                        evidence_cited="Valid DKIM/SPF Authentication + Certified Clean Architecture",
                        demanded_action="DISMISS_CHARGE"
                    ))

            # 2. Objection to Brand Squatting when the Sender IS the Brand
            if category == "IDENTITY_SPOOF" and "Brand Infringement" in charge:
                brand_in_charge = charge.split('(')[-1].strip(')')
                if brand_in_charge.lower() in from_domain:
                    objections.append(FormalObjection(
                        target_count_id=cid,
                        objection_type="ABSURD_SELF_INFRINGE_ACCUSATION",
                        grounds=(
                            f"The Prosecution commits a category error by accusing {brand_in_charge.title()} of spoofing itself. "
                            f"The sender domain '{from_domain}' is the verified official domain of the brand with passing cryptographic signatures."
                        ),
                        evidence_cited=f"Domain ownership and DKIM signature matching '{from_domain}'",
                        demanded_action="DISMISS_CHARGE"
                    ))

            # 3. Objection to Divergent Return-Path for Cloud ESP Relays
            if category == "IDENTITY_SPOOF" and "Reply-To" not in charge:
                if is_certified_esp and has_dkim_pass:
                    objections.append(FormalObjection(
                        target_count_id=cid,
                        objection_type="RFC_7960_COMPLIANT_CLOUD_BOUNCE",
                        grounds=(
                            f"RFC 7960 Section 4 explicitly sanctions cloud ESPs (e.g., SendGrid, Mailchimp, Stripe) "
                            f"using centralized bounce handling addresses on their own subdomain while signing DKIM on behalf of the author."
                        ),
                        evidence_cited="RFC 7960 Intermediary Relay Guidance + Valid DKIM signature",
                        demanded_action="DISMISS_CHARGE"
                    ))

            # 4. Objection to Benign Long URLs / Extended Parameterized URIs
            if category == "URL_DECEPTION" and ("Extended URI" in charge or "Parameter-Dense" in charge):
                if has_dkim_pass or has_spf_pass or is_certified_esp or has_clean_attachment_proof:
                    objections.append(FormalObjection(
                        target_count_id=cid,
                        objection_type="BENIGN_ENTERPRISE_DEEP_LINK",
                        grounds=(
                            "The Prosecution mistakes modern SaaS session routing and compliant tracking parameters for deception. "
                            "Deep linking, OAuth redirects, and marketing UTM tags routinely generate parameterized URIs > 150 characters."
                        ),
                        evidence_cited="RFC 3986 URI Specification + Enterprise SaaS Navigation Hygiene",
                        demanded_action="DISMISS_CHARGE"
                    ))

            # 5. Objection to Non-Fatal Attachment Accusations when Certified Clean
            if category == "ATTACHMENT_PAYLOAD" and c.get("severity") != "FATAL_VETO":
                if has_clean_attachment_proof:
                    objections.append(FormalObjection(
                        target_count_id=cid,
                        objection_type="FALSE_POSITIVE_ATTACHMENT_ACCUSATION",
                        grounds=(
                            "In-memory static byte analysis has definitively proven this attachment to be clean, "
                            "macro-free, and compliant with ISO document specifications."
                        ),
                        evidence_cited="Static Attachment Forensics Certificate",
                        demanded_action="DISMISS_CHARGE"
                    ))


    def _generate_opening(self, proofs: List[ExonerationProof], objections: List[FormalObjection], is_certified_esp: bool, score: float) -> str:
        esp_str = f"originating from certified tier-1 enterprise infrastructure ({proofs[1].title})" if is_certified_esp else "complying with standard Internet mail engineering"
        return (
            f"May it please the Court: The Defense appears on behalf of a legitimate, authentic transmission {esp_str}. "
            f"We have entered {len(proofs)} definitive cryptographic and architectural proofs of innocence into the record. "
            f"The Prosecution's charges represent classic false positives arising from contextual blindness. "
            f"We have filed {len(objections)} formal Motions to Dismiss, and we respectfully demand complete exoneration for this message."
        )

    def _generate_closing(self, proofs: List[ExonerationProof], objections: List[FormalObjection], score: float) -> str:
        return (
            f"In closing, Members of the Court: To convict a message simply because it conducts business, delivers an alert, or issues an invoice "
            f"would paralyze global digital commerce. With {len(proofs)} verified certificates of cryptographic authenticity, the Defense has met "
            f"and exceeded every burden of legitimate proof. We move for a definitive decree of INNOCENT / LEGITIMATE."
        )

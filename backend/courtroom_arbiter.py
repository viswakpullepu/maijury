"""
CHIEF JUSTICE ARBITER (Adversarial Courtroom Synthesis Engine)
Orchestrates the formal debate between Team Prosecutor (Red Team) and Team Defender (Blue Team).
Applies the Penty Disprover Principle, Monotonic Veto Standard, and Bharatiya Sakshya Adhiniyam Sec 65B.
Delivers binding verdicts: LEGITIMATE (Certified Safe) vs FAKE/MALICIOUS (Quarantine).
"""
import time
import hashlib
from typing import Dict, List, Any, Optional

try:
    from actionable_recommendations import ActionableRecommendationEngine
except ImportError:
    try:
        from backend.actionable_recommendations import ActionableRecommendationEngine
    except ImportError:
        ActionableRecommendationEngine = None

class CourtroomArbiter:
    """The impartial judicial engine that weighs prosecution vs defense and renders final verdicts."""

    def __init__(self):
        pass

    def adjudicate(
        self,
        parsed_mail: Dict[str, Any],
        prosecution_docket: Dict[str, Any],
        defense_brief: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Runs the full adversarial trial: hears charges, rules on objections, and renders judgment.
        """
        t0 = time.perf_counter()
        raw_sha256 = parsed_mail.get("sha256", "")
        envelope = parsed_mail.get("envelope", {})
        subject = envelope.get("subject", "(No Subject)")
        sender = envelope.get("from_raw", "(Unknown Sender)")

        trial_transcript: List[Dict[str, str]] = []

        # Step 1: Court Call to Order
        self._log_transcript(trial_transcript, "CHIEF_JUSTICE", 
            f"The High Court of Protocol Integrity & Email Forensics is now in session. "
            f"In the Matter of Subject: '{subject}' from Sender: '{sender}'. "
            f"Evidentiary SHA-256 Digest: {raw_sha256}. "
            f"Prosecution, present your indictment."
        )

        # Step 2: Prosecution Opening
        p_opening = prosecution_docket.get("opening_statement", "")
        self._log_transcript(trial_transcript, "PROSECUTOR", p_opening)

        # Step 3: Defense Opening
        d_opening = defense_brief.get("opening_statement", "")
        self._log_transcript(trial_transcript, "DEFENDER", d_opening)

        # Step 4: The Cross-Examination & Objection Adjudication
        raw_counts = prosecution_docket.get("counts", [])
        objections = defense_brief.get("objections", [])
        objections_by_count = {o["target_count_id"]: o for o in objections}

        surviving_counts: List[Dict[str, Any]] = []
        dismissed_counts: List[Dict[str, Any]] = []

        for count in raw_counts:
            cid = count["count_id"]
            severity = count["severity"]
            charge = count["charge_name"]
            statute = count["statute"]
            exhibit = count["exhibit"]

            self._log_transcript(trial_transcript, "PROSECUTOR",
                f"Your Honor, we call Count {cid}: '{charge}' [{severity}]. "
                f"Statute: {statute}. Exhibit: {exhibit}."
            )

            # Check if Defense filed an objection
            if cid in objections_by_count:
                obj = objections_by_count[cid]
                grounds = obj["grounds"]
                self._log_transcript(trial_transcript, "DEFENDER",
                    f"Objection, Your Honor! Motion to dismiss Count {cid}. {grounds}"
                )

                # Judicial Ruling:
                # Fatal vetos cannot be dismissed by procedural/cryptographic arguments
                if severity == "FATAL_VETO":
                    self._log_transcript(trial_transcript, "CHIEF_JUSTICE",
                        f"Objection OVERRULED. Under the Monotonic Veto Standard, cryptographic authentication "
                        f"cannot immunize an active binary weapon, payload masquerade, or protocol desync. "
                        f"Count {cid} stands as proven in full."
                    )
                    surviving_counts.append(count)
                else:
                    # Circumstantial or contextual charges with valid proofs are dismissed
                    self._log_transcript(trial_transcript, "CHIEF_JUSTICE",
                        f"Objection SUSTAINED under the Penty Disprover Principle. The Defense has established "
                        f"legitimate operational and cryptographic context. Count {cid} is hereby DISMISSED and struck from the record."
                    )
                    dismissed_counts.append({
                        **count,
                        "dismissal_grounds": grounds
                    })
            else:
                # Undefended count stands
                self._log_transcript(trial_transcript, "CHIEF_JUSTICE",
                    f"Count {cid} stands without objection."
                )
                surviving_counts.append(count)

        # Step 5: Final Arguments
        self._log_transcript(trial_transcript, "PROSECUTOR", prosecution_docket.get("closing_statement", ""))
        self._log_transcript(trial_transcript, "DEFENDER", defense_brief.get("closing_statement", ""))

        # Step 6: Synthesis & Final Decree
        surviving_vetos = [c for c in surviving_counts if c["severity"] == "FATAL_VETO"]
        surviving_severe = [c for c in surviving_counts if c["severity"] == "SEVERE"]
        
        raw_p_score = sum(c["risk_points"] for c in surviving_counts)
        d_score = defense_brief.get("exoneration_score", 0.0)

        # Verdict Determination — Refined Multi-Indicator Scoring Fusion (Mission 02)
        if surviving_vetos:
            final_score = max(95.0, min(100.0, 92.0 + len(surviving_vetos) * 3.0))
            verdict = "FAKE / MALICIOUS"
            disposition = "GATEWAY_DROP_AND_QUARANTINE"
            verdict_color = "RED"
            summary_justification = (
                f"The message is adjudicated as FAKE/MALICIOUS due to {len(surviving_vetos)} fatal, "
                f"non-dismissible exploit vectors ({', '.join(v['charge_name'] for v in surviving_vetos)}). "
                f"In accordance with the Monotonic Veto Rule, no cryptographic credentials can license binary attacks."
            )
        elif len(surviving_counts) == 0 or (raw_p_score < 25.0 and d_score >= 30.0):
            final_score = max(0.0, min(10.0, raw_p_score * 0.2))
            verdict = "LEGITIMATE / SAFE"
            disposition = "DELIVER_INBOX"
            verdict_color = "GREEN"
            summary_justification = (
                f"The message is certified 100% LEGITIMATE and SAFE. All circumstantial prosecution charges "
                f"were disproved by verified cryptographic authentication and trusted enterprise infrastructure."
            )
        elif len(surviving_counts) <= 1 and len(surviving_severe) == 0:
            # Mission 02 Rule: An isolated weak signal without corroboration cannot flag a file as suspicious
            weak_charge = surviving_counts[0]['charge_name'] if surviving_counts else "Weak Signal"
            final_score = max(0.0, min(15.0, raw_p_score * 0.25))
            verdict = "LEGITIMATE / SAFE"
            disposition = "DELIVER_INBOX"
            verdict_color = "GREEN"
            summary_justification = (
                f"The message is certified LEGITIMATE / SAFE under the Multi-Indicator Fusion Rule. "
                f"The single isolated signal ('{weak_charge}') is insufficient proof of malice without corroborating deceptive vectors."
            )
        elif raw_p_score >= 60.0 or len(surviving_severe) >= 2 or (len(surviving_counts) >= 3 and raw_p_score >= 50.0):
            # Multiple converging signals confirm malicious intent
            final_score = min(90.0, max(65.0, raw_p_score))
            verdict = "FAKE / PHISHING"
            disposition = "SPAM_OR_QUARANTINE"
            verdict_color = "RED"
            summary_justification = (
                f"The message is adjudicated as PHISHING based on multiple converging indicators "
                f"({len(surviving_counts)} surviving charges including {len(surviving_severe)} severe vectors) "
                f"overwhelming the defense's credibility."
            )
        else:
            final_score = max(25.0, min(59.0, 35.0 + (raw_p_score - d_score) * 0.35))
            verdict = "SUSPICIOUS / USER CAUTION"
            disposition = "DELIVER_WITH_WARNING_BANNER"
            verdict_color = "YELLOW"
            summary_justification = (
                f"The message exhibits unresolved structural anomalies that warrant user caution, "
                f"though no direct execution veto was proven."
            )

        t1 = time.perf_counter()
        trial_duration_ms = round((t1 - t0) * 1000.0, 2)

        # Step 7: Multi-Vector Risk Attribution Breakdown (Mission 73 / Req 1)
        risk_breakdown = self._compute_risk_breakdown(
            parsed_mail=parsed_mail,
            raw_counts=raw_counts,
            surviving_counts=surviving_counts,
            dismissed_counts=dismissed_counts,
            defense_brief=defense_brief,
            final_score=round(final_score, 1),
            surviving_vetos=surviving_vetos,
            surviving_severe=surviving_severe
        )

        self._log_transcript(trial_transcript, "CHIEF_JUSTICE",
            f"FINAL DECREE: The Court enters a binding verdict of {verdict} (Risk Score: {final_score}/100). "
            f"Disposition: {disposition}. {summary_justification}"
        )

        p_summary = risk_breakdown["pillars"]
        self._log_transcript(trial_transcript, "CHIEF_JUSTICE",
            f"RISK ATTRIBUTION BREAKDOWN: Sender: {p_summary['sender']['contribution_score']} pts ({p_summary['sender']['contribution_percentage']}%) | "
            f"Body: {p_summary['body']['contribution_score']} pts ({p_summary['body']['contribution_percentage']}%) | "
            f"URLs: {p_summary['urls']['contribution_score']} pts ({p_summary['urls']['contribution_percentage']}%) | "
            f"Attachments: {p_summary['attachments']['contribution_score']} pts ({p_summary['attachments']['contribution_percentage']}%). "
            f"Primary Threat Driver: {risk_breakdown['highest_contributor_name']}."
        )

        # Generate Actionable Recommendations (Quarantine, Sender Verification, Safe Viewer)
        actionable_recommendations = {}
        if ActionableRecommendationEngine:
            att_analyses = []
            for a in parsed_mail.get("attachments", []):
                if isinstance(a, dict) and a.get("analysis"):
                    att_analyses.append(a["analysis"])
                elif isinstance(a, dict):
                    att_analyses.append(a)

            actionable_recommendations = ActionableRecommendationEngine.generate_trial_recommendations(
                verdict=verdict,
                risk_score=final_score,
                disposition=disposition,
                parsed_envelope=envelope,
                prosecution=prosecution_docket,
                defense=defense_brief,
                attachments_analysis=att_analyses
            )

        self._log_transcript(trial_transcript, "CHIEF_JUSTICE",
            f"ACTIONABLE GUIDANCE: Primary Directive: {actionable_recommendations.get('primary_action', disposition)}. "
            f"Quarantine: {actionable_recommendations.get('quarantine', {}).get('title', 'N/A')}. "
            f"Sender Verification: {actionable_recommendations.get('verify_sender', {}).get('title', 'N/A')}. "
            f"Safe Viewer: {actionable_recommendations.get('safe_viewer', {}).get('title', 'N/A')}."
        )

        # Generate Section 65B Legal Certificate
        cert_payload = f"{raw_sha256}:{verdict}:{final_score}:{trial_duration_ms}"
        bsa_cert_token = hashlib.sha256(cert_payload.encode()).hexdigest().upper()

        return {
            "verdict": verdict,
            "verdict_color": verdict_color,
            "final_risk_score": round(final_score, 1),
            "defense_exoneration_score": round(d_score, 1),
            "disposition": disposition,
            "summary_justification": summary_justification,
            "risk_breakdown": risk_breakdown,
            "actionable_recommendations": actionable_recommendations,
            "stats": {
                "total_prosecution_counts": len(raw_counts),
                "sustained_charges": len(surviving_counts),
                "dismissed_charges": len(dismissed_counts),
                "defense_proofs_entered": len(defense_brief.get("proofs", [])),
                "fatal_vetos": len(surviving_vetos),
                "trial_duration_ms": trial_duration_ms
            },
            "surviving_counts": surviving_counts,
            "dismissed_counts": dismissed_counts,
            "trial_transcript": trial_transcript,
            "legal_metadata": {
                "statute_compliance": "Bharatiya Sakshya Adhiniyam (BSA), 2023 - Section 65B",
                "electronic_record_hash": raw_sha256,
                "adjudication_certificate_token": bsa_cert_token,
                "timestamp_epoch": time.time()
            }
        }

    def _log_transcript(self, transcript: List[Dict[str, str]], speaker: str, utterance: str):
        transcript.append({
            "speaker": speaker,
            "utterance": utterance
        })

    def _compute_risk_breakdown(
        self,
        parsed_mail: Dict[str, Any],
        raw_counts: List[Dict[str, Any]],
        surviving_counts: List[Dict[str, Any]],
        dismissed_counts: List[Dict[str, Any]],
        defense_brief: Dict[str, Any],
        final_score: float,
        surviving_vetos: List[Dict[str, Any]],
        surviving_severe: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Forensically computes the multi-vector risk breakdown across the four pillars:
        1. Sender & Authentication ('sender')
        2. Email Body Content ('body')
        3. Links & URLs ('urls')
        4. File Attachments ('attachments')

        Determines standalone pillar risk, mathematical contribution to overall score,
        evidentiary factors (sustained vs dismissed), and context highlights.
        """
        PILLAR_KEYS = ["sender", "body", "urls", "attachments"]

        PILLAR_METADATA = {
            "sender": {
                "name": "Sender & Authentication",
                "icon": "mail",
                "description": "Cryptographic signatures (SPF/DKIM/DMARC), From domain alignment, VIP impersonation, and ESP verification."
            },
            "body": {
                "name": "Email Body Content",
                "icon": "file-text",
                "description": "Urgency cues, social engineering pressure, VEC wire fraud, zero-font hidden CSS, and script execution lures."
            },
            "urls": {
                "name": "Links & URLs",
                "icon": "link",
                "description": "Anchor text destination mismatches, raw IP literals, punycode homoglyphs, high-risk TLDs, and tracking params."
            },
            "attachments": {
                "name": "File Attachments",
                "icon": "paperclip",
                "description": "Zero-execution static forensics: magic byte validation, macro inspections, template injections, and container analysis."
            }
        }

        def _resolve_pillar(count: Dict[str, Any]) -> str:
            p = count.get("pillar")
            if p in PILLAR_KEYS:
                return p
            cat = count.get("category", "")
            exhibit = str(count.get("exhibit", "")).lower()
            if cat == "HEADER_AUTH":
                return "sender"
            elif cat == "IDENTITY_SPOOF":
                if "target url" in exhibit or "url" in exhibit:
                    return "urls"
                return "sender"
            elif cat in ("BODY_CLOAKING", "BEC_FRAUD", "PSYCH_URGENCY"):
                return "body"
            elif cat == "URL_DECEPTION":
                return "urls"
            elif cat == "ATTACHMENT_PAYLOAD":
                return "attachments"
            return "body"

        # Partition counts into pillars
        pillar_surviving: Dict[str, List[Dict[str, Any]]] = {k: [] for k in PILLAR_KEYS}
        pillar_dismissed: Dict[str, List[Dict[str, Any]]] = {k: [] for k in PILLAR_KEYS}

        for c in surviving_counts:
            p = _resolve_pillar(c)
            pillar_surviving[p].append(c)

        for c in dismissed_counts:
            p = _resolve_pillar(c)
            pillar_dismissed[p].append(c)

        # Calculate raw points and vetos per pillar
        raw_pts = {k: sum(float(c.get("risk_points", 0.0)) for c in pillar_surviving[k]) for k in PILLAR_KEYS}
        vetos_per_pillar = {k: [c for c in pillar_surviving[k] if c.get("severity") == "FATAL_VETO"] for k in PILLAR_KEYS}
        severe_per_pillar = {k: [c for c in pillar_surviving[k] if c.get("severity") == "SEVERE"] for k in PILLAR_KEYS}
        suspicious_per_pillar = {k: [c for c in pillar_surviving[k] if c.get("severity") == "SUSPICIOUS"] for k in PILLAR_KEYS}
        circumstantial_per_pillar = {k: [c for c in pillar_surviving[k] if c.get("severity") == "CIRCUMSTANTIAL"] for k in PILLAR_KEYS}

        # Standalone Pillar Risk Scores (0 - 100)
        standalone_scores: Dict[str, float] = {}
        for k in PILLAR_KEYS:
            v_count = len(vetos_per_pillar[k])
            if v_count > 0:
                max_veto_pts = max(float(c.get("risk_points", 0.0)) for c in vetos_per_pillar[k])
                score = min(100.0, max(max_veto_pts, 92.0 + v_count * 3.0))
            elif len(pillar_surviving[k]) == 0:
                score = 0.0
            else:
                if final_score <= 15.0 and len(surviving_counts) <= 1 and len(surviving_severe) == 0:
                    score = max(0.0, min(15.0, raw_pts[k] * 0.25))
                else:
                    score = min(90.0, max(10.0, raw_pts[k]))
            standalone_scores[k] = round(score, 1)

        # Mathematical Contribution Allocation: C_k such that sum(C_k) == final_score
        F = round(final_score, 1)
        weights: Dict[str, float] = {}
        has_any_fatal = any(len(v) > 0 for v in vetos_per_pillar.values())

        if has_any_fatal:
            for k in PILLAR_KEYS:
                if len(vetos_per_pillar[k]) > 0:
                    weights[k] = 100.0 * len(vetos_per_pillar[k]) + raw_pts[k]
                else:
                    weights[k] = raw_pts[k] if raw_pts[k] > 0 else 0.0
        else:
            for k in PILLAR_KEYS:
                weights[k] = raw_pts[k]

        total_weight = sum(weights.values())

        contributions: Dict[str, float] = {}
        percentages: Dict[str, float] = {}

        if F == 0.0:
            for k in PILLAR_KEYS:
                contributions[k] = 0.0
                percentages[k] = 0.0
        elif total_weight == 0.0:
            # Baseline caution with no surviving charges
            even_share = round(F / 4.0, 1)
            for k in PILLAR_KEYS[:-1]:
                contributions[k] = even_share
            contributions[PILLAR_KEYS[-1]] = round(F - sum(contributions.values()), 1)
            for k in PILLAR_KEYS:
                percentages[k] = round((contributions[k] / F) * 100.0, 1) if F > 0 else 0.0
        else:
            # Proportional contribution
            unrounded_contrib = {k: F * (weights[k] / total_weight) for k in PILLAR_KEYS}
            contributions = {k: round(unrounded_contrib[k], 1) for k in PILLAR_KEYS}
            
            # Correct any rounding drift to preserve sum(contributions) == F
            drift = round(F - sum(contributions.values()), 1)
            if drift != 0.0:
                max_key = max(PILLAR_KEYS, key=lambda k: (weights[k], contributions[k]))
                contributions[max_key] = round(contributions[max_key] + drift, 1)

            # Ensure bounds [0.0, F]
            for k in PILLAR_KEYS:
                contributions[k] = max(0.0, min(F, contributions[k]))

            # Percentages
            for k in PILLAR_KEYS:
                percentages[k] = round((contributions[k] / F) * 100.0, 1)
            
            pct_drift = round(100.0 - sum(percentages.values()), 1)
            if pct_drift != 0.0:
                max_key = max(PILLAR_KEYS, key=lambda k: contributions[k])
                percentages[max_key] = round(percentages[max_key] + pct_drift, 1)

        # Context Highlights Extraction
        envelope = parsed_mail.get("envelope", {})
        auth_lines = " ".join(parsed_mail.get("auth_results", [])).lower()
        from_raw = envelope.get("from_raw", "(Unknown)")
        from_domain = envelope.get("from_domain", "")

        spf_status = "PASS" if "spf=pass" in auth_lines else ("FAIL" if ("spf=fail" in auth_lines or "spf=hardfail" in auth_lines) else ("SOFTFAIL" if "spf=softfail" in auth_lines else "ABSENT"))
        dkim_status = "PASS" if "dkim=pass" in auth_lines else ("FAIL" if "dkim=fail" in auth_lines else "ABSENT")
        dmarc_status = "PASS" if "dmarc=pass" in auth_lines else ("FAIL" if ("dmarc=fail" in auth_lines or "dmarc=reject" in auth_lines) else "ABSENT")

        sender_highlights = [
            f"Sender: {from_raw[:50]}",
            f"SPF: {spf_status}",
            f"DKIM: {dkim_status}",
            f"DMARC: {dmarc_status}"
        ]
        if defense_brief.get("is_certified_esp"):
            sender_highlights.append(f"Certified Relay: {defense_brief.get('certified_esp_provider', '').upper()}")

        body_dict = parsed_mail.get("body", {})
        combined_body = body_dict.get("combined", "")
        html_body = body_dict.get("html", "")
        body_highlights = [
            f"Size: {len(combined_body)} chars",
            f"Format: {'HTML + Plaintext' if html_body else 'Plaintext'}"
        ]
        if any(c.get("category") == "BEC_FRAUD" for c in pillar_surviving["body"]):
            body_highlights.append("BEC / Wire Fraud Trigger")
        if any(c.get("category") == "BODY_CLOAKING" for c in pillar_surviving["body"]):
            body_highlights.append("Hidden CSS Cloaking")
        if any(c.get("category") == "PSYCH_URGENCY" for c in pillar_surviving["body"]):
            body_highlights.append("Urgency Pressure")
        if not pillar_surviving["body"]:
            body_highlights.append("Zero Cloaking / Coercion")

        urls_list = parsed_mail.get("urls", [])
        urls_highlights = [
            f"Total Links: {len(urls_list)}"
        ]
        if not urls_list:
            urls_highlights.append("Zero Hyperlinks (No URL Attack Surface)")
        else:
            flagged_urls = len([c for c in pillar_surviving["urls"] if c.get("category") == "URL_DECEPTION"])
            if flagged_urls > 0:
                urls_highlights.append(f"{flagged_urls} Deceptive Link(s) Flagged")
            else:
                urls_highlights.append("All Links Cleared Safe")

        att_list = parsed_mail.get("attachments", [])
        att_highlights = [
            f"Total Attachments: {len(att_list)}"
        ]
        if not att_list:
            att_highlights.append("Zero Payloads (Surface Minimized)")
        else:
            mal_att = len([c for c in pillar_surviving["attachments"] if c.get("severity") == "FATAL_VETO"])
            if mal_att > 0:
                att_highlights.append(f"{mal_att} Weaponized File(s) Detected")
            else:
                att_highlights.append("Static Forensics Certified Clean")

        highlights_map = {
            "sender": sender_highlights,
            "body": body_highlights,
            "urls": urls_highlights,
            "attachments": att_highlights
        }

        # Build Pillars Structure
        pillars_dict = {}
        for k in PILLAR_KEYS:
            surv_list = pillar_surviving[k]
            dism_list = pillar_dismissed[k]
            has_fatal = len(vetos_per_pillar[k]) > 0

            # Determine severity & status
            if has_fatal:
                severity = "FATAL_VETO"
                status = "CRITICAL"
            elif len(severe_per_pillar[k]) > 0:
                severity = "SEVERE"
                status = "DANGER"
            elif len(suspicious_per_pillar[k]) > 0:
                severity = "SUSPICIOUS"
                status = "WARNING"
            elif len(circumstantial_per_pillar[k]) > 0:
                severity = "CIRCUMSTANTIAL"
                status = "LOW_RISK"
            else:
                severity = "SAFE"
                status = "PASS"

            # Factor itemization
            factors = []
            for c in surv_list:
                factors.append({
                    "id": c.get("count_id"),
                    "title": c.get("charge_name"),
                    "severity": c.get("severity"),
                    "risk_points": c.get("risk_points", 0.0),
                    "status": "SUSTAINED",
                    "statute": c.get("statute", ""),
                    "exhibit": c.get("exhibit", ""),
                    "explanation": c.get("explanation", ""),
                    "dismissal_grounds": None
                })
            for c in dism_list:
                factors.append({
                    "id": c.get("count_id"),
                    "title": c.get("charge_name"),
                    "severity": c.get("severity"),
                    "risk_points": c.get("risk_points", 0.0),
                    "status": "DISMISSED",
                    "statute": c.get("statute", ""),
                    "exhibit": c.get("exhibit", ""),
                    "explanation": c.get("explanation", ""),
                    "dismissal_grounds": c.get("dismissal_grounds", "Dismissed under Penty Disprover Rule.")
                })

            # Analytical summary
            if has_fatal:
                summary = f"Critical fatal threat vector identified ({len(vetos_per_pillar[k])} non-dismissible veto{'s' if len(vetos_per_pillar[k]) > 1 else ''}). Mandates gateway rejection."
            elif len(severe_per_pillar[k]) > 0:
                summary = f"Severe threat indicators sustained ({len(severe_per_pillar[k])} charge{'s' if len(severe_per_pillar[k]) > 1 else ''}). Significant contributor to malicious verdict."
            elif len(suspicious_per_pillar[k]) > 0:
                summary = f"Suspicious anomalies detected ({len(suspicious_per_pillar[k])} count{'s' if len(suspicious_per_pillar[k]) > 1 else ''}). Warrant user caution."
            elif len(dism_list) > 0 and len(surv_list) == 0:
                summary = f"All {len(dism_list)} prosecution charge{'s' if len(dism_list) > 1 else ''} successfully disproved and dismissed by defense."
            else:
                summary = "Clean: Passed all forensic checks with zero threat indicators."

            pillars_dict[k] = {
                "pillar": k,
                "name": PILLAR_METADATA[k]["name"],
                "icon": PILLAR_METADATA[k]["icon"],
                "description": PILLAR_METADATA[k]["description"],
                "risk_score": standalone_scores[k],
                "contribution_score": contributions[k],
                "contribution_percentage": percentages[k],
                "severity": severity,
                "status": status,
                "has_fatal_veto": has_fatal,
                "sustained_charges_count": len(surv_list),
                "dismissed_charges_count": len(dism_list),
                "raw_risk_points": raw_pts[k],
                "factors": factors,
                "context_highlights": highlights_map[k],
                "summary": summary
            }

        # Highest contributor determination
        if F > 0:
            highest_key = max(PILLAR_KEYS, key=lambda k: (contributions[k], standalone_scores[k]))
            highest_name = PILLAR_METADATA[highest_key]["name"]
        else:
            highest_key = "none"
            highest_name = "None (All Pillars Certified Clean)"

        # Executive summary text
        if F == 0.0:
            summary_text = (
                "Overall risk score is 0.0/100 (Certified Legitimate / Safe). "
                "All four vectors — Sender, Email Body, URLs, and Attachments — passed security baseline with zero sustained threat indicators."
            )
        elif has_any_fatal:
            veto_pillar_names = [PILLAR_METADATA[k]["name"] for k in PILLAR_KEYS if len(vetos_per_pillar[k]) > 0]
            summary_text = (
                f"Overall risk score of {F}/100 is decisively driven by fatal threat vectors in "
                f"{', '.join(veto_pillar_names)} ({contributions[highest_key]} pts / {percentages[highest_key]}% contribution). "
                f"Under the Monotonic Veto Rule, these critical findings mandate gateway quarantine."
            )
        elif F <= 15.0:
            summary_text = (
                f"Overall risk score of {F}/100 is certified SAFE under the Multi-Indicator Fusion Rule. "
                f"Isolated residual signal in {highest_name} ({contributions[highest_key]} pts) is insufficient proof of malice without corroborating vectors."
            )
        else:
            summary_text = (
                f"Overall risk score of {F}/100 reflects a composite multi-vector threat: "
                f"{highest_name} is the primary driver contributing {contributions[highest_key]} pts ({percentages[highest_key]}%), "
                f"corroborated by secondary forensic indicators."
            )

        formula = (
            f"Overall Risk ({F}) = Sender ({contributions['sender']}) + "
            f"Body ({contributions['body']}) + URLs ({contributions['urls']}) + "
            f"Attachments ({contributions['attachments']})"
        )

        return {
            "pillars": pillars_dict,
            "total_risk_score": F,
            "highest_contributor": highest_key,
            "highest_contributor_name": highest_name,
            "summary_text": summary_text,
            "attribution_formula": formula
        }


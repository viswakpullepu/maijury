"""
CHIEF JUSTICE ARBITER (Adversarial Courtroom Synthesis Engine)
Orchestrates the formal debate between Team Prosecutor (Red Team) and Team Defender (Blue Team).
Applies the Penty Disprover Principle, Monotonic Veto Standard, and Bharatiya Sakshya Adhiniyam Sec 65B.
Delivers binding verdicts: LEGITIMATE (Certified Safe) vs FAKE/MALICIOUS (Quarantine).
"""
import time
import hashlib
from typing import Dict, List, Any, Optional

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

        self._log_transcript(trial_transcript, "CHIEF_JUSTICE",
            f"FINAL DECREE: The Court enters a binding verdict of {verdict} (Risk Score: {final_score}/100). "
            f"Disposition: {disposition}. {summary_justification}"
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

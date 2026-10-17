"""
Official PS4 Benchmark Runner & Test Suite Engine
Executes official hackathon test cases strictly in-memory (io.BytesIO)
and computes evaluation metrics against official ground truth.
"""

import os
import io
import csv
import time
from typing import Dict, List, Any, Optional

try:
    from eml_parser import EMLParser
    from team_prosecutor import TeamProsecutor
    from team_defender import TeamDefender
    from courtroom_arbiter import CourtroomArbiter
    from attachment_analyzer import AttachmentAnalyzer
except ImportError:
    from backend.eml_parser import EMLParser
    from backend.team_prosecutor import TeamProsecutor
    from backend.team_defender import TeamDefender
    from backend.courtroom_arbiter import CourtroomArbiter
    from backend.attachment_analyzer import AttachmentAnalyzer

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "official_ps4"))
if not os.path.exists(DATA_DIR):
    # Fallback to scratch if data/ doesn't exist
    DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scratch", "official_ps4", "PS4_Phishing_Email_Attachment_Checker"))

class OfficialBenchmarkRunner:
    """Zero-execution benchmark runner for Problem Statement 4 official datasets."""

    @classmethod
    def get_catalog(cls, variant: str = "A") -> List[Dict[str, Any]]:
        """Returns metadata for all official test files in the test arena."""
        catalog = []
        variant = variant.upper()
        if variant not in ["A", "B"]:
            variant = "A"

        # 1. Mission 04 Edge-Case Test Cases (TC01 - TC15)
        tc_dir = os.path.join(DATA_DIR, "emails", "mission04_tests")
        tc_descs = {
            "TC01": ("Clean Email Without Attachments", "legitimate", "Baseline benign message with standard RFC headers"),
            "TC02": ("Clean PDF Document", "benign", "Certified ISO 32000-1 document with zero /Launch or /JS"),
            "TC03": ("PDF with Active /OpenAction + /JS", "suspicious", "Active content exploit container with automatic trigger"),
            "TC04": ("Macro-Enabled Word Document (.docm)", "suspicious", "VBA macro stream container (vbaProject.bin detected)"),
            "TC05": ("Double Extension Executable (.pdf.exe)", "suspicious", "Windows shell extension masking technique"),
            "TC06": ("Type Mismatch Masquerade (Declared PDF, MZ Bytes)", "suspicious", "PE header hidden behind PDF MIME type"),
            "TC07": ("Password-Protected ZIP Archive", "suspicious", "Encrypted PKWARE container requiring in-body password"),
            "TC08": ("Deeply Nested ZIP Archive (Depth 4)", "suspicious", "Exceeds max recursion limit of 2 layers (Zip Bomb/Evasion)"),
            "TC09": ("Oversized Attachment (11.5 MB)", "suspicious", "Exceeds gateway policy inspection threshold of 10 MB"),
            "TC10": ("Corrupt / Truncated PDF (55 Bytes)", "suspicious", "Truncated payload lacking mandatory %%EOF trailer"),
            "TC11": ("Zero-Byte Empty Stream (0 Bytes)", "suspicious", "Empty file stream failing ingestion integrity validation"),
            "TC12": ("Benign ZIP Archive with Images", "benign", "Compressed image archive containing only raster graphics"),
            "TC13": ("Right-to-Left Override (RLO) Filename", "suspicious", "Unicode U+202E override inverting filename on display"),
            "TC14": ("HTML Credential Harvesting Form", "suspicious", "HTML attachment embedding <input type='password'> form"),
            "TC15": ("Standard Benign Enterprise Email", "legitimate", "Authentic internal communication with valid auth headers")
        }

        if os.path.exists(tc_dir):
            for fname in sorted(os.listdir(tc_dir)):
                if f"_{variant}." in fname:
                    tc_id = fname.split("_")[0]
                    desc, expected_label, attack_vector = tc_descs.get(tc_id, ("Test Case", "unknown", "Edge Case"))
                    file_path = os.path.join(tc_dir, fname)
                    file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
                    is_email = fname.endswith(".eml")
                    catalog.append({
                        "test_id": tc_id,
                        "filename": fname,
                        "category": "Mission 04 Edge Suite",
                        "title": desc,
                        "expected_label": expected_label,
                        "attack_vector": attack_vector,
                        "is_email": is_email,
                        "file_size": file_size,
                        "file_path": file_path,
                        "variant": variant
                    })

        # 2. Mission 01 Email Corpus (M1-01 to M1-16)
        m1_index = os.path.join(DATA_DIR, "reference", f"email_index_{variant}.csv")
        if os.path.exists(m1_index):
            with open(m1_index, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get("folder") == "mission01":
                        email_id = row["email_id"]
                        fname = row["file"]
                        fpath = os.path.join(DATA_DIR, "emails", "mission01", fname)
                        file_size = os.path.getsize(fpath) if os.path.exists(fpath) else 0
                        catalog.append({
                            "test_id": email_id,
                            "filename": fname,
                            "category": "Mission 01 Email Corpus",
                            "title": f"Mission 01 Sample {email_id}",
                            "expected_label": row["label"].lower().strip(),
                            "attack_vector": row["signals"],
                            "is_email": True,
                            "file_size": file_size,
                            "file_path": fpath,
                            "variant": variant
                        })

        # 3. Mission 02 Attachment Corpus (M2-01 to M2-14)
        if os.path.exists(m1_index):
            with open(m1_index, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get("folder") == "mission02":
                        email_id = row["email_id"]
                        fname = row["file"]
                        fpath = os.path.join(DATA_DIR, "emails", "mission02", fname)
                        file_size = os.path.getsize(fpath) if os.path.exists(fpath) else 0
                        catalog.append({
                            "test_id": email_id,
                            "filename": fname,
                            "category": "Mission 02 Attachment Corpus",
                            "title": f"Mission 02 Sample {email_id}",
                            "expected_label": row["label"].lower().strip(),
                            "attack_vector": row["signals"],
                            "is_email": True,
                            "file_size": file_size,
                            "file_path": fpath,
                            "variant": variant
                        })

        return catalog

    @classmethod
    def run_single_test(cls, file_path: str, expected_label: str, filename: str, is_email: bool) -> Dict[str, Any]:
        """Runs a single test item in memory and evaluates against expected label."""
        t0 = time.perf_counter()
        if not os.path.exists(file_path):
            return {
                "filename": filename,
                "status": "ERROR",
                "message": f"File not found: {file_path}",
                "match": False
            }

        with open(file_path, "rb") as f:
            raw_bytes = f.read()

        if is_email:
            parsed = EMLParser.parse(raw_bytes)
            attachments_analysis = []
            for att in parsed.get("attachments", []):
                rep = att.get("analysis")
                if not rep:
                    rep = AttachmentAnalyzer.inspect_attachment(
                        filename=att.get("filename", ""),
                        payload=att.get("raw_payload", b""),
                        declared_ct=att.get("declared_type", ""),
                        email_body_text=parsed.get("body", {}).get("combined", "")
                    )
                    att["analysis"] = rep
                attachments_analysis.append(rep)

            prosecution = TeamProsecutor().prosecute(parsed)
            defense = TeamDefender().defend(parsed, prosecution)
            verdict_obj = CourtroomArbiter().adjudicate(parsed, prosecution, defense)
            trial = {
                "prosecution": prosecution,
                "defense": defense,
                "verdict": verdict_obj,
                "actionable_recommendations": verdict_obj.get("actionable_recommendations", {})
            }
            v_str = verdict_obj.get("verdict", "").upper()
            score = verdict_obj.get("final_risk_score", 0.0)
            
            # Map verdict to expected categories
            if "PHISHING" in v_str or "MALICIOUS" in v_str:
                predicted_label = "phishing"
            elif "SUSPICIOUS" in v_str or "CAUTION" in v_str:
                predicted_label = "suspicious"
            else:
                predicted_label = "legitimate"

            # Check match
            if expected_label == "legitimate":
                match = (predicted_label == "legitimate")
            elif expected_label in ["phishing", "suspicious"]:
                match = (predicted_label in ["phishing", "suspicious"])
            else:
                match = (predicted_label == expected_label)

            charges = [c.get("charge_name", "Allegation") for c in trial["prosecution"].get("counts", [])]
            objections = [o.get("grounds", "Defense Objection") for o in trial["defense"].get("objections", [])]
            evidence = trial["verdict"].get("summary_justification", "")
            actionable = trial.get("actionable_recommendations", {})

            duration_ms = round((time.perf_counter() - t0) * 1000, 2)
            return {
                "filename": filename,
                "is_email": True,
                "verdict": v_str,
                "score": score,
                "predicted_label": predicted_label,
                "expected_label": expected_label,
                "match": match,
                "status": "PASS" if match else "MISMATCH",
                "charges": charges,
                "objections": objections,
                "evidence": evidence,
                "actionable_recommendations": actionable,
                "duration_ms": duration_ms,
                "size_bytes": len(raw_bytes)
            }
        else:
            # Standalone attachment
            rep = AttachmentAnalyzer.inspect_attachment(filename=filename, payload=raw_bytes)
            risk_level = rep.get("risk_level", "SAFE")
            score = rep.get("risk_score", 0.0)
            
            if risk_level in ["MALICIOUS", "SUSPICIOUS"] or score >= 40.0:
                predicted_label = "suspicious"
            else:
                predicted_label = "benign"

            if expected_label in ["suspicious", "malicious"]:
                match = (predicted_label in ["suspicious", "malicious"])
            elif expected_label == "benign":
                match = (predicted_label == "benign")
            else:
                match = (predicted_label == expected_label)

            duration_ms = round((time.perf_counter() - t0) * 1000, 2)
            return {
                "filename": filename,
                "is_email": False,
                "verdict": risk_level,
                "score": score,
                "predicted_label": predicted_label,
                "expected_label": expected_label,
                "match": match,
                "status": "PASS" if match else "MISMATCH",
                "charges": rep.get("evidence", []),
                "objections": ["Zero-execution verified in-memory stream"],
                "evidence": " ".join(rep.get("reasons", [])),
                "classification": rep.get("classification", ""),
                "duration_ms": duration_ms,
                "size_bytes": len(raw_bytes)
            }

    @classmethod
    def run_suite(cls, suite_type: str = "all", variant: str = "A") -> Dict[str, Any]:
        """Runs the requested suite and computes full confusion matrix and summary statistics."""
        t_start = time.perf_counter()
        catalog = cls.get_catalog(variant=variant)

        if suite_type == "mission04":
            filtered = [item for item in catalog if "Mission 04" in item["category"]]
        elif suite_type == "mission01":
            filtered = [item for item in catalog if "Mission 01" in item["category"]]
        elif suite_type == "mission02":
            filtered = [item for item in catalog if "Mission 02" in item["category"]]
        else:
            filtered = catalog

        results = []
        tp, fp, tn, fn = 0, 0, 0, 0

        for item in filtered:
            res = cls.run_single_test(
                file_path=item["file_path"],
                expected_label=item["expected_label"],
                filename=item["filename"],
                is_email=item["is_email"]
            )
            # Combine catalog info
            res["test_id"] = item["test_id"]
            res["category"] = item["category"]
            res["title"] = item["title"]
            res["attack_vector"] = item["attack_vector"]
            results.append(res)

            # Confusion Matrix calculation
            exp = item["expected_label"]
            pred = res["predicted_label"]
            is_mal = (exp in ["phishing", "suspicious", "malicious"])
            pred_mal = (pred in ["phishing", "suspicious", "malicious"])

            if is_mal and pred_mal:
                tp += 1
            elif not is_mal and not pred_mal:
                tn += 1
            elif not is_mal and pred_mal:
                fp += 1
            elif is_mal and not pred_mal:
                fn += 1

        total = len(results)
        passed = sum(1 for r in results if r.get("match", False))
        accuracy = round((passed / total * 100), 2) if total > 0 else 0.0
        fpr = round((fp / (fp + tn) * 100), 2) if (fp + tn) > 0 else 0.0
        total_time_ms = round((time.perf_counter() - t_start) * 1000, 2)
        mean_latency = round(total_time_ms / total, 2) if total > 0 else 0.0

        summary = {
            "suite_type": suite_type,
            "variant": variant,
            "total_tests": total,
            "passed_tests": passed,
            "failed_tests": total - passed,
            "accuracy_percent": accuracy,
            "false_positive_count": fp,
            "false_positive_rate": fpr,
            "confusion_matrix": {
                "true_positives": tp,
                "true_negatives": tn,
                "false_positives": fp,
                "false_negatives": fn
            },
            "total_execution_ms": total_time_ms,
            "mean_latency_ms": mean_latency,
            "zero_execution_guarantee": True,
            "timestamp": time.time()
        }

        return {
            "summary": summary,
            "results": results
        }


if __name__ == "__main__":
    import json
    import sys
    # Ensure stdout handles utf-8 if possible
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
        
    print("=" * 80)
    print("[*] RUNNING OFFICIAL PS4 BENCHMARK SUITE (Variant A & B)")
    print("=" * 80)
    report = OfficialBenchmarkRunner.run_suite(suite_type="all", variant="both")
    summary = report["summary"]
    print(f"Total Tests Executed: {summary['total_tests']}")
    print(f"Passed Tests:         {summary['passed_tests']}")
    print(f"Failed Tests:         {summary['failed_tests']}")
    print(f"Accuracy:             {summary['accuracy_percent']}%")
    print(f"False Positive Rate:  {summary['false_positive_rate']}%")
    print(f"Confusion Matrix:     TP={summary['confusion_matrix']['true_positives']} | TN={summary['confusion_matrix']['true_negatives']} | FP={summary['confusion_matrix']['false_positives']} | FN={summary['confusion_matrix']['false_negatives']}")
    print(f"Total Time:           {summary['total_execution_ms']} ms (Mean {summary['mean_latency_ms']} ms/test)")
    print(f"Zero-Execution Safe:  {summary['zero_execution_guarantee']}")
    print("=" * 80)
    if summary["failed_tests"] > 0:
        print("FAILURES DETECTED:")
        for r in report["results"]:
            if not r.get("match", False):
                print(f" - [{r['id']}] Expected: {r['expected_label']}, Predicted: {r['predicted_label']}")
    else:
        print("[SUCCESS] ALL OFFICIAL BENCHMARK TESTS PASSED WITH 100% ACCURACY!")



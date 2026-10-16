"""
Test Suite: User Feedback & False Positive / False Negative Evaluation Engine
Mission 02 / Requirement 4

Verifies:
- User feedback ingestion (False Positives, False Negatives, Disputed Indicators)
- Confusion Matrix & Accuracy / Precision / Recall / F1-Score computations
- BSA §65B Cryptographic Evidence Token Generation
- Thread-safe atomic file persistence and reload
- Calibration insight generation for Arbiter, Prosecutor, and Defender
- CSV Export formatting
- REST API integration via FastAPI TestClient
"""

import os
import shutil
import tempfile
import pytest
from fastapi.testclient import TestClient

from backend.feedback_engine import (
    FeedbackStore,
    FeedbackSubmission,
    FeedbackType,
    FeedbackStatus,
    ConfusionMatrix,
)


@pytest.fixture
def temp_store():
    """Provides an isolated FeedbackStore in a temporary directory."""
    temp_dir = tempfile.mkdtemp(prefix="mailjury_test_feedback_")
    store = FeedbackStore(storage_dir=temp_dir)
    yield store
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_add_false_positive_feedback(temp_store: FeedbackStore):
    """Test user reporting a false positive on a legitimate email falsely flagged as phishing."""
    submission = FeedbackSubmission(
        email_sha256="aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999",
        email_subject="Payroll Update: Bank Account Migration",
        email_from="hr@mycorp.com",
        original_verdict="PHISHING / MALICIOUS",
        original_risk_score=85.0,
        reported_classification="LEGITIMATE",
        feedback_type=FeedbackType.FALSE_POSITIVE,
        disputed_indicators=["COUNT #1: Financial Urgency", "COUNT #2: Password Reset Link"],
        analyst_notes="Legitimate internal HR notice sent to all employees.",
        reporter_role="soc_analyst",
        suggested_risk_score=5.0
    )

    rec = temp_store.add_feedback(submission)
    assert rec.feedback_id.startswith("FB-")
    assert rec.status == FeedbackStatus.PENDING_REVIEW
    assert rec.evidence_token.startswith("BSA65B-FB-")
    assert rec.submission.feedback_type == FeedbackType.FALSE_POSITIVE
    assert len(rec.submission.disputed_indicators) == 2


def test_add_false_negative_feedback(temp_store: FeedbackStore):
    """Test user reporting a false negative on an evasive scam email falsely marked safe."""
    submission = FeedbackSubmission(
        email_sha256="1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
        email_subject="Important Security Upgrade (Scan QR)",
        email_from="support@microsoft-online-security.com",
        original_verdict="LEGITIMATE / SAFE",
        original_risk_score=10.0,
        reported_classification="PHISHING",
        feedback_type=FeedbackType.FALSE_NEGATIVE,
        disputed_indicators=["MISSED: Embedded Quishing QR Code"],
        analyst_notes="Stealth quishing attack stealing M365 session cookies.",
        reporter_role="security_admin",
        suggested_risk_score=98.0
    )

    rec = temp_store.add_feedback(submission)
    assert rec.submission.feedback_type == FeedbackType.FALSE_NEGATIVE
    assert rec.submission.reported_classification == "PHISHING"
    assert rec.submission.suggested_risk_score == 98.0


def test_persistence_and_reload(temp_store: FeedbackStore):
    """Verify atomic disk write and persistence across instance restarts."""
    sub = FeedbackSubmission(
        email_sha256="hash123",
        email_subject="Test Email",
        email_from="sender@example.com",
        original_verdict="SUSPICIOUS",
        original_risk_score=55.0,
        reported_classification="LEGITIMATE",
        feedback_type=FeedbackType.FALSE_POSITIVE,
        disputed_indicators=["Urgency count"],
        analyst_notes="Operational notification.",
        reporter_role="end_user"
    )
    rec = temp_store.add_feedback(sub)
    fid = rec.feedback_id

    # Re-instantiate a second FeedbackStore pointing to the same directory
    reloaded_store = FeedbackStore(storage_dir=temp_store.storage_dir)
    loaded_rec = reloaded_store.get_by_id(fid)

    assert loaded_rec is not None
    assert loaded_rec.feedback_id == fid
    assert loaded_rec.submission.email_sha256 == "hash123"
    assert loaded_rec.evidence_token == rec.evidence_token


def test_update_status_and_resolution(temp_store: FeedbackStore):
    """Verify status transitions and analyst resolution notes."""
    sub = FeedbackSubmission(
        email_sha256="hash456",
        email_subject="Suspicious Invoice",
        email_from="vendor@domain.com",
        original_verdict="PHISHING",
        original_risk_score=80.0,
        reported_classification="LEGITIMATE",
        feedback_type=FeedbackType.FALSE_POSITIVE
    )
    rec = temp_store.add_feedback(sub)

    updated = temp_store.update_status(
        feedback_id=rec.feedback_id,
        status=FeedbackStatus.VERIFIED,
        notes="Confirmed by SOC lead. Rule calibration approved."
    )

    assert updated is not None
    assert updated.status == FeedbackStatus.VERIFIED
    assert updated.resolved_at is not None
    assert updated.resolution_notes == "Confirmed by SOC lead. Rule calibration approved."


def test_query_and_search_filtering(temp_store: FeedbackStore):
    """Test filtering by feedback_type, status, and full-text search."""
    sub1 = FeedbackSubmission(
        email_sha256="hash_fp",
        email_subject="Urgent Payroll Notification",
        email_from="payroll@internal.com",
        original_verdict="PHISHING",
        original_risk_score=82.0,
        reported_classification="LEGITIMATE",
        feedback_type=FeedbackType.FALSE_POSITIVE,
        analyst_notes="Payroll notice"
    )
    sub2 = FeedbackSubmission(
        email_sha256="hash_fn",
        email_subject="Free Gift Card Delivery",
        email_from="scam@attacker.com",
        original_verdict="LEGITIMATE",
        original_risk_score=15.0,
        reported_classification="PHISHING",
        feedback_type=FeedbackType.FALSE_NEGATIVE,
        analyst_notes="Phishing gift card"
    )

    temp_store.add_feedback(sub1)
    temp_store.add_feedback(sub2)

    # Filter by type
    fps = temp_store.get_all(feedback_type="FALSE_POSITIVE")
    assert len(fps) == 1
    assert fps[0].submission.email_subject == "Urgent Payroll Notification"

    fns = temp_store.get_all(feedback_type="FALSE_NEGATIVE")
    assert len(fns) == 1
    assert fns[0].submission.email_subject == "Free Gift Card Delivery"

    # Search keyword
    searched = temp_store.get_all(search="payroll")
    assert len(searched) == 1
    assert searched[0].submission.email_from == "payroll@internal.com"


def test_confusion_matrix_and_evaluation_metrics(temp_store: FeedbackStore):
    """Test mathematical accuracy of Confusion Matrix (TP, TN, FP, FN, Precision, Recall, F1)."""
    # Baseline benchmark: 20 TP, 10 TN, 0 FP, 0 FN -> Accuracy 100%
    report_initial = temp_store.evaluate_metrics()
    cm_init = report_initial.confusion_matrix
    assert cm_init.true_positives == 20
    assert cm_init.true_negatives == 10
    assert cm_init.false_positives == 0
    assert cm_init.false_negatives == 0
    assert cm_init.accuracy == 1.0
    assert cm_init.precision == 1.0
    assert cm_init.recall == 1.0
    assert cm_init.false_positive_rate == 0.0

    # Add 1 False Positive
    sub_fp = FeedbackSubmission(
        email_sha256="h1",
        email_subject="Legitimate Urgent Memo",
        original_verdict="PHISHING",
        original_risk_score=75.0,
        reported_classification="LEGITIMATE",
        feedback_type=FeedbackType.FALSE_POSITIVE,
        disputed_indicators=["Urgency keyword"]
    )
    temp_store.add_feedback(sub_fp)

    # Add 1 False Negative
    sub_fn = FeedbackSubmission(
        email_sha256="h2",
        email_subject="Stealth Phishing Archive",
        original_verdict="LEGITIMATE",
        original_risk_score=10.0,
        reported_classification="PHISHING",
        feedback_type=FeedbackType.FALSE_NEGATIVE,
        disputed_indicators=["Encrypted ZIP with body password"]
    )
    temp_store.add_feedback(sub_fn)

    report_evaluated = temp_store.evaluate_metrics()
    cm = report_evaluated.confusion_matrix

    assert cm.true_positives == 20
    assert cm.true_negatives == 10
    assert cm.false_positives == 1
    assert cm.false_negatives == 1
    assert cm.total_samples == 32

    # Accuracy = (20 + 10) / 32 = 30 / 32 = 0.9375
    assert cm.accuracy == 0.9375

    # Precision = TP / (TP + FP) = 20 / 21 = 0.9524
    assert cm.precision == round(20 / 21, 4)

    # Recall = TP / (TP + FN) = 20 / 21 = 0.9524
    assert cm.recall == round(20 / 21, 4)

    # False Positive Rate = FP / (FP + TN) = 1 / (1 + 10) = 0.0909
    assert cm.false_positive_rate == round(1 / 11, 4)

    # False Negative Rate = FN / (FN + TP) = 1 / (1 + 20) = 0.0476
    assert cm.false_negative_rate == round(1 / 21, 4)


def test_calibration_insights_generation(temp_store: FeedbackStore):
    """Test dynamic generation of rule calibration recommendations based on reported errors."""
    sub_fp = FeedbackSubmission(
        email_sha256="h_urgency",
        email_subject="Urgent Deadline Warning",
        original_verdict="PHISHING",
        original_risk_score=80.0,
        reported_classification="LEGITIMATE",
        feedback_type=FeedbackType.FALSE_POSITIVE,
        disputed_indicators=["COUNT #1: Urgency Deadline Phrasing"]
    )
    temp_store.add_feedback(sub_fp)

    sub_fn = FeedbackSubmission(
        email_sha256="h_zip",
        email_subject="Invoice package (pass: 1234)",
        original_verdict="LEGITIMATE",
        original_risk_score=15.0,
        reported_classification="PHISHING",
        feedback_type=FeedbackType.FALSE_NEGATIVE,
        disputed_indicators=["ATTACHMENT: Password-protected ZIP archive"]
    )
    temp_store.add_feedback(sub_fn)

    report = temp_store.evaluate_metrics()
    insights = report.calibration_insights

    rule_targets = [ins.rule_target for ins in insights]
    assert any("CourtroomArbiter" in t for t in rule_targets)
    assert any("AttachmentAnalyzer" in t for t in rule_targets)

    # Verify top disputed indicators are counted correctly
    top_ind = report.top_disputed_indicators
    assert len(top_ind) >= 2


def test_csv_export(temp_store: FeedbackStore):
    """Test RFC 4180 CSV export functionality."""
    sub = FeedbackSubmission(
        email_sha256="export_sha256_hash",
        email_subject="Export Test Subject",
        email_from="sender@corp.com",
        original_verdict="PHISHING",
        original_risk_score=90.0,
        reported_classification="LEGITIMATE",
        feedback_type=FeedbackType.FALSE_POSITIVE,
        disputed_indicators=["Indicator A", "Indicator B"],
        analyst_notes="Test analyst note",
        reporter_role="soc_analyst"
    )
    temp_store.add_feedback(sub)

    csv_data = temp_store.export_csv()
    assert "feedback_id" in csv_data
    assert "email_sha256" in csv_data
    assert "export_sha256_hash" in csv_data
    assert "Export Test Subject" in csv_data
    assert "FALSE_POSITIVE" in csv_data
    assert "BSA65B-FB-" in csv_data


def test_delete_feedback(temp_store: FeedbackStore):
    """Test record deletion."""
    sub = FeedbackSubmission(
        email_sha256="del_hash",
        original_verdict="PHISHING",
        original_risk_score=70.0,
        reported_classification="LEGITIMATE",
        feedback_type=FeedbackType.FALSE_POSITIVE
    )
    rec = temp_store.add_feedback(sub)
    fid = rec.feedback_id

    assert temp_store.get_by_id(fid) is not None
    assert temp_store.delete_feedback(fid) is True
    assert temp_store.get_by_id(fid) is None
    assert temp_store.delete_feedback("NON_EXISTENT") is False


# ─── REST API ENDPOINTS TEST (TestClient) ───────────────────────────────────

def test_api_feedback_endpoints():
    """Test full FastAPI endpoint lifecycle for user feedback and accuracy evaluation."""
    os.environ["TESTING"] = "1"
    from backend.main import app
    client = TestClient(app)

    # 1. Post new feedback
    payload = {
        "email_sha256": "api_test_email_sha256_123456",
        "email_subject": "Quarterly Financial Forecast",
        "email_from": "cfo@company.com",
        "original_verdict": "PHISHING / MALICIOUS",
        "original_risk_score": 77.0,
        "reported_classification": "LEGITIMATE",
        "feedback_type": "FALSE_POSITIVE",
        "disputed_indicators": ["Urgent financial wording"],
        "analyst_notes": "Official communication from CFO office.",
        "reporter_role": "soc_analyst",
        "suggested_risk_score": 10.0
    }

    resp = client.post("/api/feedback", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "RECORDED"
    assert "feedback_id" in data["record"]
    fid = data["record"]["feedback_id"]

    # 2. Get feedback list
    list_resp = client.get("/api/feedback")
    assert list_resp.status_code == 200
    list_data = list_resp.json()
    assert list_data["total"] >= 1
    assert any(r["feedback_id"] == fid for r in list_data["records"])

    # 3. Get evaluation metrics
    eval_resp = client.get("/api/feedback/evaluation")
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()
    assert "confusion_matrix" in eval_data
    assert "calibration_insights" in eval_data
    assert eval_data["confusion_matrix"]["false_positives"] >= 1

    # 4. Patch feedback status
    patch_resp = client.patch(
        f"/api/feedback/{fid}/status",
        json={"status": "VERIFIED", "notes": "Approved by SOC supervisor"}
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["record"]["status"] == "VERIFIED"

    # 5. Export CSV
    export_resp = client.get("/api/feedback/export?format=csv")
    assert export_resp.status_code == 200
    assert "text/csv" in export_resp.headers["content-type"]
    assert "api_test_email_sha256_123456" in export_resp.text

    # 6. Run calibration simulation
    cal_resp = client.post("/api/feedback/calibrate")
    assert cal_resp.status_code == 200
    cal_data = cal_resp.json()
    assert "calibration_status" in cal_data
    assert "insights" in cal_data

    # 7. Clean up delete
    del_resp = client.delete(f"/api/feedback/{fid}")
    assert del_resp.status_code == 200
    assert del_resp.json()["status"] == "DELETED"

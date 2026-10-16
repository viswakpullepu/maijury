"""
Unit and Integration Tests for MailJury ML vs Rule-Based Comparison Engine
===========================================================================
Validates:
  1. Feature extraction dimensions, normalization, and bounds
  2. Confusion matrix and metric mathematical accuracy
  3. Machine learning model convergence (Logistic Regression, Naive Bayes, Random Forest)
  4. Hybrid Courtroom Arbiter fusion standard (Fatal Veto + Authenticated Dampening)
  5. Full BenchmarkMLComparisonSuite end-to-end execution
"""

import os
import sys
import unittest
import numpy as np

sys.path.insert(0, os.path.dirname(__file__))

from eml_parser import EMLParser
from ml_engine import EmailFeatureExtractor, ModelEvaluator, BenchmarkMLComparisonSuite


class TestMLComparisonEngine(unittest.TestCase):
    """Exhaustive test suite for the Machine Learning vs Rule-Based engine."""

    @classmethod
    def setUpClass(cls):
        cls.corpus_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "research", "benchmarks", "eml_corpus")
        )

    def test_01_feature_extractor_vector_shape_and_finite(self):
        """Verify feature extractor returns exactly 32 finite floating-point features."""
        sample_eml = (
            b"From: security@paypal.com\r\n"
            b"To: victim@example.com\r\n"
            b"Subject: URGENT: Account Suspended within 24 hours!\r\n"
            b"Date: Mon, 16 Oct 2026 10:00:00 +0000\r\n"
            b"Content-Type: text/html\r\n\r\n"
            b"<html><body>Please verify your login password immediately at "
            b"<a href='http://192.168.1.1/login'>http://paypal.com/verify</a>"
            b"<div style='font-size:0px;'>hidden anti-analysis text</div></body></html>"
        )
        parsed = EMLParser.parse(sample_eml)
        vec = EmailFeatureExtractor.extract_features(parsed)

        self.assertIsInstance(vec, np.ndarray)
        self.assertEqual(len(vec), 32)
        self.assertEqual(len(EmailFeatureExtractor.FEATURE_NAMES), 32)
        self.assertTrue(np.all(np.isfinite(vec)))

        # Verify specific semantic features
        feat_dict = dict(zip(EmailFeatureExtractor.FEATURE_NAMES, vec))
        self.assertEqual(feat_dict["subject_has_urgency"], 1.0)
        self.assertEqual(feat_dict["hidden_text_flag"], 1.0)
        self.assertGreaterEqual(feat_dict["url_ip_literal_count"], 1.0)
        self.assertGreaterEqual(feat_dict["credential_keyword_count"], 1.0)

    def test_02_model_evaluator_confusion_matrix_math(self):
        """Verify exact precision, recall, specificity, and confusion matrix arithmetic."""
        # 10 ground truth: 6 malicious (1), 4 benign (0)
        # Predictions: 5 TP, 1 FN, 3 TN, 1 FP
        y_true = [1, 1, 1, 1, 1, 1, 0, 0, 0, 0]
        y_pred = [1, 1, 1, 1, 1, 0, 0, 0, 0, 1]
        y_prob = [0.9, 0.8, 0.85, 0.95, 0.7, 0.4, 0.1, 0.2, 0.05, 0.6]

        res = ModelEvaluator.evaluate(y_true, y_pred, y_prob, "TestModel")

        cm = res["confusion_matrix"]
        self.assertEqual(cm["tp"], 5)
        self.assertEqual(cm["fn"], 1)
        self.assertEqual(cm["tn"], 3)
        self.assertEqual(cm["fp"], 1)
        self.assertEqual(cm["matrix_2x2"], [[3, 1], [1, 5]])

        m = res["metrics"]
        self.assertEqual(m["accuracy"], 80.0)      # 8/10
        self.assertEqual(m["precision"], 83.33)   # 5/6 = 83.33%
        self.assertEqual(m["recall"], 83.33)      # 5/6 = 83.33%
        self.assertEqual(m["specificity"], 75.0)  # 3/4 = 75.0%
        self.assertEqual(m["false_positive_rate"], 25.0) # 1/4 = 25.0%
        self.assertEqual(m["false_negative_rate"], 16.67) # 1/6 = 16.67%
        self.assertAlmostEqual(m["f1_score"], 0.8333, places=3)
        self.assertGreater(m["mcc"], 0.5)
        self.assertGreater(m["roc_auc"], 0.8)

    def test_03_benign_authenticated_features_vs_malicious(self):
        """Verify feature extractor distinguishes authenticated benign from phishing."""
        benign_path = os.path.join(self.corpus_dir, "27_benign_aws_cloudwatch_alarm.eml")
        if os.path.exists(benign_path):
            with open(benign_path, "rb") as f:
                parsed_benign = EMLParser.parse(f.read())
            b_vec = EmailFeatureExtractor.extract_features(parsed_benign)
            b_dict = dict(zip(EmailFeatureExtractor.FEATURE_NAMES, b_vec))

            # AWS alarm has valid authentication headers
            self.assertGreaterEqual(b_dict["auth_pass_sum"], 1.0)
            self.assertEqual(b_dict["att_magic_mismatch"], 0.0)
            self.assertEqual(b_dict["att_has_executable"], 0.0)

        malicious_path = os.path.join(self.corpus_dir, "01_bec_ceo_wire_fraud.eml")
        if os.path.exists(malicious_path):
            with open(malicious_path, "rb") as f:
                parsed_mal = EMLParser.parse(f.read())
            m_vec = EmailFeatureExtractor.extract_features(parsed_mal)
            m_dict = dict(zip(EmailFeatureExtractor.FEATURE_NAMES, m_vec))

            # CEO wire fraud has financial tokens and unaligned sender
            self.assertGreater(m_dict["financial_keyword_count"], 0.0)
            self.assertEqual(m_dict["auth_pass_sum"], 0.0)

    def test_04_full_benchmark_suite_evaluation(self):
        """Verify the full 5-model comparative benchmark executes and outputs valid schema."""
        suite = BenchmarkMLComparisonSuite(self.corpus_dir)
        report = suite.run_comparison()

        self.assertIn("models_evaluated", report)
        models = report["models_evaluated"]

        # Ensure all 5 target models are present
        self.assertIn("rule_based", models)
        self.assertIn("logistic_regression", models)
        self.assertIn("naive_bayes", models)
        self.assertIn("random_forest", models)
        self.assertIn("hybrid_courtroom", models)

        # Verify Rule-Based achieves 100% on the benchmark corpus
        rule_eval = models["rule_based"]
        self.assertEqual(rule_eval["metrics"]["accuracy"], 100.0)
        self.assertEqual(rule_eval["metrics"]["false_positive_rate"], 0.0)
        self.assertEqual(rule_eval["confusion_matrix"]["tp"], 24)
        self.assertEqual(rule_eval["confusion_matrix"]["fp"], 0)
        self.assertEqual(rule_eval["confusion_matrix"]["tn"], 6)
        self.assertEqual(rule_eval["confusion_matrix"]["fn"], 0)

        # Verify Hybrid Courtroom achieves 100%
        hybrid_eval = models["hybrid_courtroom"]
        self.assertEqual(hybrid_eval["metrics"]["accuracy"], 100.0)
        self.assertEqual(hybrid_eval["metrics"]["precision"], 100.0)
        self.assertEqual(hybrid_eval["metrics"]["recall"], 100.0)
        self.assertEqual(hybrid_eval["metrics"]["false_positive_rate"], 0.0)

        # Verify Latency Profile exists
        for m_key, m_val in models.items():
            lat = m_val["latency_profile"]
            self.assertGreater(lat["mean_ms"], 0.0)
            self.assertGreater(lat["throughput_per_sec"], 0.0)

        # Verify Feature Importance
        fi = report["feature_importance"]
        self.assertIn("logistic_regression_coefficients", fi)
        self.assertIn("random_forest_gini", fi)
        self.assertGreater(len(fi["logistic_regression_coefficients"]), 0)
        self.assertGreater(len(fi["random_forest_gini"]), 0)

        # Verify Adversarial Robustness Scenarios
        adv = report["adversarial_robustness"]
        self.assertEqual(adv["total_adversarial_scenarios"], 3)


if __name__ == "__main__":
    unittest.main()

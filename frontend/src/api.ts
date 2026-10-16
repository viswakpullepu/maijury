// API service layer — communicates with FastAPI backend
import axios from 'axios'

const api = axios.create({ baseURL: '/api', timeout: 30000 })

export interface RiskFactor {
  id: string
  title: string
  severity: 'FATAL_VETO' | 'SEVERE' | 'SUSPICIOUS' | 'CIRCUMSTANTIAL'
  risk_points: number
  status: 'SUSTAINED' | 'DISMISSED'
  statute: string
  exhibit: string
  explanation: string
  dismissal_grounds?: string | null
}

export interface RiskPillar {
  pillar: 'sender' | 'body' | 'urls' | 'attachments'
  name: string
  icon: string
  description: string
  risk_score: number
  contribution_score: number
  contribution_percentage: number
  severity: 'SAFE' | 'CIRCUMSTANTIAL' | 'SUSPICIOUS' | 'SEVERE' | 'FATAL_VETO'
  status: 'PASS' | 'LOW_RISK' | 'WARNING' | 'DANGER' | 'CRITICAL'
  has_fatal_veto: boolean
  sustained_charges_count: number
  dismissed_charges_count: number
  raw_risk_points: number
  factors: RiskFactor[]
  context_highlights: string[]
  summary: string
}

export interface RiskBreakdown {
  pillars: {
    sender: RiskPillar
    body: RiskPillar
    urls: RiskPillar
    attachments: RiskPillar
  }
  total_risk_score: number
  highest_contributor: 'sender' | 'body' | 'urls' | 'attachments' | 'none'
  highest_contributor_name: string
  summary_text: string
  attribution_formula: string
}

export interface SafeViewerGuidance {
  filename: string
  viewer_type: 'DISASSEMBLY_SANDBOX' | 'ISOLATED_WEB_VIEWER' | 'HARDENED_PDF_VIEWER' | 'DISPOSABLE_CONTAINER' | 'STANDARD_SAFE_VIEWER'
  recommended_viewer: string
  prohibited_actions: string[]
  step_by_step_instructions: string[]
  safe_inspection_tools: string[]
}

export interface QuarantineGuidance {
  status: string
  title?: string
  action?: string
  soc_priority?: string
  instructions?: string
  mailbox_actions?: string[]
  gateway_actions?: string[]
  perimeter_containment?: string[]
}

export interface SenderVerificationGuidance {
  verification_required: boolean
  title?: string
  recommended_channel: string
  purported_sender?: string
  sender_domain?: string
  why_needed?: string
  guidance?: string
  protocol_checklist?: string[]
}

export interface PrioritizedChecklistItem {
  step: number
  category: 'QUARANTINE' | 'VERIFY_SENDER' | 'SAFE_VIEWER' | 'INCIDENT_RESPONSE' | 'USER_HYGIENE'
  priority: 'IMMEDIATE' | 'HIGH' | 'MEDIUM' | 'ADVISORY'
  action: string
  detail: string
}

export interface QuickActionItem {
  id: string
  label: string
  recommended: boolean
  action_code: string
  description: string
}

export interface ActionableRecommendations {
  primary_action: 'QUARANTINE_AND_ISOLATE' | 'VERIFY_SENDER_AND_HOLD' | 'DELIVER_SAFELY'
  summary_headline: string
  quarantine: QuarantineGuidance
  verify_sender: SenderVerificationGuidance
  safe_viewer: {
    has_attachments: boolean
    title: string
    overview: string
    email_body_viewer_guidance: string
    attachment_viewers: Array<{
      filename: string
      risk_level: string
      risk_score: number
      classification: string
      guidance: SafeViewerGuidance
    }>
    recommended_tools_matrix?: Record<string, string[]>
  }
  prioritized_checklist: PrioritizedChecklistItem[]
  quick_actions: QuickActionItem[]
}

export interface TrialSummary {
  verdict: string
  risk_score: number
  color: 'RED' | 'GREEN' | 'YELLOW'
  disposition: string
  justification: string
  fatal_vetos: number
  charges_sustained: number
  charges_dismissed: number
  defense_proofs: number
  pipeline_ms: number
  bsa_cert: string
  risk_breakdown?: RiskBreakdown
  actionable_recommendations?: ActionableRecommendations
}

export interface IndictmentCount {
  count_id: string
  category: string
  pillar?: 'sender' | 'body' | 'urls' | 'attachments'
  charge_name: string
  severity: 'FATAL_VETO' | 'SEVERE' | 'SUSPICIOUS' | 'CIRCUMSTANTIAL'
  statute: string
  exhibit: string
  risk_points: number
  explanation: string
}

export interface ExonerationProof {
  proof_id: string
  pillar: string
  title: string
  certificate: string
  legitimacy_points: number
  legal_basis: string
}

export interface TranscriptEntry {
  speaker: 'CHIEF_JUSTICE' | 'PROSECUTOR' | 'DEFENDER'
  utterance: string
}

export interface FullTrialResult {
  meta: {
    filename: string
    sha256: string
    raw_size_bytes: number
    pipeline_ms: number
    timestamp: number
  }
  envelope: {
    from_raw: string
    from_display: string
    from_email: string
    from_domain: string
    to: string
    subject: string
    date: string
    reply_to: string
    return_path: string
  }
  prosecution: {
    team: string
    counts: IndictmentCount[]
    total_counts: number
    fatal_veto_present: boolean
    severe_counts: number
    prosecution_score: number
    opening_statement: string
    closing_statement: string
  }
  defense: {
    team: string
    proofs: ExonerationProof[]
    total_proofs: number
    objections: any[]
    total_objections: number
    is_certified_esp: boolean
    certified_esp_provider: string
    exoneration_score: number
    opening_statement: string
    closing_statement: string
  }
  verdict: {
    verdict: string
    verdict_color: 'RED' | 'GREEN' | 'YELLOW'
    final_risk_score: number
    defense_exoneration_score: number
    disposition: string
    summary_justification: string
    stats: {
      total_prosecution_counts: number
      sustained_charges: number
      dismissed_charges: number
      defense_proofs_entered: number
      fatal_vetos: number
      trial_duration_ms: number
    }
    surviving_counts: IndictmentCount[]
    dismissed_counts: any[]
    trial_transcript: TranscriptEntry[]
    legal_metadata: {
      statute_compliance: string
      electronic_record_hash: string
      adjudication_certificate_token: string
      timestamp_epoch: number
    }
    risk_breakdown?: RiskBreakdown
    actionable_recommendations?: ActionableRecommendations
  }
  summary: TrialSummary
  attachments_analysis?: AttachmentAnalysis[]
  actionable_recommendations?: ActionableRecommendations
}

export interface DetectedFileType {
  mime_type: string
  declared_mime: string
  declared_extension: string
  magic_hex: string
  magic_ascii: string
  format_name: string
  category: 'EXECUTABLE' | 'DOCUMENT' | 'ARCHIVE' | 'IMAGE' | 'SCRIPT' | 'DATA'
  mime_mismatch: boolean
  extension_mismatch: boolean
  size_bytes: number
  size_formatted: string
  description: string
}

export interface SuspiciousFeature {
  id: string
  name: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  category: string
  description: string
  evidence: string
  mitre_attack: string
  risk_contribution: number
}

export interface RemediationChecklistItem {
  task: string
  status: string
  action: string
}

export interface RecommendedAction {
  primary_action: 'BLOCK_AND_QUARANTINE' | 'HOLD_FOR_ADMIN_TRIAGE' | 'PERMIT_DELIVERY'
  action_label: string
  urgency: string
  summary: string
  end_user_guidance: string
  soc_analyst_playbook: string[]
  remediation_checklist: RemediationChecklistItem[]
  safe_viewer_profile?: any
  quarantine_profile?: any
  sender_verification_profile?: any
}

export interface AttachmentReportCard {
  card_id: string
  filename: string
  sha256: string
  size_bytes: number
  size_formatted: string
  detected_file_type: DetectedFileType
  suspicious_features: SuspiciousFeature[]
  suspicious_features_count: number
  benign_features: string[]
  benign_features_count: number
  risk_level: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS'
  risk_score: number
  severity_tier: 'CRITICAL_THREAT' | 'ELEVATED_RISK' | 'NEGLIGIBLE_RISK'
  classification: string
  recommended_action: RecommendedAction
  mitre_techniques: string[]
  triggered_rules: string[]
  zero_execution_guarantee: string
  legal_evidence_certificate: {
    statute: string
    certificate_id: string
    admissibility: string
  }
}

export interface AttachmentAnalysis {
  filename: string
  extension: string
  size_bytes: number
  sha256: string
  declared_type: string
  detected_type: string
  magic_hex: string
  magic_ascii: string
  risk_level: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS'
  risk_score: number
  classification: string
  evidence: string[]
  reasons: string
  is_safe: boolean
  zero_execution_guarantee: string
  mitre_techniques?: string[]
  detected_file_type?: DetectedFileType
  suspicious_features?: SuspiciousFeature[]
  benign_features?: string[]
  recommended_action?: RecommendedAction
  report_card?: AttachmentReportCard
  safe_viewer_guidance?: any
  quarantine_guidance?: any
  sender_verification_guidance?: any
  recommendations?: any[]
}

export const analyzeFile = async (file: File): Promise<FullTrialResult> => {
  const form = new FormData()
  form.append('file', file)
  const { data } = await api.post<FullTrialResult>('/analyze', form)
  return data
}

export const analyzeText = async (rawEmail: string): Promise<FullTrialResult> => {
  const { data } = await api.post<FullTrialResult>('/analyze/text', { raw_email: rawEmail })
  return data
}

export const analyzeAttachment = async (file: File): Promise<AttachmentAnalysis> => {
  const form = new FormData()
  form.append('file', file)
  const { data } = await api.post<AttachmentAnalysis>('/analyze/attachment', form)
  return data
}

export const runBenchmark = async () => {
  const { data } = await api.get('/benchmark')
  return data
}

export const runMission02Benchmark = async () => {
  const { data } = await api.get('/mission-02/benchmark')
  return data
}

export const checkHealth = async () => {
  const { data } = await api.get('/health')
  return data
}

// ─── USER FEEDBACK & EVALUATION API (MISSION 02 REQ 4) ──────────────────────

export type FeedbackType =
  | 'FALSE_POSITIVE'
  | 'FALSE_NEGATIVE'
  | 'INCORRECT_RISK_SCORE'
  | 'ATTACHMENT_MISCLASSIFICATION'
  | 'OTHER'

export type FeedbackStatus = 'PENDING_REVIEW' | 'VERIFIED' | 'RESOLVED' | 'REJECTED'

export interface FeedbackSubmission {
  email_sha256: string
  email_subject: string
  email_from: string
  original_verdict: string
  original_risk_score: number
  reported_classification: string
  feedback_type: FeedbackType
  disputed_indicators: string[]
  analyst_notes: string
  reporter_role?: string
  suggested_risk_score?: number
}

export interface FeedbackRecord {
  feedback_id: string
  timestamp: number
  timestamp_iso: string
  submission: FeedbackSubmission
  status: FeedbackStatus
  evidence_token: string
  resolved_at?: number
  resolution_notes?: string
}

export interface ConfusionMatrix {
  true_positives: number
  true_negatives: number
  false_positives: number
  false_negatives: number
  total_samples: number
  accuracy: number
  precision: number
  recall: number
  f1_score: number
  false_positive_rate: number
  false_negative_rate: number
}

export interface CalibrationInsight {
  insight_id: string
  rule_target: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO'
  title: string
  description: string
  recommended_action: string
  affected_count: number
}

export interface EvaluationReport {
  generated_at: string
  total_feedback_reports: number
  pending_review_count: number
  verified_count: number
  feedback_type_counts: Record<string, number>
  confusion_matrix: ConfusionMatrix
  top_disputed_indicators: { indicator: string; dispute_count: number }[]
  calibration_insights: CalibrationInsight[]
}

export const submitFeedback = async (
  payload: FeedbackSubmission
): Promise<{ status: string; message: string; record: FeedbackRecord }> => {
  const { data } = await api.post('/feedback', payload)
  return data
}

export const getFeedbackList = async (params?: {
  feedback_type?: string
  status?: string
  search?: string
  limit?: number
}): Promise<{ total: number; records: FeedbackRecord[] }> => {
  const { data } = await api.get('/feedback', { params })
  return data
}

export const getFeedbackEvaluation = async (): Promise<EvaluationReport> => {
  const { data } = await api.get<EvaluationReport>('/feedback/evaluation')
  return data
}

export const exportFeedbackCsv = async (): Promise<string> => {
  const { data } = await api.get('/feedback/export', {
    params: { format: 'csv' },
    responseType: 'text',
  })
  return data
}

export const seedFeedbackSamples = async (): Promise<{ status: string; message: string }> => {
  const { data } = await api.post('/feedback/seed-samples')
  return data
}

export const updateFeedbackStatus = async (
  feedbackId: string,
  status: FeedbackStatus,
  notes?: string
): Promise<{ status: string; record: FeedbackRecord }> => {
  const { data } = await api.patch(`/feedback/${feedbackId}/status`, { status, notes })
  return data
}

export const deleteFeedbackRecord = async (
  feedbackId: string
): Promise<{ status: string; feedback_id: string }> => {
  const { data } = await api.delete(`/feedback/${feedbackId}`)
  return data
}

export const runFeedbackCalibration = async (): Promise<{
  calibration_status: string
  total_feedback_applied: number
  insights: CalibrationInsight[]
  confusion_matrix: ConfusionMatrix
}> => {
  const { data } = await api.post('/feedback/calibrate')
  return data
}

// ── ML VS RULE-BASED COMPARISON BENCHMARK (MISSION 02 REQ 5) ──────────────────

export interface ModelMetrics {
  accuracy: number
  precision: number
  recall: number
  specificity: number
  false_positive_rate: number
  false_negative_rate: number
  f1_score: number
  mcc: number
  roc_auc: number
  pr_auc: number
}

export interface ModelConfusionMatrix {
  tp: number
  fp: number
  tn: number
  fn: number
  matrix_2x2: number[][]
}

export interface LatencyProfile {
  mean_ms: number
  p50_ms: number
  p95_ms: number
  p99_ms: number
  throughput_per_sec: number
}

export interface ModelEvaluationResult {
  model_name: string
  confusion_matrix: ModelConfusionMatrix
  metrics: ModelMetrics
  latency_profile: LatencyProfile
  roc_curve: { fpr: number; tpr: number }[]
  sample_counts: {
    total: number
    ground_truth_malicious: number
    ground_truth_benign: number
  }
}

export interface FeatureImportanceItem {
  feature: string
  weight?: number
  importance?: number
  direction?: string
}

export interface AdversarialScenario {
  scenario_name: string
  attack_technique: string
  ml_vulnerability: string
  courtroom_defense: string
  verdict_outcome: string
}

export interface MLComparisonReport {
  title: string
  total_corpus_samples: number
  ground_truth_split: {
    malicious_samples: number
    benign_samples: number
  }
  models_evaluated: {
    rule_based: ModelEvaluationResult
    logistic_regression: ModelEvaluationResult
    naive_bayes: ModelEvaluationResult
    random_forest: ModelEvaluationResult
    hybrid_courtroom: ModelEvaluationResult
  }
  feature_importance: {
    logistic_regression_coefficients: FeatureImportanceItem[]
    random_forest_gini: FeatureImportanceItem[]
  }
  adversarial_robustness: {
    total_adversarial_scenarios: number
    scenarios: AdversarialScenario[]
  }
  comparative_summary: {
    dimension: string
    rule_based: string
    ml_based: string
    hybrid_courtroom: string
  }[]
  benchmark_latency_ms: number
}

export const getMLComparisonBenchmark = async (): Promise<MLComparisonReport> => {
  const { data } = await api.get<MLComparisonReport>('/benchmark/ml-comparison')
  return data
}



// API service layer — communicates with FastAPI backend
import axios from 'axios'

const api = axios.create({ baseURL: '/api', timeout: 30000 })

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
}

export interface IndictmentCount {
  count_id: string
  category: string
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
  }
  summary: TrialSummary
  attachments_analysis?: AttachmentAnalysis[]
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

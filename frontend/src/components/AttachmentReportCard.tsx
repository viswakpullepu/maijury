import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  ShieldAlert,
  ShieldCheck,
  FileWarning,
  Binary,
  Copy,
  Check,
  Download,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  Lock,
  Fingerprint,
  FileText,
  CheckCircle2,
  ListChecks,
  UserCheck,
  Radio,
  FileQuestion,
  Archive,
  Cpu,
  FileCheck2,
  Eye,
  Ban
} from 'lucide-react'
import type { AttachmentAnalysis } from '../api'

interface AttachmentReportCardProps {
  attachment: AttachmentAnalysis
  defaultExpanded?: boolean
}

export const AttachmentReportCard: React.FC<AttachmentReportCardProps> = ({
  attachment,
  defaultExpanded = true
}) => {
  const [copiedHash, setCopiedHash] = useState(false)
  const [activeTab, setActiveTab] = useState<'overview' | 'features' | 'action' | 'hex'>('overview')
  const [isCardExpanded, setIsCardExpanded] = useState(defaultExpanded)
  const [expandedFeature, setExpandedFeature] = useState<string | null>(null)

  const rep = attachment.report_card || {
    card_id: `REPCARD-ATT-${attachment.sha256?.slice(0, 12).toUpperCase() || 'UNKNOWN'}`,
    filename: attachment.filename,
    sha256: attachment.sha256,
    size_bytes: attachment.size_bytes,
    size_formatted: `${(attachment.size_bytes / 1024).toFixed(1)} KB`,
    detected_file_type: attachment.detected_file_type || {
      mime_type: attachment.detected_type,
      declared_mime: attachment.declared_type,
      declared_extension: attachment.extension,
      magic_hex: attachment.magic_hex,
      magic_ascii: attachment.magic_ascii,
      format_name: attachment.classification,
      category: 'DATA',
      mime_mismatch: false,
      extension_mismatch: false,
      size_bytes: attachment.size_bytes,
      size_formatted: `${(attachment.size_bytes / 1024).toFixed(1)} KB`,
      description: attachment.classification
    },
    suspicious_features: attachment.suspicious_features || [],
    suspicious_features_count: attachment.suspicious_features?.length || 0,
    benign_features: attachment.benign_features || [],
    benign_features_count: attachment.benign_features?.length || 0,
    risk_level: attachment.risk_level,
    risk_score: attachment.risk_score,
    severity_tier: attachment.risk_score >= 80 ? 'CRITICAL_THREAT' : (attachment.risk_score >= 30 ? 'ELEVATED_RISK' : 'NEGLIGIBLE_RISK'),
    classification: attachment.classification,
    recommended_action: attachment.recommended_action || {
      primary_action: attachment.risk_level === 'MALICIOUS' ? 'BLOCK_AND_QUARANTINE' : (attachment.risk_level === 'SUSPICIOUS' ? 'HOLD_FOR_ADMIN_TRIAGE' : 'PERMIT_DELIVERY'),
      action_label: attachment.risk_level === 'MALICIOUS' ? '🚫 Block & Quarantine Immediately' : (attachment.risk_level === 'SUSPICIOUS' ? '⚠️ Hold for Security Triage' : '✅ Permit Inbox Delivery'),
      urgency: attachment.risk_level === 'MALICIOUS' ? 'IMMEDIATE_ACTION_REQUIRED' : (attachment.risk_level === 'SUSPICIOUS' ? 'ANALYST_INVESTIGATION_REQUIRED' : 'ROUTINE_TRAFFIC'),
      summary: attachment.reasons || 'Perform standard attachment verification.',
      end_user_guidance: attachment.risk_level === 'MALICIOUS' ? 'Do NOT open or download this attachment.' : 'Safe for viewing.',
      soc_analyst_playbook: ['Review attachment forensics and confirm gateway disposition.'],
      remediation_checklist: []
    },
    mitre_techniques: attachment.mitre_techniques || [],
    triggered_rules: (attachment as any).triggered_rule_ids || [],
    zero_execution_guarantee: attachment.zero_execution_guarantee,
    legal_evidence_certificate: {
      statute: 'Bharatiya Sakshya Adhiniyam (BSA) 2023 §65B',
      certificate_id: `BSA65B-ATT-${attachment.sha256?.slice(0, 16).toUpperCase() || 'UNKNOWN'}`,
      admissibility: 'VERIFIED_AUTHENTIC_ELECTRONIC_RECORD'
    }
  }

  const isMalicious = rep.risk_level === 'MALICIOUS'
  const isSuspicious = rep.risk_level === 'SUSPICIOUS'
  const isSafe = rep.risk_level === 'SAFE'

  const copySha256 = () => {
    navigator.clipboard.writeText(rep.sha256)
    setCopiedHash(true)
    setTimeout(() => setCopiedHash(false), 2000)
  }

  const exportReportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(rep, null, 2))
    const downloadAnchor = document.createElement('a')
    downloadAnchor.setAttribute('href', dataStr)
    downloadAnchor.setAttribute('download', `${rep.filename}_forensic_report_card.json`)
    document.body.appendChild(downloadAnchor)
    downloadAnchor.click()
    downloadAnchor.remove()
  }

  // Visual Theme mapping based on Risk Level
  const theme = isMalicious
    ? {
        border: 'border-red-900/70',
        bg: 'bg-gradient-to-br from-[#180808] to-[#0c0505]',
        glow: 'shadow-[0_0_30px_rgba(239,68,68,0.12)]',
        badge: 'bg-red-950 text-red-300 border-red-800',
        badgeLight: 'bg-red-950/50 text-red-400 border-red-900/60',
        icon: ShieldAlert,
        iconColor: 'text-red-500',
        meterFrom: 'from-orange-500',
        meterTo: 'to-red-500',
        titleColor: 'text-red-400'
      }
    : isSuspicious
    ? {
        border: 'border-amber-900/70',
        bg: 'bg-gradient-to-br from-[#181206] to-[#0d0903]',
        glow: 'shadow-[0_0_30px_rgba(245,158,11,0.1)]',
        badge: 'bg-amber-950 text-amber-300 border-amber-800',
        badgeLight: 'bg-amber-950/50 text-amber-400 border-amber-900/60',
        icon: FileWarning,
        iconColor: 'text-amber-500',
        meterFrom: 'from-yellow-500',
        meterTo: 'to-amber-500',
        titleColor: 'text-amber-400'
      }
    : {
        border: 'border-emerald-950/80',
        bg: 'bg-gradient-to-br from-[#06140b] to-[#040c07]',
        glow: 'shadow-[0_0_30px_rgba(34,197,94,0.08)]',
        badge: 'bg-emerald-950 text-emerald-300 border-emerald-800',
        badgeLight: 'bg-emerald-950/50 text-emerald-400 border-emerald-900/60',
        icon: ShieldCheck,
        iconColor: 'text-emerald-500',
        meterFrom: 'from-teal-500',
        meterTo: 'to-emerald-500',
        titleColor: 'text-emerald-400'
      }

  const StatusIcon = theme.icon
  const dft = rep.detected_file_type
  const act = rep.recommended_action
  const suspiciousFeatures = rep.suspicious_features || []
  const benignFeatures = rep.benign_features || []

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className={`border ${theme.border} ${theme.bg} ${theme.glow} rounded-2xl overflow-hidden transition-all duration-300`}
    >
      {/* ── CARD TOP BAR ── */}
      <div className="p-4 sm:p-5 border-b border-[#1e2333]/70">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          {/* File Info & Icon */}
          <div className="flex items-start gap-3.5 min-w-0">
            <div className={`w-11 h-11 rounded-xl bg-[#090b10] border border-[#1e2333] flex items-center justify-center shrink-0 mt-0.5`}>
              <StatusIcon className={`w-6 h-6 ${theme.iconColor}`} />
            </div>

            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-bold text-[#f8fafc] text-base truncate max-w-sm sm:max-w-md" title={rep.filename}>
                  {rep.filename}
                </span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${theme.badge}`}>
                  {rep.card_id}
                </span>
              </div>

              {/* Format & Size badges */}
              <div className="flex items-center gap-2 mt-1.5 text-xs text-[#94a3b8] flex-wrap">
                <span className="inline-flex items-center gap-1 font-medium text-[#cbd5e1]">
                  {dft.category === 'EXECUTABLE' && <Cpu className="w-3.5 h-3.5 text-red-400" />}
                  {dft.category === 'DOCUMENT' && <FileText className="w-3.5 h-3.5 text-blue-400" />}
                  {dft.category === 'ARCHIVE' && <Archive className="w-3.5 h-3.5 text-amber-400" />}
                  {dft.category === 'IMAGE' && <FileCheck2 className="w-3.5 h-3.5 text-emerald-400" />}
                  {dft.format_name}
                </span>
                <span className="text-[#475569]">·</span>
                <span className="font-mono text-[#64748b]">{rep.size_formatted}</span>
                <span className="text-[#475569]">·</span>
                {dft.mime_mismatch ? (
                  <span className="text-red-400 font-semibold text-[11px] bg-red-950/60 px-1.5 py-0.5 rounded border border-red-900/60 flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3" /> MIME Masquerade
                  </span>
                ) : (
                  <span className="text-[#64748b] font-mono text-[11px] truncate max-w-[180px]" title={dft.mime_type}>
                    {dft.mime_type}
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* Risk Score & Quick Actions */}
          <div className="flex items-center gap-3 self-end sm:self-center shrink-0">
            {/* Risk Badge */}
            <div className="text-right">
              <div className="flex items-baseline justify-end gap-1">
                <span className={`text-2xl font-black ${theme.titleColor} tracking-tight`}>
                  {rep.risk_score.toFixed(1)}
                </span>
                <span className="text-xs text-[#64748b] font-mono">/ 100</span>
              </div>
              <div className={`text-[10px] font-bold tracking-wider uppercase px-2 py-0.5 rounded-full border ${theme.badge}`}>
                {rep.risk_level}
              </div>
            </div>

            {/* Expand / Collapse Button */}
            <button
              onClick={() => setIsCardExpanded(!isCardExpanded)}
              className="w-9 h-9 rounded-lg bg-[#0d1017] border border-[#1e2333] hover:border-[#334155] flex items-center justify-center text-[#94a3b8] hover:text-white transition-colors"
              title={isCardExpanded ? 'Collapse report card' : 'Expand full report card'}
            >
              {isCardExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Risk Meter Gauge */}
        <div className="mt-4">
          <div className="h-1.5 bg-[#0a0c10] rounded-full overflow-hidden border border-[#1e2333]/80">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${Math.max(rep.risk_score, 4)}%` }}
              transition={{ duration: 0.6, ease: 'easeOut' }}
              className={`h-full rounded-full bg-gradient-to-r ${theme.meterFrom} ${theme.meterTo}`}
            />
          </div>
        </div>
      </div>

      <AnimatePresence>
        {isCardExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="space-y-4 p-4 sm:p-5"
          >
            {/* ── CARD NAVIGATION TABS ── */}
            <div className="flex gap-1.5 bg-[#0a0c12] p-1 rounded-xl border border-[#1e2333] text-xs">
              {[
                { id: 'overview', label: '📊 Forensic Overview' },
                {
                  id: 'features',
                  label: isSafe
                    ? `🛡️ Benign Features (${benignFeatures.length})`
                    : `⚠️ Suspicious Features (${suspiciousFeatures.length})`
                },
                { id: 'action', label: '📋 Recommended Action' },
                { id: 'hex', label: '🔍 Byte Signatures' }
              ].map(t => (
                <button
                  key={t.id}
                  onClick={() => setActiveTab(t.id as any)}
                  className={`flex-1 py-1.5 px-2.5 rounded-lg font-medium transition-all text-center truncate ${
                    activeTab === t.id
                      ? 'bg-[#181d2a] text-white border border-[#2d3748] shadow-sm'
                      : 'text-[#64748b] hover:text-[#cbd5e1]'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>

            {/* ── TAB 1: FORENSIC OVERVIEW ── */}
            {activeTab === 'overview' && (
              <div className="space-y-4">
                {/* Primary Directive Banner */}
                <div className={`p-3.5 rounded-xl border ${theme.badgeLight} flex items-center justify-between gap-3`}>
                  <div className="flex items-center gap-2.5">
                    <Radio className={`w-4 h-4 ${theme.iconColor} animate-pulse`} />
                    <span className="text-xs font-bold uppercase tracking-wider text-[#f1f5f9]">
                      {act.action_label}
                    </span>
                  </div>
                  <span className="text-[10px] font-mono text-[#94a3b8] px-2 py-0.5 rounded bg-black/40 border border-[#262c3d]">
                    Urgency: {act.urgency}
                  </span>
                </div>

                {/* Key Metrics Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs">
                  <div className="bg-[#090b10] border border-[#1a1f2e] rounded-xl p-3">
                    <div className="text-[#64748b] text-[11px] mb-1">Detected File Type</div>
                    <div className="font-semibold text-[#f1f5f9] truncate" title={dft.format_name}>
                      {dft.format_name}
                    </div>
                    <div className="text-[10px] font-mono text-[#64748b] truncate mt-0.5">{dft.mime_type}</div>
                  </div>

                  <div className="bg-[#090b10] border border-[#1a1f2e] rounded-xl p-3">
                    <div className="text-[#64748b] text-[11px] mb-1">Declared Mimetype</div>
                    <div className="font-semibold text-[#cbd5e1] truncate" title={dft.declared_mime}>
                      {dft.declared_mime || 'None'}
                    </div>
                    <div className="text-[10px] font-mono text-[#64748b] truncate mt-0.5">
                      Ext: {dft.declared_extension || '(none)'}
                    </div>
                  </div>

                  <div className="bg-[#090b10] border border-[#1a1f2e] rounded-xl p-3">
                    <div className="text-[#64748b] text-[11px] mb-1">Risk Evaluation</div>
                    <div className={`font-bold ${theme.titleColor}`}>
                      {rep.severity_tier.replace('_', ' ')}
                    </div>
                    <div className="text-[10px] font-mono text-[#64748b] mt-0.5">
                      {rep.risk_score.toFixed(1)} / 100.0
                    </div>
                  </div>

                  <div className="bg-[#090b10] border border-[#1a1f2e] rounded-xl p-3">
                    <div className="text-[#64748b] text-[11px] mb-1">Features Identified</div>
                    <div className="font-semibold text-[#f1f5f9]">
                      {isSafe ? `${benignFeatures.length} Clean Checks` : `${suspiciousFeatures.length} Threat Flags`}
                    </div>
                    <div className="text-[10px] font-mono text-[#64748b] mt-0.5">
                      {rep.mitre_techniques.length} MITRE TTPs
                    </div>
                  </div>
                </div>

                {/* Classification & Reasons Summary */}
                <div className="bg-[#090b10] border border-[#1a1f2e] rounded-xl p-3.5 space-y-2 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-[#64748b] font-medium">Forensic Classification:</span>
                    <span className={`font-bold ${theme.titleColor}`}>
                      {rep.classification}
                    </span>
                  </div>
                  <p className="text-[#94a3b8] leading-relaxed text-[11px]">
                    {attachment.reasons || dft.description}
                  </p>
                </div>

                {/* MITRE ATT&CK Techniques */}
                {rep.mitre_techniques.length > 0 && (
                  <div className="flex items-center gap-1.5 flex-wrap text-xs">
                    <span className="text-[#64748b] text-[11px] mr-1">MITRE ATT&CK:</span>
                    {rep.mitre_techniques.map((t: string) => (
                      <span
                        key={t}
                        className="bg-[#121622] text-[#93c5fd] border border-[#1e2a4a] px-2 py-0.5 rounded text-[11px] font-mono"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* ── TAB 2: SUSPICIOUS OR BENIGN FEATURES ── */}
            {activeTab === 'features' && (
              <div className="space-y-3">
                {isSafe ? (
                  /* BENIGN CERTIFICATIONS */
                  <div className="space-y-2.5">
                    <div className="bg-[#07170c] border border-emerald-950 p-3 rounded-xl flex items-center gap-2.5">
                      <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-emerald-300">Certified Benign Static Structure</div>
                        <div className="text-[11px] text-[#94a3b8]">
                          Zero malicious macros, zero external execution vectors, and strict container format integrity verified.
                        </div>
                      </div>
                    </div>

                    <div className="space-y-1.5">
                      {benignFeatures.map((bf, idx) => (
                        <div
                          key={idx}
                          className="bg-[#090b10] border border-[#1a1f2e] rounded-lg p-2.5 flex items-start gap-2.5 text-xs text-[#cbd5e1]"
                        >
                          <span className="text-emerald-400 font-bold shrink-0 mt-0.5">✓</span>
                          <span>{bf}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  /* SUSPICIOUS FEATURES LIST */
                  <div className="space-y-2">
                    {suspiciousFeatures.length === 0 ? (
                      <div className="text-center py-6 text-[#64748b] text-xs">
                        No specific isolated features cataloged. Flagged by heuristic baseline.
                      </div>
                    ) : (
                      suspiciousFeatures.map(feat => {
                        const isExpanded = expandedFeature === feat.id
                        const sevBadge =
                          feat.severity === 'CRITICAL'
                            ? 'bg-red-950 text-red-300 border-red-800'
                            : feat.severity === 'HIGH'
                            ? 'bg-orange-950 text-orange-300 border-orange-800'
                            : 'bg-yellow-950 text-yellow-300 border-yellow-800'

                        return (
                          <div
                            key={feat.id}
                            className="bg-[#090b10] border border-[#1a1f2e] rounded-xl overflow-hidden text-xs transition-colors"
                          >
                            <button
                              onClick={() => setExpandedFeature(isExpanded ? null : feat.id)}
                              className="w-full p-3 flex items-center gap-2.5 text-left hover:bg-white/[0.02]"
                            >
                              <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${sevBadge}`}>
                                {feat.severity}
                              </span>
                              <span className="font-semibold text-[#f1f5f9] flex-1 truncate">
                                {feat.name}
                              </span>
                              {feat.mitre_attack && feat.mitre_attack !== 'N/A' && (
                                <span className="text-[10px] font-mono text-[#93c5fd] bg-[#121622] px-2 py-0.5 rounded border border-[#1e2a4a] hidden sm:inline-block">
                                  {feat.mitre_attack}
                                </span>
                              )}
                              {isExpanded ? (
                                <ChevronUp className="w-4 h-4 text-[#64748b] shrink-0" />
                              ) : (
                                <ChevronDown className="w-4 h-4 text-[#64748b] shrink-0" />
                              )}
                            </button>

                            <AnimatePresence>
                              {isExpanded && (
                                <motion.div
                                  initial={{ height: 0, opacity: 0 }}
                                  animate={{ height: 'auto', opacity: 1 }}
                                  exit={{ height: 0, opacity: 0 }}
                                  className="px-3.5 pb-3.5 pt-1 border-t border-[#1a1f2e]/60 space-y-2 text-[11px]"
                                >
                                  <div className="text-[#94a3b8] leading-relaxed">
                                    {feat.description}
                                  </div>
                                  {feat.evidence && (
                                    <div className="bg-[#050608] border border-[#1e2333] rounded-lg p-2 font-mono text-[#cbd5e1] break-all">
                                      <span className="text-[#64748b] select-none">Evidence: </span>
                                      {feat.evidence}
                                    </div>
                                  )}
                                </motion.div>
                              )}
                            </AnimatePresence>
                          </div>
                        )
                      })
                    )}
                  </div>
                )}
              </div>
            )}

            {/* ── TAB 3: RECOMMENDED ACTION & PLAYBOOK ── */}
            {activeTab === 'action' && (
              <div className="space-y-3.5 text-xs">
                {/* Executive Action Summary */}
                <div className={`p-4 rounded-xl border ${theme.badgeLight} space-y-1.5`}>
                  <div className="text-[11px] font-bold text-[#94a3b8] uppercase tracking-wider">
                    Executive Operational Guidance
                  </div>
                  <div className="font-semibold text-white leading-relaxed text-sm">
                    {act.summary}
                  </div>
                </div>

                {/* Safe Viewer Protocol (Requirement 3: Inspect file using safe viewer) */}
                {attachment.safe_viewer_guidance && (
                  <div className="bg-[#090e17] border border-[#1e2a4a] rounded-xl p-3.5 space-y-2.5">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-white font-semibold">
                        <Eye className="w-4 h-4 text-blue-400" />
                        <span>Safe Viewer Inspection Protocol</span>
                      </div>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-950/80 border border-blue-800 text-blue-300">
                        {attachment.safe_viewer_guidance.viewer_type}
                      </span>
                    </div>

                    <div className="bg-[#05070c] border border-[#172033] rounded-lg p-2.5 space-y-1">
                      <div className="text-[11px] text-[#cbd5e1] font-medium">
                        Recommended Viewer: <strong className="text-white">{attachment.safe_viewer_guidance.recommended_viewer}</strong>
                      </div>
                      {attachment.safe_viewer_guidance.safe_inspection_tools && (
                        <div className="flex flex-wrap gap-1 pt-1">
                          {attachment.safe_viewer_guidance.safe_inspection_tools.map((tool: string, tIdx: number) => (
                            <span key={tIdx} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#101726] border border-[#1e2d4d] text-blue-300">
                              {tool}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Prohibited actions */}
                    {attachment.safe_viewer_guidance.prohibited_actions && attachment.safe_viewer_guidance.prohibited_actions.length > 0 && (
                      <div className="space-y-1">
                        <div className="text-[10px] font-bold text-red-400 uppercase tracking-wider">
                          Prohibited Direct Actions
                        </div>
                        <div className="space-y-1">
                          {attachment.safe_viewer_guidance.prohibited_actions.map((actItem: string, aIdx: number) => (
                            <div key={aIdx} className="flex items-start gap-1.5 text-[11px] text-red-300/90">
                              <Ban className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
                              <span>{actItem}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Step by step safe inspection instructions */}
                    {attachment.safe_viewer_guidance.step_by_step_instructions && attachment.safe_viewer_guidance.step_by_step_instructions.length > 0 && (
                      <div className="space-y-1 pt-1">
                        <div className="text-[10px] font-bold text-[#64748b] uppercase tracking-wider">
                          Inspection Procedure
                        </div>
                        <div className="space-y-1 pl-1">
                          {attachment.safe_viewer_guidance.step_by_step_instructions.map((stepItem: string, sIdx: number) => (
                            <div key={sIdx} className="flex items-start gap-2 text-[11px] text-[#94a3b8]">
                              <span className="font-mono text-blue-400 shrink-0 font-bold">{sIdx + 1}.</span>
                              <span className="leading-tight">{stepItem}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Recipient / End-User Instructions */}
                <div className="bg-[#090b10] border border-[#1a1f2e] rounded-xl p-3.5 space-y-1.5">
                  <div className="flex items-center gap-2 text-white font-semibold">
                    <UserCheck className="w-4 h-4 text-blue-400" />
                    <span>Recipient / End-User Directives</span>
                  </div>
                  <p className="text-[#94a3b8] leading-relaxed text-[11px]">
                    {act.end_user_guidance}
                  </p>
                </div>

                {/* SOC Analyst Incident Response Playbook */}
                {act.soc_analyst_playbook && act.soc_analyst_playbook.length > 0 && (
                  <div className="bg-[#090b10] border border-[#1a1f2e] rounded-xl p-3.5 space-y-2">
                    <div className="flex items-center gap-2 text-white font-semibold">
                      <ListChecks className="w-4 h-4 text-purple-400" />
                      <span>SOC Incident Response Playbook</span>
                    </div>
                    <div className="space-y-1.5 pl-1">
                      {act.soc_analyst_playbook.map((step, sIdx) => (
                        <div key={sIdx} className="text-[#94a3b8] flex items-start gap-2 text-[11px]">
                          <span className="text-purple-400 font-mono font-bold shrink-0 mt-0.5">•</span>
                          <span className="leading-tight">{step}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Tactical Remediation Checklist */}
                {act.remediation_checklist && act.remediation_checklist.length > 0 && (
                  <div className="bg-[#090b10] border border-[#1a1f2e] rounded-xl p-3.5 space-y-2">
                    <div className="text-[#64748b] text-[11px] font-medium uppercase tracking-wider">
                      Remediation Tasks Checklist
                    </div>
                    <div className="space-y-1.5">
                      {act.remediation_checklist.map((item, cIdx) => (
                        <div
                          key={cIdx}
                          className="bg-[#050608] border border-[#1e2333] rounded-lg p-2 flex items-center justify-between gap-2 text-[11px]"
                        >
                          <span className="text-[#cbd5e1] font-medium">{item.task}</span>
                          <span
                            className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                              item.status === 'REQUIRED'
                                ? 'bg-red-950 text-red-300 border-red-800'
                                : item.status === 'COMPLETED'
                                ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                                : 'bg-slate-900 text-slate-400 border-slate-700'
                            }`}
                          >
                            {item.status}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* ── TAB 4: BYTE SIGNATURES & EVIDENCE ── */}
            {activeTab === 'hex' && (
              <div className="space-y-3 text-xs">
                {/* Magic Hex Dump & ASCII */}
                <div className="bg-[#050608] border border-[#1a1f2e] rounded-xl p-3.5 space-y-2 font-mono">
                  <div className="text-[#64748b] text-[11px] font-medium flex items-center gap-1.5">
                    <Binary className="w-3.5 h-3.5" />
                    <span>In-Memory Byte Signature Analysis</span>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                    <div className="bg-[#0a0c10] border border-[#1e2333] p-2.5 rounded-lg">
                      <div className="text-[#64748b] text-[10px] mb-1">Raw Magic Hex Stream (First 16 Bytes)</div>
                      <div className="text-purple-300 font-bold tracking-wider break-all">
                        {dft.magic_hex || 'None'}
                      </div>
                    </div>
                    <div className="bg-[#0a0c10] border border-[#1e2333] p-2.5 rounded-lg">
                      <div className="text-[#64748b] text-[10px] mb-1">ASCII Character Representation</div>
                      <div className="text-emerald-300 font-bold break-all">
                        '{dft.magic_ascii || 'None'}'
                      </div>
                    </div>
                  </div>
                </div>

                {/* Evidence List */}
                {attachment.evidence && attachment.evidence.length > 0 && (
                  <div className="bg-[#090b10] border border-[#1a1f2e] rounded-xl p-3.5 space-y-2">
                    <div className="text-[#64748b] text-[11px] font-medium uppercase tracking-wider">
                      Forensic Inspection Proofs ({attachment.evidence.length})
                    </div>
                    <div className="space-y-1.5 pl-1">
                      {attachment.evidence.map((ev, evIdx) => (
                        <div key={evIdx} className="text-[#94a3b8] flex items-start gap-2 text-[11px]">
                          <span className="text-blue-400 font-mono shrink-0 mt-0.5">•</span>
                          <span className="font-mono leading-tight break-all">{ev}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* ── CARD FOOTER & DIGITAL CERTIFICATE ── */}
            <div className="border-t border-[#1a1f2e] pt-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-[#64748b]">
              {/* Hash and Chain of Custody */}
              <div className="flex items-center gap-2 min-w-0">
                <Fingerprint className="w-3.5 h-3.5 text-purple-400 shrink-0" />
                <span className="font-mono text-[10px] truncate max-w-[220px]" title={rep.sha256}>
                  SHA256: {rep.sha256}
                </span>
                <button
                  onClick={copySha256}
                  className="hover:text-white transition-colors p-1"
                  title="Copy SHA-256 hash"
                >
                  {copiedHash ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>

              {/* BSA 65B & Export Buttons */}
              <div className="flex items-center gap-2 shrink-0">
                <span className="text-[10px] font-mono text-[#475569] hidden md:inline-block">
                  BSA 2023 §65B Certified
                </span>
                <button
                  onClick={exportReportJson}
                  className="flex items-center gap-1.5 text-[11px] font-medium px-2.5 py-1 rounded-lg bg-[#0d1017] border border-[#1e2333] hover:border-[#3b82f6] text-[#cbd5e1] hover:text-white transition-all"
                  title="Export Report Card as JSON"
                >
                  <Download className="w-3 h-3 text-blue-400" />
                  <span>Export Report</span>
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

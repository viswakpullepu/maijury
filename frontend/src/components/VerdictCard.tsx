import React, { useState } from 'react'
import { motion } from 'framer-motion'
import {
  CheckCircle, XCircle, AlertTriangle, Gavel, Fingerprint, Clock, Lock,
  Mail, FileText, Link2, Paperclip, Layers, Scale, ShieldAlert, Ban,
  PhoneCall, Eye, CheckSquare, ChevronDown, ChevronUp
} from 'lucide-react'
import type { FullTrialResult } from '../api'

interface VerdictCardProps {
  result: FullTrialResult
  onOpenFeedback?: () => void
}

const VERDICT_CONFIG = {
  RED: {
    bg: 'bg-gradient-to-br from-[#1a0808] to-[#0f0505]',
    border: 'border-red-900',
    glow: 'shadow-[0_0_40px_rgba(239,68,68,0.15)]',
    pulse: 'verdict-fake',
    icon: XCircle,
    iconColor: 'text-red-500',
    scoreColor: 'text-red-400',
    labelBg: 'bg-red-950 border-red-800 text-red-300',
  },
  GREEN: {
    bg: 'bg-gradient-to-br from-[#081a10] to-[#050f08]',
    border: 'border-green-900',
    glow: 'shadow-[0_0_40px_rgba(34,197,94,0.12)]',
    pulse: 'verdict-safe',
    icon: CheckCircle,
    iconColor: 'text-green-500',
    scoreColor: 'text-green-400',
    labelBg: 'bg-green-950 border-green-800 text-green-300',
  },
  YELLOW: {
    bg: 'bg-gradient-to-br from-[#1a1508] to-[#0f0e05]',
    border: 'border-yellow-900',
    glow: 'shadow-[0_0_40px_rgba(234,179,8,0.1)]',
    pulse: '',
    icon: AlertTriangle,
    iconColor: 'text-yellow-500',
    scoreColor: 'text-yellow-400',
    labelBg: 'bg-yellow-950 border-yellow-800 text-yellow-300',
  }
}

const DISPOSITION_LABELS: Record<string, { label: string; description: string }> = {
  GATEWAY_DROP_AND_QUARANTINE: { label: '🚫 DROP & QUARANTINE', description: 'Message must be rejected at gateway and isolated.' },
  SPAM_OR_QUARANTINE: { label: '📥 QUARANTINE', description: 'Deliver to spam/quarantine for security review.' },
  DELIVER_WITH_WARNING_BANNER: { label: '⚠️ DELIVER + WARN', description: 'Deliver with prominent caution banner.' },
  DELIVER_INBOX: { label: '✅ DELIVER TO INBOX', description: 'Message is certified safe for delivery.' },
}

export const VerdictCard: React.FC<VerdictCardProps> = ({ result, onOpenFeedback }) => {
  const [showChecklist, setShowChecklist] = useState(false)
  const { summary, envelope } = result
  const color = summary.color as 'RED' | 'GREEN' | 'YELLOW'
  const config = VERDICT_CONFIG[color] || VERDICT_CONFIG.YELLOW
  const Icon = config.icon
  const disposition = DISPOSITION_LABELS[summary.disposition] || {
    label: summary.disposition, description: ''
  }
  const breakdown = summary.risk_breakdown || result.verdict.risk_breakdown
  const recs = result.actionable_recommendations || summary.actionable_recommendations || result.verdict?.actionable_recommendations

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.97 }}
      animate={{ opacity: 1, scale: 1 }}
      className={`${config.bg} ${config.glow} border ${config.border} ${config.pulse} rounded-2xl p-6 space-y-5`}
    >
      {/* Header */}
      <div className="flex items-start gap-4">
        <motion.div
          initial={{ scale: 0 }}
          animate={{ scale: 1 }}
          transition={{ type: 'spring', stiffness: 300, damping: 20, delay: 0.1 }}
        >
          <Icon className={`w-12 h-12 ${config.iconColor}`} strokeWidth={1.5} />
        </motion.div>
        <div className="flex-1 min-w-0">
          <div className={`inline-block text-xs font-bold px-3 py-1 rounded-full border ${config.labelBg} mb-2`}>
            {summary.verdict}
          </div>
          <h2 className="text-[#94a3b8] text-sm truncate" title={envelope.subject}>
            "{envelope.subject}"
          </h2>
          <p className="text-[#64748b] text-xs truncate">{envelope.from_raw}</p>
        </div>
        <div className="text-right shrink-0">
          <div className={`text-4xl font-black ${config.scoreColor} leading-none`}>
            {summary.risk_score}
          </div>
          <div className="text-[#64748b] text-xs">/ 100</div>
        </div>
      </div>

      {/* Meter */}
      <div className="space-y-1">
        <div className="flex justify-between text-xs text-[#64748b]">
          <span>SAFE</span>
          <span>Risk Score</span>
          <span>MALICIOUS</span>
        </div>
        <div className="h-2.5 bg-[#0d0f14] rounded-full overflow-hidden border border-[#1e2130]">
          <motion.div
            initial={{ width: 0 }}
            animate={{ width: `${summary.risk_score}%` }}
            transition={{ duration: 0.8, ease: 'easeOut', delay: 0.2 }}
            className={`h-full rounded-full ${
              color === 'RED' ? 'bg-gradient-to-r from-orange-600 to-red-500' :
              color === 'GREEN' ? 'bg-gradient-to-r from-emerald-600 to-green-500' :
              'bg-gradient-to-r from-yellow-600 to-amber-500'
            }`}
          />
        </div>
      </div>

      {/* Disposition */}
      <div className={`rounded-lg p-3 border ${config.border} ${config.bg}`}>
        <div className="text-sm font-bold text-[#f1f5f9]">{disposition.label}</div>
        <div className="text-xs text-[#64748b] mt-0.5">{disposition.description}</div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 gap-2">
        {[
          { label: 'Charges Sustained', value: summary.charges_sustained, color: 'text-[#ef4444]' },
          { label: 'Charges Dismissed', value: summary.charges_dismissed, color: 'text-[#22c55e]' },
          { label: 'Defense Proofs', value: summary.defense_proofs, color: 'text-[#3b82f6]' },
          { label: 'Fatal Vetos', value: summary.fatal_vetos, color: summary.fatal_vetos > 0 ? 'text-red-500' : 'text-[#64748b]' },
        ].map(({ label, value, color }) => (
          <div key={label} className="bg-[#0d0f14] border border-[#1e2130] rounded-lg p-3 text-center">
            <div className={`text-2xl font-bold ${color}`}>{value}</div>
            <div className="text-[#64748b] text-xs mt-0.5">{label}</div>
          </div>
        ))}
      </div>
 
      {/* 4-Pillar Risk Contribution Breakdown */}
      {breakdown && (
        <div className="bg-[#0a0c10] border border-[#1e2130] rounded-xl p-3.5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5 text-xs font-semibold text-[#f1f5f9]">
              <Layers className="w-3.5 h-3.5 text-[#3b82f6]" />
              <span>Risk Contribution by Vector</span>
            </div>
            {breakdown.highest_contributor !== 'none' && (
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-red-950/80 border border-red-900 text-red-300 font-mono">
                Primary: {breakdown.highest_contributor_name.split(' ')[0]}
              </span>
            )}
          </div>

          <div className="space-y-2">
            {[
              { key: 'sender', icon: Mail, label: 'Sender & Auth' },
              { key: 'body', icon: FileText, label: 'Email Body' },
              { key: 'urls', icon: Link2, label: 'Links & URLs' },
              { key: 'attachments', icon: Paperclip, label: 'Attachments' },
            ].map(({ key, icon: PillarIcon, label }) => {
              const p = breakdown.pillars[key as keyof typeof breakdown.pillars]
              if (!p) return null
              const isFatal = p.severity === 'FATAL_VETO'
              const isSevere = p.severity === 'SEVERE'
              const isSuspicious = p.severity === 'SUSPICIOUS'

              const badgeColor = isFatal
                ? 'text-red-400 bg-red-950/80 border-red-800'
                : isSevere
                ? 'text-orange-400 bg-orange-950/80 border-orange-800'
                : isSuspicious
                ? 'text-yellow-400 bg-yellow-950/80 border-yellow-800'
                : 'text-green-400 bg-green-950/80 border-green-800'

              const barColor = isFatal
                ? 'bg-gradient-to-r from-red-600 to-rose-500'
                : isSevere
                ? 'bg-gradient-to-r from-orange-600 to-red-500'
                : isSuspicious
                ? 'bg-gradient-to-r from-amber-600 to-yellow-500'
                : 'bg-emerald-500'

              return (
                <div key={key} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-1.5 min-w-0">
                      <PillarIcon className="w-3.5 h-3.5 text-[#64748b] shrink-0" />
                      <span className="text-[#94a3b8] truncate font-medium text-[11px]">{label}</span>
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded border font-mono ${badgeColor}`}>
                        {p.severity === 'FATAL_VETO' ? 'FATAL' : p.severity}
                      </span>
                      <span className="font-mono text-[11px] font-bold text-[#f1f5f9]">
                        +{p.contribution_score} <span className="text-[#64748b] font-normal">({p.contribution_percentage}%)</span>
                      </span>
                    </div>
                  </div>
                  <div className="h-1.5 bg-[#07090d] rounded-full overflow-hidden border border-[#171b26]">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${p.contribution_percentage}%` }}
                      transition={{ duration: 0.6, ease: 'easeOut' }}
                      className={`h-full rounded-full ${barColor}`}
                    />
                  </div>
                </div>
              )
            })}
          </div>

          <div className="text-[10px] text-[#64748b] font-mono border-t border-[#1e2130] pt-2 truncate" title={breakdown.attribution_formula}>
            {breakdown.attribution_formula}
          </div>
        </div>
      )}

      {/* Actionable Recommendations (Requirement 3: Quarantine, Official Sender Verification, Safe Viewer) */}
      {recs && (
        <div className="bg-[#0a0c10] border border-[#1e2a4a] rounded-xl p-3.5 space-y-3 shadow-lg">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              <span className="text-xs font-bold text-[#f1f5f9] tracking-wide uppercase">
                Actionable Defense Directives
              </span>
            </div>
            <span
              className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold border ${
                recs.primary_action === 'QUARANTINE_AND_ISOLATE'
                  ? 'bg-red-950/90 text-red-300 border-red-800'
                  : recs.primary_action === 'VERIFY_SENDER_AND_HOLD'
                  ? 'bg-amber-950/90 text-amber-300 border-amber-800'
                  : 'bg-green-950/90 text-green-300 border-green-800'
              }`}
            >
              {recs.primary_action.replace(/_/g, ' ')}
            </span>
          </div>

          <div className="text-xs text-[#cbd5e1] font-medium leading-relaxed bg-[#10141f] p-2.5 rounded-lg border border-[#1e2436]">
            {recs.summary_headline}
          </div>

          {/* 3 Core Recommendation Pillars */}
          <div className="grid grid-cols-1 gap-2 text-xs">
            {/* Pillar 1: Quarantine */}
            <div className="bg-[#0d1017] border border-[#1f293d] rounded-lg p-2.5 space-y-1">
              <div className="flex items-center justify-between text-[11px]">
                <div className="flex items-center gap-1.5 font-semibold text-red-400">
                  <Ban className="w-3.5 h-3.5 shrink-0" />
                  <span>1. Quarantine & Mailbox Isolation</span>
                </div>
                <span className="text-[10px] font-mono text-[#94a3b8] px-1.5 py-0.2 rounded bg-black/40">
                  {recs.quarantine.status}
                </span>
              </div>
              <p className="text-[11px] text-[#94a3b8] leading-tight">
                {recs.quarantine.action || recs.quarantine.instructions}
              </p>
              {recs.quarantine.mailbox_actions && recs.quarantine.mailbox_actions.length > 0 && (
                <div className="text-[10px] text-[#64748b] font-mono">
                  • {recs.quarantine.mailbox_actions[0]}
                </div>
              )}
            </div>

            {/* Pillar 2: Verify Sender */}
            <div className="bg-[#0d1017] border border-[#1f293d] rounded-lg p-2.5 space-y-1">
              <div className="flex items-center justify-between text-[11px]">
                <div className="flex items-center gap-1.5 font-semibold text-amber-400">
                  <PhoneCall className="w-3.5 h-3.5 shrink-0" />
                  <span>2. Out-of-Band Sender Verification</span>
                </div>
                <span className="text-[10px] font-mono text-amber-300 px-1.5 py-0.2 rounded bg-amber-950/40 border border-amber-900/60">
                  {recs.verify_sender.verification_required ? 'REQUIRED' : 'ADVISORY'}
                </span>
              </div>
              <p className="text-[11px] text-[#94a3b8] leading-tight">
                Channel: <strong className="text-white">{recs.verify_sender.recommended_channel}</strong>
              </p>
              <p className="text-[10px] text-amber-400/90 leading-tight">
                Strict: Never reply directly or call contact numbers inside this email.
              </p>
            </div>

            {/* Pillar 3: Safe Viewer */}
            <div className="bg-[#0d1017] border border-[#1f293d] rounded-lg p-2.5 space-y-1">
              <div className="flex items-center justify-between text-[11px]">
                <div className="flex items-center gap-1.5 font-semibold text-blue-400">
                  <Eye className="w-3.5 h-3.5 shrink-0" />
                  <span>3. Safe Viewer File Inspection</span>
                </div>
                <span className="text-[10px] font-mono text-blue-300 px-1.5 py-0.2 rounded bg-blue-950/40 border border-blue-900/60">
                  {recs.safe_viewer.has_attachments ? `${recs.safe_viewer.attachment_viewers.length} File(s)` : 'Body Text'}
                </span>
              </div>
              <p className="text-[11px] text-[#94a3b8] leading-tight">
                {recs.safe_viewer.overview}
              </p>
              {recs.safe_viewer.attachment_viewers && recs.safe_viewer.attachment_viewers.length > 0 && (
                <div className="text-[10px] text-blue-300/90 font-mono bg-blue-950/30 p-1.5 rounded border border-blue-900/40 truncate">
                  Viewer: {recs.safe_viewer.attachment_viewers[0].guidance.recommended_viewer}
                </div>
              )}
            </div>
          </div>

          {/* Expandable Prioritized Action Checklist */}
          {recs.prioritized_checklist && recs.prioritized_checklist.length > 0 && (
            <div className="pt-1">
              <button
                type="button"
                onClick={() => setShowChecklist(!showChecklist)}
                className="w-full flex items-center justify-between p-2 rounded-lg bg-[#0d1017] hover:bg-[#121722] border border-[#1f293d] text-[11px] font-semibold text-[#93c5fd] transition-colors"
              >
                <div className="flex items-center gap-1.5">
                  <CheckSquare className="w-3.5 h-3.5 text-[#3b82f6]" />
                  <span>Prioritized Action Checklist ({recs.prioritized_checklist.length} Steps)</span>
                </div>
                {showChecklist ? (
                  <ChevronUp className="w-3.5 h-3.5 text-[#64748b]" />
                ) : (
                  <ChevronDown className="w-3.5 h-3.5 text-[#64748b]" />
                )}
              </button>

              {showChecklist && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  className="mt-2 space-y-1.5 pl-1"
                >
                  {recs.prioritized_checklist.map(item => {
                    const isImmediate = item.priority === 'IMMEDIATE'
                    const isHigh = item.priority === 'HIGH'
                    const prioColor = isImmediate
                      ? 'bg-red-950 text-red-300 border-red-800'
                      : isHigh
                      ? 'bg-orange-950 text-orange-300 border-orange-800'
                      : 'bg-blue-950 text-blue-300 border-blue-800'

                    return (
                      <div
                        key={item.step}
                        className="bg-[#080a0f] border border-[#1a1f2e] rounded-lg p-2 text-[11px] space-y-1"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-white flex items-center gap-1.5">
                            <span className="font-mono text-[#64748b]">#{item.step}</span>
                            <span>{item.action}</span>
                          </span>
                          <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${prioColor}`}>
                            {item.priority}
                          </span>
                        </div>
                        <p className="text-[10px] text-[#94a3b8] leading-tight">{item.detail}</p>
                      </div>
                    )
                  })}
                </motion.div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Justification */}
      <div className="bg-[#0a0c10] border border-[#1e2130] rounded-lg p-3">
        <div className="flex items-center gap-2 mb-2">
          <Gavel className="w-4 h-4 text-[#a855f7]" />
          <span className="text-xs font-medium text-[#a855f7]">Chief Justice Ruling</span>
        </div>
        <p className="text-xs text-[#94a3b8] leading-relaxed">{summary.justification}</p>
      </div>

      {/* Legal Metadata */}
      <div className="border-t border-[#1e2130] pt-4 space-y-2">
        <div className="flex items-center gap-2 text-[#475569] text-xs">
          <Fingerprint className="w-3.5 h-3.5" />
          <span className="font-mono truncate">{result.meta.sha256.substring(0, 32)}...</span>
        </div>
        <div className="flex items-center gap-2 text-[#475569] text-xs">
          <Lock className="w-3.5 h-3.5" />
          <span>BSA 2023 §65B: {summary.bsa_cert.substring(0, 24)}...</span>
        </div>
        <div className="flex items-center gap-2 text-[#475569] text-xs">
          <Clock className="w-3.5 h-3.5" />
          <span>Trial completed in {summary.pipeline_ms}ms</span>
        </div>
      </div>

      {/* Dispute Classification / User Feedback Action Button */}
      {onOpenFeedback && (
        <button
          onClick={onOpenFeedback}
          type="button"
          className="w-full flex items-center justify-center gap-2 py-3 px-4 rounded-xl text-xs font-bold bg-[#141824] hover:bg-[#1a2030] border border-[#2d3752] hover:border-[#3b82f6] text-[#93c5fd] hover:text-white transition-all shadow-md cursor-pointer group"
        >
          <Scale className="w-4 h-4 text-[#3b82f6] group-hover:scale-110 transition-transform" />
          <span>⚖️ Dispute Classification / Report Feedback</span>
        </button>
      )}
    </motion.div>
  )
}

import React from 'react'
import { motion } from 'framer-motion'
import { CheckCircle, XCircle, AlertTriangle, Gavel, Fingerprint, Clock, Lock } from 'lucide-react'
import type { FullTrialResult } from '../api'

interface VerdictCardProps {
  result: FullTrialResult
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

export const VerdictCard: React.FC<VerdictCardProps> = ({ result }) => {
  const { summary, envelope } = result
  const color = summary.color as 'RED' | 'GREEN' | 'YELLOW'
  const config = VERDICT_CONFIG[color] || VERDICT_CONFIG.YELLOW
  const Icon = config.icon
  const disposition = DISPOSITION_LABELS[summary.disposition] || {
    label: summary.disposition, description: ''
  }

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
    </motion.div>
  )
}

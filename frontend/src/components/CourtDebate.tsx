import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ChevronDown, ChevronUp, AlertOctagon, ShieldCheck, Paperclip, FileCheck, FileWarning, ShieldAlert, Mail, FileText, Link2, Layers, CheckCircle, Ban, PhoneCall, Eye, CheckSquare, AlertTriangle } from 'lucide-react'
import type { TranscriptEntry, IndictmentCount, ExonerationProof, FullTrialResult, AttachmentAnalysis } from '../api'
import { AttachmentReportCard } from './AttachmentReportCard'

const SPEAKER_STYLES: Record<string, { label: string; color: string; bg: string; border: string }> = {
  CHIEF_JUSTICE: {
    label: '⚖️ Chief Justice',
    color: 'text-[#a855f7]',
    bg: 'bg-[#120d1a]',
    border: 'border-[#4c1d95]'
  },
  PROSECUTOR: {
    label: '⚔️ Team Prosecutor',
    color: 'text-[#ef4444]',
    bg: 'bg-[#1a0808]',
    border: 'border-[#7f1d1d]'
  },
  DEFENDER: {
    label: '🛡️ Team Defender',
    color: 'text-[#22c55e]',
    bg: 'bg-[#081a10]',
    border: 'border-[#14532d]'
  }
}

const SEVERITY_BADGE: Record<string, { label: string; classes: string }> = {
  FATAL_VETO: { label: '☠ FATAL VETO', classes: 'bg-red-950 text-red-400 border border-red-800' },
  SEVERE: { label: '🔴 SEVERE', classes: 'bg-orange-950 text-orange-400 border border-orange-800' },
  SUSPICIOUS: { label: '🟡 SUSPICIOUS', classes: 'bg-yellow-950 text-yellow-400 border border-yellow-800' },
  CIRCUMSTANTIAL: { label: '⚪ CIRCUMSTANTIAL', classes: 'bg-slate-800 text-slate-400 border border-slate-600' },
}

interface CourtDebateProps {
  result: FullTrialResult
}

export const CourtDebate: React.FC<CourtDebateProps> = ({ result }) => {
  const [expandedCount, setExpandedCount] = useState<string | null>(null)
  const [expandedPillar, setExpandedPillar] = useState<string | null>(null)
  const [tab, setTab] = useState<'breakdown' | 'charges' | 'defense' | 'attachments' | 'recommendations' | 'transcript'>('breakdown')
  const [attachmentFilter, setAttachmentFilter] = useState<'ALL' | 'MALICIOUS' | 'SUSPICIOUS' | 'SAFE'>('ALL')

  const { prosecution, defense, verdict, attachments_analysis, summary } = result
  const attachments = attachments_analysis || []
  const breakdown = summary.risk_breakdown || verdict.risk_breakdown
  const recs = result.actionable_recommendations || summary.actionable_recommendations || verdict.actionable_recommendations

  return (
    <div className="space-y-4">
      {/* Tab bar */}
      <div className="flex gap-1 bg-[#0d0f14] rounded-lg p-1 border border-[#1e2130]">
        {([
          ['breakdown', '📊 Risk Breakdown'],
          ['charges', `⚔️ Charges (${verdict.stats.total_prosecution_counts})`],
          ['defense', `🛡️ Defense (${verdict.stats.defense_proofs_entered})`],
          ['attachments', `📎 Attachments (${attachments.length})`],
          ['recommendations', '📋 Actionable Guidance'],
          ['transcript', '📜 Trial Transcript'],
        ] as const).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`flex-1 py-2 px-3 rounded-md text-xs font-medium transition-all ${
              tab === key
                ? 'bg-[#1a1f2e] text-white border border-[#2d3556]'
                : 'text-[#64748b] hover:text-white'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      <AnimatePresence mode="wait">
        {/* BREAKDOWN TAB */}
        {tab === 'breakdown' && (
          <motion.div key="breakdown" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="space-y-4">
            
            {/* Header Attribution Card */}
            <div className="bg-[#0c1017] border border-[#1e2a3f] rounded-xl p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 rounded-lg bg-blue-950/80 border border-blue-800 flex items-center justify-center">
                    <Layers className="w-4 h-4 text-blue-400" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-[#f1f5f9]">Multi-Vector Risk Attribution Engine</h3>
                    <p className="text-[11px] text-[#64748b]">
                      Bharatiya Sakshya Adhiniyam §65B & Multi-Indicator Fusion Adjudication
                    </p>
                  </div>
                </div>
                {breakdown && breakdown.highest_contributor !== 'none' ? (
                  <div className="flex items-center gap-2 bg-red-950/60 border border-red-900/80 px-3 py-1.5 rounded-lg text-xs">
                    <span className="text-[#94a3b8]">Primary Threat:</span>
                    <span className="font-bold text-red-300 font-mono">
                      {breakdown.highest_contributor_name}
                    </span>
                  </div>
                ) : (
                  <div className="flex items-center gap-1.5 bg-green-950/60 border border-green-900/80 px-3 py-1.5 rounded-lg text-xs text-green-300 font-medium">
                    <ShieldCheck className="w-3.5 h-3.5 text-green-400" />
                    <span>All Vectors Certified Clean</span>
                  </div>
                )}
              </div>

              {/* Attribution Equation Box */}
              {breakdown && (
                <div className="bg-[#07090e] border border-[#151c28] rounded-lg p-3">
                  <div className="text-[11px] text-[#64748b] mb-1.5 font-medium flex items-center justify-between">
                    <span>MATHEMATICAL CAUSAL ATTRIBUTION</span>
                    <span className="font-mono text-purple-400">Total: {breakdown.total_risk_score} / 100</span>
                  </div>
                  <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                    <span className="text-[#94a3b8] font-bold">Overall Risk ({breakdown.total_risk_score})</span>
                    <span className="text-[#475569]">=</span>
                    <span className="bg-[#121622] px-2 py-0.5 rounded border border-[#1e2638] text-blue-300">
                      Sender: +{breakdown.pillars.sender.contribution_score} ({breakdown.pillars.sender.contribution_percentage}%)
                    </span>
                    <span className="text-[#475569]">+</span>
                    <span className="bg-[#121622] px-2 py-0.5 rounded border border-[#1e2638] text-amber-300">
                      Body: +{breakdown.pillars.body.contribution_score} ({breakdown.pillars.body.contribution_percentage}%)
                    </span>
                    <span className="text-[#475569]">+</span>
                    <span className="bg-[#121622] px-2 py-0.5 rounded border border-[#1e2638] text-cyan-300">
                      URLs: +{breakdown.pillars.urls.contribution_score} ({breakdown.pillars.urls.contribution_percentage}%)
                    </span>
                    <span className="text-[#475569]">+</span>
                    <span className="bg-[#121622] px-2 py-0.5 rounded border border-[#1e2638] text-rose-300">
                      Attachments: +{breakdown.pillars.attachments.contribution_score} ({breakdown.pillars.attachments.contribution_percentage}%)
                    </span>
                  </div>
                  <p className="text-xs text-[#94a3b8] mt-2.5 leading-relaxed">
                    {breakdown.summary_text}
                  </p>
                </div>
              )}
            </div>

            {/* 4 Detailed Interactive Pillar Cards */}
            {breakdown && (
              <div className="space-y-3">
                {[
                  { key: 'sender', icon: Mail, label: 'Sender & Authentication' },
                  { key: 'body', icon: FileText, label: 'Email Body Content' },
                  { key: 'urls', icon: Link2, label: 'Links & URLs' },
                  { key: 'attachments', icon: Paperclip, label: 'File Attachments' },
                ].map(({ key, icon: PillarIcon, label }) => {
                  const p = breakdown.pillars[key as keyof typeof breakdown.pillars]
                  if (!p) return null

                  const isExpanded = expandedPillar === key
                  const isFatal = p.severity === 'FATAL_VETO'
                  const isSevere = p.severity === 'SEVERE'
                  const isSuspicious = p.severity === 'SUSPICIOUS'

                  const cardBorder = isFatal
                    ? 'border-red-900 bg-[#140606]'
                    : isSevere
                    ? 'border-orange-950 bg-[#120805]'
                    : isSuspicious
                    ? 'border-yellow-950 bg-[#120f06]'
                    : 'border-green-950/80 bg-[#061209]'

                  const badgeClass = isFatal
                    ? 'bg-red-950 text-red-400 border-red-800'
                    : isSevere
                    ? 'bg-orange-950 text-orange-400 border-orange-800'
                    : isSuspicious
                    ? 'bg-yellow-950 text-yellow-400 border-yellow-800'
                    : 'bg-green-950 text-green-400 border-green-800'

                  const meterColor = isFatal
                    ? 'bg-gradient-to-r from-red-600 to-rose-500'
                    : isSevere
                    ? 'bg-gradient-to-r from-orange-600 to-red-500'
                    : isSuspicious
                    ? 'bg-gradient-to-r from-amber-600 to-yellow-500'
                    : 'bg-emerald-500'

                  return (
                    <div key={key} className={`border ${cardBorder} rounded-xl p-4 space-y-3 transition-colors`}>
                      {/* Top Row */}
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex items-center gap-2.5 min-w-0">
                          <div className="w-8 h-8 rounded-lg bg-[#0d1117] border border-[#1e2638] flex items-center justify-center shrink-0">
                            <PillarIcon className="w-4 h-4 text-[#94a3b8]" />
                          </div>
                          <div className="min-w-0">
                            <div className="text-sm font-bold text-[#f1f5f9] truncate">
                              {p.name}
                            </div>
                            <div className="text-[11px] text-[#64748b] truncate">
                              {p.description}
                            </div>
                          </div>
                        </div>

                        <div className="text-right shrink-0 space-y-1">
                          <div className="flex items-center justify-end gap-1.5">
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded border font-mono ${badgeClass}`}>
                              {p.severity === 'FATAL_VETO' ? '☠ FATAL VETO' : p.severity}
                            </span>
                            <span className="text-xs font-mono font-bold text-[#f1f5f9]">
                              +{p.contribution_score} pts
                            </span>
                          </div>
                          <div className="text-[11px] text-[#64748b] font-mono">
                            {p.contribution_percentage}% contribution · Standalone: {p.risk_score}/100
                          </div>
                        </div>
                      </div>

                      {/* Standalone Risk Meter Bar */}
                      <div className="space-y-1">
                        <div className="flex justify-between text-[10px] text-[#64748b] font-mono">
                          <span>Standalone Pillar Risk</span>
                          <span>{p.risk_score} / 100</span>
                        </div>
                        <div className="h-1.5 bg-[#090b10] rounded-full overflow-hidden border border-[#1a1f2e]">
                          <motion.div
                            initial={{ width: 0 }}
                            animate={{ width: `${p.risk_score}%` }}
                            transition={{ duration: 0.6, ease: 'easeOut' }}
                            className={`h-full rounded-full ${meterColor}`}
                          />
                        </div>
                      </div>

                      {/* Context Highlights */}
                      {p.context_highlights && p.context_highlights.length > 0 && (
                        <div className="flex flex-wrap gap-1.5 pt-1">
                          {p.context_highlights.map((h, hIdx) => (
                            <span key={hIdx} className="text-[11px] font-mono bg-[#0d1017] border border-[#1e2536] text-[#94a3b8] px-2 py-0.5 rounded">
                              {h}
                            </span>
                          ))}
                        </div>
                      )}

                      {/* Analytical Summary */}
                      <div className="text-xs text-[#94a3b8] bg-[#090c12]/70 rounded-lg p-2.5 border border-[#171e2c] leading-relaxed">
                        <span className="text-[#64748b] font-medium">Judicial Finding: </span>
                        {p.summary}
                      </div>

                      {/* Contributing Factors Accordion */}
                      {p.factors && p.factors.length > 0 && (
                        <div>
                          <button
                            onClick={() => setExpandedPillar(isExpanded ? null : key)}
                            className="flex items-center gap-1.5 text-xs text-[#64748b] hover:text-[#cbd5e1] transition-colors py-1 font-medium"
                          >
                            <span>Contributing Forensic Factors ({p.factors.length})</span>
                            {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                          </button>

                          <AnimatePresence>
                            {isExpanded && (
                              <motion.div
                                initial={{ opacity: 0, height: 0 }}
                                animate={{ opacity: 1, height: 'auto' }}
                                exit={{ opacity: 0, height: 0 }}
                                className="space-y-2 pt-2"
                              >
                                {p.factors.map((f, fIdx) => {
                                  const isSustained = f.status === 'SUSTAINED'
                                  const fBadge = isSustained
                                    ? (f.severity === 'FATAL_VETO' ? 'bg-red-950 text-red-300 border-red-800' : 'bg-orange-950 text-orange-300 border-orange-800')
                                    : 'bg-green-950 text-green-300 border-green-800'

                                  return (
                                    <div
                                      key={fIdx}
                                      className={`text-xs rounded-lg p-2.5 border ${
                                        isSustained ? 'bg-[#150a0a] border-[#3b1515]' : 'bg-[#08130a] border-[#15381a]'
                                      }`}
                                    >
                                      <div className="flex items-center justify-between gap-2 mb-1">
                                        <div className="flex items-center gap-1.5 min-w-0">
                                          <span className={`text-[10px] px-1.5 py-0.5 rounded border font-mono ${fBadge}`}>
                                            {isSustained ? f.severity : 'DISMISSED'}
                                          </span>
                                          <span className="font-semibold text-[#f1f5f9] truncate">{f.title}</span>
                                        </div>
                                        <span className="font-mono text-[11px] text-[#94a3b8] shrink-0">
                                          {isSustained ? `+${f.risk_points} pts` : 'Struck from record'}
                                        </span>
                                      </div>
                                      {f.exhibit && (
                                        <div className="text-[11px] font-mono text-[#64748b] truncate mt-0.5">
                                          Exhibit: {f.exhibit}
                                        </div>
                                      )}
                                      {f.statute && (
                                        <div className="text-[10px] text-[#475569] mt-0.5">
                                          Statute: {f.statute}
                                        </div>
                                      )}
                                      {f.dismissal_grounds && (
                                        <div className="text-[11px] text-green-400 mt-1 pl-2 border-l-2 border-green-600">
                                          Defense Exoneration: {f.dismissal_grounds}
                                        </div>
                                      )}
                                    </div>
                                  )
                                })}
                              </motion.div>
                            )}
                          </AnimatePresence>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </motion.div>
        )}

        {/* CHARGES TAB */}
        {tab === 'charges' && (
          <motion.div key="charges" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="space-y-2">
            {prosecution.counts.length === 0 ? (
              <div className="text-center py-8 text-[#64748b]">
                <ShieldCheck className="w-8 h-8 mx-auto mb-2 text-[#22c55e]" />
                No charges filed — Prosecution rests.
              </div>
            ) : prosecution.counts.map((count: IndictmentCount) => {
              const survived = verdict.surviving_counts.some((c: any) => c.count_id === count.count_id)
              const badge = SEVERITY_BADGE[count.severity] || SEVERITY_BADGE.CIRCUMSTANTIAL
              const isExpanded = expandedCount === count.count_id

              return (
                <motion.div
                  key={count.count_id}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  className={`border rounded-lg overflow-hidden ${
                    survived ? 'border-[#7f1d1d] bg-[#0f0505]' : 'border-[#14532d] bg-[#050f08]'
                  }`}
                >
                  <button
                    onClick={() => setExpandedCount(isExpanded ? null : count.count_id)}
                    className="w-full flex items-center gap-3 p-3 text-left hover:bg-white/5 transition-colors"
                  >
                    <span className={`text-xs px-2 py-0.5 rounded font-mono ${badge.classes}`}>{badge.label}</span>
                    <span className="text-sm font-medium text-[#f1f5f9] flex-1 truncate">{count.charge_name}</span>
                    <div className="flex items-center gap-2 shrink-0">
                      {!survived && (
                        <span className="text-xs text-[#22c55e] bg-[#081a10] border border-[#14532d] px-2 py-0.5 rounded">
                          DISMISSED
                        </span>
                      )}
                      <span className="text-xs text-[#64748b] font-mono">+{count.risk_points}pts</span>
                      {isExpanded ? <ChevronUp className="w-4 h-4 text-[#64748b]" /> : <ChevronDown className="w-4 h-4 text-[#64748b]" />}
                    </div>
                  </button>
                  <AnimatePresence>
                    {isExpanded && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        className="border-t border-[#1e2130] px-4 py-3 space-y-2"
                      >
                        <div className="text-xs text-[#64748b]">
                          <span className="text-[#94a3b8] font-medium">Statute: </span>{count.statute}
                        </div>
                        <div className="text-xs font-mono bg-[#0a0c10] rounded px-3 py-2 text-[#94a3b8] border border-[#1e2130]">
                          Exhibit: {count.exhibit}
                        </div>
                        <div className="text-xs text-[#94a3b8] leading-relaxed">{count.explanation}</div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </motion.div>
              )
            })}
          </motion.div>
        )}

        {/* DEFENSE TAB */}
        {tab === 'defense' && (
          <motion.div key="defense" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="space-y-2">
            {defense.proofs.length === 0 ? (
              <div className="text-center py-8 text-[#64748b]">
                <AlertOctagon className="w-8 h-8 mx-auto mb-2 text-[#ef4444]" />
                No exonerating proofs established.
              </div>
            ) : defense.proofs.map((proof: ExonerationProof) => (
              <motion.div
                key={proof.proof_id}
                initial={{ opacity: 0, x: 8 }}
                animate={{ opacity: 1, x: 0 }}
                className="border border-[#14532d] bg-[#050f08] rounded-lg p-3 space-y-1.5"
              >
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-[#22c55e] shrink-0" />
                  <span className="text-sm font-medium text-[#f1f5f9]">{proof.title}</span>
                  <span className="ml-auto text-xs text-[#22c55e] font-mono">+{proof.legitimacy_points}pts</span>
                </div>
                <p className="text-xs text-[#64748b] font-mono pl-6">{proof.certificate}</p>
                <p className="text-xs text-[#475569] pl-6">{proof.legal_basis}</p>
              </motion.div>
            ))}

            {defense.objections.length > 0 && (
              <div className="mt-4 border-t border-[#1e2130] pt-4">
                <h4 className="text-xs font-medium text-[#64748b] mb-2">
                  MOTIONS TO DISMISS ({defense.objections.length})
                </h4>
                {defense.objections.map((obj: any, i: number) => (
                  <div key={i} className="border border-[#1a3a1a] bg-[#080f08] rounded-lg p-3 mb-2">
                    <div className="text-xs text-[#22c55e] font-medium mb-1">
                      Motion against {obj.target_count_id} — {obj.demanded_action}
                    </div>
                    <p className="text-xs text-[#64748b]">{obj.grounds}</p>
                  </div>
                ))}
              </div>
            )}
          </motion.div>
        )}

        {/* ATTACHMENTS TAB */}
        {tab === 'attachments' && (
          <motion.div key="attachments" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="space-y-4">
            {/* Zero Execution Guarantee Banner */}
            <div className="bg-[#0c121e] border border-[#1e2d4a] rounded-xl p-3 flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-blue-950 border border-blue-800 flex items-center justify-center shrink-0">
                <ShieldCheck className="w-4 h-4 text-blue-400" />
              </div>
              <div>
                <div className="text-xs font-bold text-blue-300">Zero-Execution Static Guarantee</div>
                <div className="text-[11px] text-[#64748b]">
                  Analyzed 100% in-memory via pure byte-stream parsing. No file was opened, mounted, rendered, or executed.
                </div>
              </div>
            </div>

            {attachments.length === 0 ? (
              <div className="text-center py-10 text-[#64748b] bg-[#0d0f14] border border-[#1e2130] rounded-xl">
                <Paperclip className="w-8 h-8 mx-auto mb-2 text-[#64748b]" />
                <div className="text-sm font-medium text-[#94a3b8]">Zero Attachments Present</div>
                <div className="text-xs text-[#475569] mt-1">Attack surface minimized: this message carries no file payloads.</div>
              </div>
            ) : (
              <div className="space-y-4">
                {/* Header / Filter Toolbar if multiple attachments */}
                <div className="flex flex-wrap items-center justify-between gap-2 px-1">
                  <div className="text-xs text-[#94a3b8] flex items-center gap-2 font-medium">
                    <span className="text-slate-400">Forensic Report Cards:</span>
                    <span className="font-bold text-white">{attachments.length} attachment{attachments.length > 1 ? 's' : ''} inspected</span>
                  </div>

                  {attachments.length > 1 && (
                    <div className="flex items-center gap-1 bg-[#090b10] p-1 rounded-lg border border-[#1e2130]">
                      {(['ALL', 'MALICIOUS', 'SUSPICIOUS', 'SAFE'] as const).map(filterKey => {
                        const count = filterKey === 'ALL'
                          ? attachments.length
                          : filterKey === 'SAFE'
                          ? attachments.filter(a => a.risk_level === 'SAFE').length
                          : attachments.filter(a => a.risk_level === filterKey).length

                        if (count === 0 && filterKey !== 'ALL') return null

                        return (
                          <button
                            key={filterKey}
                            onClick={() => setAttachmentFilter(filterKey)}
                            className={`px-2.5 py-1 rounded text-[11px] font-semibold transition-all ${
                              attachmentFilter === filterKey
                                ? 'bg-[#1e293b] text-white border border-[#3b82f6]/40 shadow-xs'
                                : 'text-[#64748b] hover:text-white'
                            }`}
                          >
                            {filterKey === 'ALL' ? 'All' : filterKey.charAt(0) + filterKey.slice(1).toLowerCase()} ({count})
                          </button>
                        )
                      })}
                    </div>
                  )}
                </div>

                {/* Per-Attachment Report Cards */}
                {attachments
                  .filter(att => {
                    if (attachmentFilter === 'ALL') return true
                    if (attachmentFilter === 'SAFE') return att.risk_level === 'SAFE'
                    return att.risk_level === attachmentFilter
                  })
                  .map((att: AttachmentAnalysis, idx: number) => (
                    <AttachmentReportCard
                      key={att.sha256 || idx}
                      attachment={att}
                      defaultExpanded={attachments.length === 1 || att.risk_level === 'MALICIOUS'}
                    />
                  ))}
              </div>
            )}
          </motion.div>
        )}

        {/* RECOMMENDATIONS TAB (Requirement 3: Quarantine, Official Sender Verification, Safe Viewer) */}
        {tab === 'recommendations' && (
          <motion.div key="recommendations" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="space-y-4">
            
            {/* Header Banner */}
            <div className="bg-[#0c1017] border border-[#1e2a3f] rounded-xl p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 rounded-lg bg-amber-950/80 border border-amber-800 flex items-center justify-center">
                    <ShieldAlert className="w-4 h-4 text-amber-400" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-[#f1f5f9]">Actionable Defense Directives</h3>
                    <p className="text-[11px] text-[#64748b]">
                      Tailored containment, out-of-band sender verification, and zero-execution safe viewers
                    </p>
                  </div>
                </div>
                {recs && (
                  <span
                    className={`text-xs font-mono font-bold px-3 py-1 rounded-full border ${
                      recs.primary_action === 'QUARANTINE_AND_ISOLATE'
                        ? 'bg-red-950 text-red-300 border-red-800'
                        : recs.primary_action === 'VERIFY_SENDER_AND_HOLD'
                        ? 'bg-amber-950 text-amber-300 border-amber-800'
                        : 'bg-green-950 text-green-300 border-green-800'
                    }`}
                  >
                    {recs.primary_action.replace(/_/g, ' ')}
                  </span>
                )}
              </div>

              {recs && (
                <div className="text-xs text-[#cbd5e1] font-medium bg-[#111726] border border-[#1e2c48] p-3 rounded-lg leading-relaxed">
                  {recs.summary_headline}
                </div>
              )}
            </div>

            {recs && (
              <>
                {/* 1. Quarantine & Mailbox Isolation Directive */}
                <div className="bg-[#0f0c12] border border-red-950/80 rounded-xl p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-7 h-7 rounded-lg bg-red-950/60 border border-red-800 flex items-center justify-center">
                        <Ban className="w-4 h-4 text-red-400" />
                      </div>
                      <div>
                        <h4 className="text-xs font-bold text-red-300">1. Quarantine & Mailbox Isolation</h4>
                        <p className="text-[10px] text-[#64748b]">Perimeter gateway containment & tenant isolation</p>
                      </div>
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-red-800 bg-red-950/60 text-red-400 font-bold">
                      {recs.quarantine.status}
                    </span>
                  </div>

                  <div className="text-xs text-[#cbd5e1] bg-[#1a0c0c] border border-red-900/40 p-3 rounded-lg">
                    <strong className="text-white">Action: </strong>{recs.quarantine.action || recs.quarantine.instructions}
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                    {/* Mailbox Actions */}
                    {recs.quarantine.mailbox_actions && recs.quarantine.mailbox_actions.length > 0 && (
                      <div className="bg-[#090b10] border border-[#1a1f2e] rounded-lg p-3 space-y-1.5">
                        <div className="text-[11px] font-bold text-[#cbd5e1] flex items-center gap-1.5">
                          <Mail className="w-3.5 h-3.5 text-red-400" />
                          <span>Mailbox Store Directives</span>
                        </div>
                        <div className="space-y-1 pl-1">
                          {recs.quarantine.mailbox_actions.map((act, i) => (
                            <div key={i} className="text-[11px] text-[#94a3b8] flex items-start gap-1.5">
                              <span className="text-red-400 shrink-0">•</span>
                              <span>{act}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Perimeter / SIEM Actions */}
                    {recs.quarantine.perimeter_containment && recs.quarantine.perimeter_containment.length > 0 && (
                      <div className="bg-[#090b10] border border-[#1a1f2e] rounded-lg p-3 space-y-1.5">
                        <div className="text-[11px] font-bold text-[#cbd5e1] flex items-center gap-1.5">
                          <Layers className="w-3.5 h-3.5 text-blue-400" />
                          <span>SOC & Perimeter Ingestion</span>
                        </div>
                        <div className="space-y-1 pl-1">
                          {recs.quarantine.perimeter_containment.map((act, i) => (
                            <div key={i} className="text-[11px] text-[#94a3b8] flex items-start gap-1.5">
                              <span className="text-blue-400 shrink-0">•</span>
                              <span>{act}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* 2. Official Channel Sender Verification */}
                <div className="bg-[#120f0a] border border-amber-950/80 rounded-xl p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-7 h-7 rounded-lg bg-amber-950/60 border border-amber-800 flex items-center justify-center">
                        <PhoneCall className="w-4 h-4 text-amber-400" />
                      </div>
                      <div>
                        <h4 className="text-xs font-bold text-amber-300">2. Verify Sender via Official Channel</h4>
                        <p className="text-[10px] text-[#64748b]">Out-of-band verification protocol</p>
                      </div>
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-amber-800 bg-amber-950/60 text-amber-300 font-bold">
                      {recs.verify_sender.verification_required ? 'ACTION REQUIRED' : 'ADVISORY'}
                    </span>
                  </div>

                  <div className="bg-[#1a150a] border border-amber-900/40 p-3 rounded-lg space-y-1.5 text-xs">
                    <div>
                      <span className="text-[#94a3b8]">Purported Sender: </span>
                      <strong className="text-white">{recs.verify_sender.purported_sender || result.envelope.from_raw}</strong>
                    </div>
                    <div>
                      <span className="text-[#94a3b8]">Recommended Channel: </span>
                      <strong className="text-amber-300">{recs.verify_sender.recommended_channel}</strong>
                    </div>
                    {recs.verify_sender.why_needed && (
                      <p className="text-[#cbd5e1] text-[11px] pt-1 border-t border-amber-900/30">
                        {recs.verify_sender.why_needed}
                      </p>
                    )}
                  </div>

                  {/* Out of Band Protocol Checklist */}
                  {recs.verify_sender.protocol_checklist && (
                    <div className="space-y-1.5">
                      <div className="text-[11px] font-bold text-[#cbd5e1] uppercase tracking-wider">
                        Verification Challenge Protocol
                      </div>
                      <div className="space-y-1 pl-1">
                        {recs.verify_sender.protocol_checklist.map((item, i) => (
                          <div key={i} className="text-[11px] text-[#94a3b8] flex items-start gap-2 bg-[#090b10] border border-[#1a1f2e] p-2 rounded-lg">
                            <span className="font-mono text-amber-400 font-bold shrink-0">{i + 1}.</span>
                            <span>{item}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="bg-red-950/40 border border-red-900/60 p-2.5 rounded-lg flex items-center gap-2 text-[11px] text-red-300">
                    <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                    <span><strong>Strict Prohibition:</strong> Do NOT reply to this email, do NOT click any links, and do NOT use phone numbers or contact details written inside the message.</span>
                  </div>
                </div>

                {/* 3. Safe Viewer File Inspection Matrix */}
                <div className="bg-[#0a0f17] border border-blue-950/80 rounded-xl p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-7 h-7 rounded-lg bg-blue-950/60 border border-blue-800 flex items-center justify-center">
                        <Eye className="w-4 h-4 text-blue-400" />
                      </div>
                      <div>
                        <h4 className="text-xs font-bold text-blue-300">3. Safe Viewer File Inspection</h4>
                        <p className="text-[10px] text-[#64748b]">Zero-execution analysis environments tailored per payload type</p>
                      </div>
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-blue-800 bg-blue-950/60 text-blue-300 font-bold">
                      {recs.safe_viewer.has_attachments ? `${recs.safe_viewer.attachment_viewers.length} ATTACHMENT(S)` : 'EMAIL BODY'}
                    </span>
                  </div>

                  <div className="bg-[#0d1424] border border-blue-900/40 p-3 rounded-lg text-xs text-[#cbd5e1]">
                    {recs.safe_viewer.overview}
                  </div>

                  {/* Attachment Viewers List */}
                  {recs.safe_viewer.attachment_viewers && recs.safe_viewer.attachment_viewers.length > 0 && (
                    <div className="space-y-3">
                      {recs.safe_viewer.attachment_viewers.map((av, idx) => (
                        <div key={idx} className="bg-[#070a12] border border-[#1b253b] rounded-xl p-3.5 space-y-2.5">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <Paperclip className="w-4 h-4 text-blue-400" />
                              <span className="text-xs font-bold text-white font-mono">{av.filename}</span>
                            </div>
                            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                              av.risk_level === 'MALICIOUS' ? 'bg-red-950 text-red-300 border-red-800' :
                              av.risk_level === 'SUSPICIOUS' ? 'bg-amber-950 text-amber-300 border-amber-800' :
                              'bg-green-950 text-green-300 border-green-800'
                            }`}>
                              {av.risk_level} ({av.risk_score}/100)
                            </span>
                          </div>

                          <div className="bg-[#0d1322] border border-[#1d2b48] rounded-lg p-2.5 text-xs space-y-1">
                            <div>
                              <span className="text-[#64748b]">Recommended Safe Viewer: </span>
                              <strong className="text-white">{av.guidance.recommended_viewer}</strong>
                            </div>
                            <div>
                              <span className="text-[#64748b]">Viewer Class: </span>
                              <span className="text-blue-300 font-mono text-[11px]">{av.guidance.viewer_type}</span>
                            </div>
                            {av.guidance.safe_inspection_tools && (
                              <div className="flex flex-wrap gap-1 pt-1">
                                {av.guidance.safe_inspection_tools.map((tool, tIdx) => (
                                  <span key={tIdx} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-blue-950/60 border border-blue-900/60 text-blue-300">
                                    {tool}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>

                          {/* Instructions */}
                          {av.guidance.step_by_step_instructions && (
                            <div className="space-y-1 pl-1">
                              <div className="text-[10px] font-bold text-[#64748b] uppercase tracking-wider">
                                Inspection Steps
                              </div>
                              {av.guidance.step_by_step_instructions.map((step, sIdx) => (
                                <div key={sIdx} className="text-[11px] text-[#94a3b8] flex items-start gap-1.5">
                                  <span className="font-mono text-blue-400 font-bold shrink-0">{sIdx + 1}.</span>
                                  <span>{step}</span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Body text viewer fallback */}
                  {!recs.safe_viewer.has_attachments && (
                    <div className="bg-[#070a12] border border-[#1b253b] rounded-xl p-3 text-xs text-[#94a3b8]">
                      {recs.safe_viewer.email_body_viewer_guidance}
                    </div>
                  )}
                </div>

                {/* 4. Complete Prioritized Incident Response Checklist */}
                {recs.prioritized_checklist && recs.prioritized_checklist.length > 0 && (
                  <div className="bg-[#0b0e14] border border-[#1e2538] rounded-xl p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <CheckSquare className="w-4 h-4 text-purple-400" />
                        <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                          Prioritized Execution Checklist ({recs.prioritized_checklist.length} Steps)
                        </h4>
                      </div>
                      <span className="text-[10px] font-mono text-[#64748b]">NIST SP 800-61r2 Aligned</span>
                    </div>

                    <div className="space-y-2">
                      {recs.prioritized_checklist.map(item => {
                        const prioBadge =
                          item.priority === 'IMMEDIATE' ? 'bg-red-950 text-red-300 border-red-800' :
                          item.priority === 'HIGH' ? 'bg-orange-950 text-orange-300 border-orange-800' :
                          item.priority === 'MEDIUM' ? 'bg-amber-950 text-amber-300 border-amber-800' :
                          'bg-blue-950 text-blue-300 border-blue-800'

                        return (
                          <div
                            key={item.step}
                            className="bg-[#07090e] border border-[#161c29] rounded-lg p-3 space-y-1.5 text-xs"
                          >
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2 font-semibold text-white">
                                <span className="font-mono text-purple-400 font-bold">Step {item.step}:</span>
                                <span>{item.action}</span>
                              </div>
                              <div className="flex items-center gap-1.5">
                                <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-black/40 text-[#94a3b8] border border-[#232a3c]">
                                  {item.category}
                                </span>
                                <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${prioBadge}`}>
                                  {item.priority}
                                </span>
                              </div>
                            </div>
                            <p className="text-[11px] text-[#94a3b8] leading-relaxed pl-1">
                              {item.detail}
                            </p>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}
              </>
            )}
          </motion.div>
        )}

        {/* TRANSCRIPT TAB */}
        {tab === 'transcript' && (
          <motion.div key="transcript" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="space-y-3 max-h-[500px] overflow-y-auto pr-1">
            {verdict.trial_transcript.map((entry: TranscriptEntry, i: number) => {
              const style = SPEAKER_STYLES[entry.speaker] || SPEAKER_STYLES.CHIEF_JUSTICE
              return (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.04 }}
                  className={`${style.bg} border ${style.border} rounded-lg p-3`}
                >
                  <div className={`text-xs font-semibold ${style.color} mb-1.5`}>{style.label}</div>
                  <p className="text-xs text-[#94a3b8] leading-relaxed">{entry.utterance}</p>
                </motion.div>
              )
            })}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

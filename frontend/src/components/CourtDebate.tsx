import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ChevronDown, ChevronUp, AlertOctagon, ShieldCheck, Paperclip, FileCheck, FileWarning, ShieldAlert } from 'lucide-react'
import type { TranscriptEntry, IndictmentCount, ExonerationProof, FullTrialResult, AttachmentAnalysis } from '../api'

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
  const [tab, setTab] = useState<'charges' | 'defense' | 'attachments' | 'transcript'>('charges')

  const { prosecution, defense, verdict, attachments_analysis } = result
  const attachments = attachments_analysis || []

  return (
    <div className="space-y-4">
      {/* Tab bar */}
      <div className="flex gap-1 bg-[#0d0f14] rounded-lg p-1 border border-[#1e2130]">
        {([
          ['charges', `⚔️ Charges (${verdict.stats.total_prosecution_counts})`],
          ['defense', `🛡️ Defense (${verdict.stats.defense_proofs_entered})`],
          ['attachments', `📎 Attachments (${attachments.length})`],
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
              attachments.map((att: AttachmentAnalysis, idx: number) => {
                const isMalicious = att.risk_level === 'MALICIOUS'
                const isSuspicious = att.risk_level === 'SUSPICIOUS'
                const cardBorder = isMalicious ? 'border-red-900 bg-[#160808]' : (isSuspicious ? 'border-yellow-900 bg-[#141005]' : 'border-green-950 bg-[#06120a]')
                const badgeClass = isMalicious ? 'bg-red-950 text-red-400 border-red-800' : (isSuspicious ? 'bg-yellow-950 text-yellow-400 border-yellow-800' : 'bg-green-950 text-green-400 border-green-800')
                const sizeKb = (att.size_bytes / 1024).toFixed(1)

                return (
                  <motion.div
                    key={idx}
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: idx * 0.05 }}
                    className={`border ${cardBorder} rounded-xl p-4 space-y-3`}
                  >
                    {/* Header */}
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-2.5 min-w-0">
                        {isMalicious ? (
                          <ShieldAlert className="w-5 h-5 text-red-500 shrink-0" />
                        ) : isSuspicious ? (
                          <FileWarning className="w-5 h-5 text-yellow-500 shrink-0" />
                        ) : (
                          <FileCheck className="w-5 h-5 text-green-500 shrink-0" />
                        )}
                        <div className="min-w-0">
                          <div className="text-sm font-semibold text-[#f1f5f9] truncate" title={att.filename}>
                            {att.filename}
                          </div>
                          <div className="text-[11px] text-[#64748b] font-mono">
                            {sizeKb} KB · SHA256: {att.sha256.slice(0, 16)}...
                          </div>
                        </div>
                      </div>
                      <div className="shrink-0 text-right">
                        <span className={`text-[11px] font-bold px-2.5 py-1 rounded-md border ${badgeClass}`}>
                          {att.risk_level} ({att.risk_score}/100)
                        </span>
                      </div>
                    </div>

                    {/* Classification Banner */}
                    <div className="text-xs bg-[#0d0f14] border border-[#1e2130] rounded-lg px-3 py-2 flex items-center gap-2">
                      <span className="text-[#64748b] font-medium">Classification:</span>
                      <span className={`font-semibold ${isMalicious ? 'text-red-300' : isSuspicious ? 'text-yellow-300' : 'text-green-300'}`}>
                        {att.classification}
                      </span>
                    </div>

                    {/* MIME & Magic Bytes Grid */}
                    <div className="grid grid-cols-2 gap-2 text-[11px]">
                      <div className="bg-[#090b10] border border-[#1a1f2e] rounded-lg p-2">
                        <div className="text-[#64748b] mb-0.5">Declared vs Detected MIME</div>
                        <div className="text-[#cbd5e1] font-mono truncate" title={att.declared_type}>
                          Declared: {att.declared_type || 'None'}
                        </div>
                        <div className={`font-mono truncate ${att.declared_type && !att.declared_type.includes(att.detected_type.split('/')[1] || '') && isMalicious ? 'text-red-400 font-bold' : 'text-[#94a3b8]'}`}>
                          Detected: {att.detected_type}
                        </div>
                      </div>
                      <div className="bg-[#090b10] border border-[#1a1f2e] rounded-lg p-2">
                        <div className="text-[#64748b] mb-0.5">Magic Signature (Hex & ASCII)</div>
                        <div className="text-[#cbd5e1] font-mono">[{att.magic_hex || 'None'}]</div>
                        <div className="text-[#64748b] font-mono truncate">ASCII: '{att.magic_ascii}'</div>
                      </div>
                    </div>

                    {/* Evidence Points */}
                    {att.evidence && att.evidence.length > 0 && (
                      <div className="space-y-1">
                        <div className="text-[11px] font-medium text-[#64748b]">Forensic Evidence:</div>
                        <div className="space-y-1 pl-2">
                          {att.evidence.map((ev, evIdx) => (
                            <div key={evIdx} className="text-xs text-[#94a3b8] flex items-start gap-1.5">
                              <span className="text-[#475569] mt-0.5">•</span>
                              <span className="font-mono text-[11px] leading-tight">{ev}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Analytical Reasons */}
                    {att.reasons && (
                      <div className="text-xs text-[#64748b] bg-[#090b10]/60 rounded-lg p-2.5 leading-relaxed border border-[#171b26]">
                        <span className="text-[#94a3b8] font-medium">Analysis: </span>
                        {att.reasons}
                      </div>
                    )}
                  </motion.div>
                )
              })
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

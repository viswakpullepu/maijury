import React, { useState, useId } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  X,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Sliders,
  CheckCircle2,
  FileCheck2,
  Send,
  Loader2,
  Lock,
} from 'lucide-react'
import {
  submitFeedback,
  type FullTrialResult,
  type FeedbackType,
  type FeedbackRecord,
  type FeedbackSubmission,
} from '../api'

interface FeedbackModalProps {
  result: FullTrialResult
  isOpen: boolean
  onClose: () => void
  onSubmitted?: (record: FeedbackRecord) => void
}

const QUICK_NOTES = [
  'Valid internal operational notice with genuine urgency',
  'Verified vendor invoice with normal payment terms',
  'Evasive quishing QR attack missed in inline attachment',
  'Known penetration testing / red team authorized simulation',
]

export const FeedbackModal: React.FC<FeedbackModalProps> = ({
  result,
  isOpen,
  onClose,
  onSubmitted,
}) => {
  const isOriginalPhishing =
    result.summary.verdict.includes('FAKE') ||
    result.summary.verdict.includes('PHISHING') ||
    result.summary.verdict.includes('MALICIOUS')

  const defaultType: FeedbackType = isOriginalPhishing
    ? 'FALSE_POSITIVE'
    : 'FALSE_NEGATIVE'

  const defaultReported = isOriginalPhishing ? 'LEGITIMATE' : 'PHISHING'

  const [feedbackType, setFeedbackType] = useState<FeedbackType>(defaultType)
  const [reportedClassification, setReportedClassification] = useState(defaultReported)
  const [selectedIndicators, setSelectedIndicators] = useState<string[]>([])
  const [customIndicator, setCustomIndicator] = useState('')
  const [suggestedScore, setSuggestedScore] = useState<number>(
    isOriginalPhishing ? 5 : 95
  )
  const [analystNotes, setAnalystNotes] = useState('')
  const [reporterRole, setReporterRole] = useState<'end_user' | 'soc_analyst' | 'security_admin'>('soc_analyst')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)
  const [successRecord, setSuccessRecord] = useState<FeedbackRecord | null>(null)

  const scoreSliderId = useId()

  // Collect all disputable indictments from prosecution and proofs from defense
  const disputableCounts = [
    ...result.prosecution.counts.map(
      (c) => `PROSECUTION: [${c.severity}] ${c.charge_name}`
    ),
    ...result.defense.proofs.map((p) => `DEFENSE: ${p.title}`),
  ]

  const toggleIndicator = (ind: string) => {
    setSelectedIndicators((prev) =>
      prev.includes(ind) ? prev.filter((i) => i !== ind) : [...prev, ind]
    )
  }

  const handleAddCustomIndicator = () => {
    if (customIndicator.trim() && !selectedIndicators.includes(customIndicator.trim())) {
      setSelectedIndicators([...selectedIndicators, customIndicator.trim()])
      setCustomIndicator('')
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsSubmitting(true)
    setErrorMsg(null)

    const payload: FeedbackSubmission = {
      email_sha256: result.meta.sha256,
      email_subject: result.envelope.subject || result.meta.filename || 'Untitled Email',
      email_from: result.envelope.from_raw || 'Unknown Sender',
      original_verdict: result.summary.verdict,
      original_risk_score: result.summary.risk_score,
      reported_classification: reportedClassification,
      feedback_type: feedbackType,
      disputed_indicators: selectedIndicators,
      analyst_notes: analystNotes.trim(),
      reporter_role: reporterRole,
      suggested_risk_score: suggestedScore,
    }

    try {
      const res = await submitFeedback(payload)
      setSuccessRecord(res.record)
      if (onSubmitted) {
        onSubmitted(res.record)
      }
    } catch (err: any) {
      setErrorMsg(err?.response?.data?.detail || err.message || 'Failed to submit feedback')
    } finally {
      setIsSubmitting(false)
    }
  }

  if (!isOpen) return null

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md overflow-y-auto">
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 15 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 15 }}
          transition={{ type: 'spring', damping: 25, stiffness: 300 }}
          className="bg-[#0f1117] border border-[#1e2333] rounded-2xl max-w-2xl w-full p-6 text-[#f1f5f9] shadow-2xl relative my-8"
        >
          {/* Close button */}
          <button
            onClick={onClose}
            className="absolute top-5 right-5 text-[#64748b] hover:text-white p-1 rounded-lg hover:bg-white/5 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>

          {!successRecord ? (
            <form onSubmit={handleSubmit} className="space-y-5">
              {/* Header */}
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-[#3b82f6] to-[#a855f7] flex items-center justify-center text-white text-xs font-bold">
                    ⚖️
                  </div>
                  <h2 className="text-lg font-bold text-white">
                    Report Classification / Dispute Verdict
                  </h2>
                </div>
                <p className="text-xs text-[#94a3b8] leading-relaxed">
                  Provide ground-truth feedback to train the Chief Justice Arbiter, eliminate false positives, and catch evasive threats.
                </p>
              </div>

              {/* Email Summary Banner */}
              <div className="bg-[#141824] border border-[#1e2333] rounded-xl p-3.5 flex items-center justify-between text-xs">
                <div className="min-w-0 flex-1 mr-4">
                  <div className="text-[#64748b] truncate mb-0.5">
                    Subject: <span className="text-[#e2e8f0] font-medium">"{result.envelope.subject || result.meta.filename}"</span>
                  </div>
                  <div className="text-[#64748b] truncate font-mono text-[11px]">
                    SHA: {result.meta.sha256.substring(0, 24)}...
                  </div>
                </div>
                <div className="text-right shrink-0">
                  <div className="text-[#64748b] text-[10px] uppercase font-semibold">Original Verdict</div>
                  <div className="font-bold text-sm text-[#f43f5e]">{result.summary.verdict}</div>
                  <div className="text-[#94a3b8] text-[11px]">Risk: {result.summary.risk_score}/100</div>
                </div>
              </div>

              {/* Feedback Type Selection */}
              <div>
                <label className="block text-xs font-semibold text-[#cbd5e1] mb-2 uppercase tracking-wide">
                  1. Classification Issue Type
                </label>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  {[
                    {
                      type: 'FALSE_POSITIVE' as FeedbackType,
                      title: 'False Positive',
                      desc: 'Legitimate email marked as threat',
                      icon: ShieldCheck,
                      color: 'border-emerald-500/40 bg-emerald-950/20 text-emerald-400',
                    },
                    {
                      type: 'FALSE_NEGATIVE' as FeedbackType,
                      title: 'False Negative',
                      desc: 'Hostile scam missed as safe',
                      icon: ShieldAlert,
                      color: 'border-rose-500/40 bg-rose-950/20 text-rose-400',
                    },
                    {
                      type: 'INCORRECT_RISK_SCORE' as FeedbackType,
                      title: 'Score Off',
                      desc: 'Score too harsh / too lenient',
                      icon: Sliders,
                      color: 'border-amber-500/40 bg-amber-950/20 text-amber-400',
                    },
                    {
                      type: 'ATTACHMENT_MISCLASSIFICATION' as FeedbackType,
                      title: 'File Triage',
                      desc: 'Attachment wrong verdict',
                      icon: FileCheck2,
                      color: 'border-purple-500/40 bg-purple-950/20 text-purple-400',
                    },
                  ].map((card) => {
                    const Icon = card.icon
                    const isSelected = feedbackType === card.type
                    return (
                      <button
                        type="button"
                        key={card.type}
                        onClick={() => {
                          setFeedbackType(card.type)
                          if (card.type === 'FALSE_POSITIVE') {
                            setReportedClassification('LEGITIMATE')
                            setSuggestedScore(5)
                          } else if (card.type === 'FALSE_NEGATIVE') {
                            setReportedClassification('PHISHING')
                            setSuggestedScore(95)
                          }
                        }}
                        className={`p-3 rounded-xl border text-left transition-all relative ${
                          isSelected
                            ? `${card.color} ring-1 ring-white/20 font-semibold shadow-lg`
                            : 'border-[#1e2333] bg-[#141824] text-[#94a3b8] hover:border-[#2d354a]'
                        }`}
                      >
                        <Icon className="w-4 h-4 mb-1.5" />
                        <div className="text-xs font-bold">{card.title}</div>
                        <div className="text-[10px] text-[#64748b] leading-tight mt-0.5">
                          {card.desc}
                        </div>
                      </button>
                    )
                  })}
                </div>
              </div>

              {/* Reported True Classification & Suggested Score */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-[#cbd5e1] mb-2 uppercase tracking-wide">
                    2. Corrected Classification
                  </label>
                  <div className="flex gap-2">
                    {[
                      { id: 'LEGITIMATE', label: '✅ Legitimate', color: 'hover:border-emerald-500' },
                      { id: 'SUSPICIOUS', label: '⚠️ Suspicious', color: 'hover:border-amber-500' },
                      { id: 'PHISHING', label: '🚫 Phishing', color: 'hover:border-rose-500' },
                    ].map((opt) => (
                      <button
                        type="button"
                        key={opt.id}
                        onClick={() => setReportedClassification(opt.id)}
                        className={`flex-1 py-2 px-2.5 rounded-lg text-xs font-semibold border transition-all ${
                          reportedClassification === opt.id
                            ? 'bg-[#1a2238] border-[#3b82f6] text-white'
                            : 'border-[#1e2333] bg-[#141824] text-[#94a3b8]'
                        }`}
                      >
                        {opt.label}
                      </button>
                    ))}
                  </div>
                </div>

                <div>
                  <label htmlFor={scoreSliderId} className="flex justify-between text-xs font-semibold text-[#cbd5e1] mb-2 uppercase tracking-wide">
                    <span>Suggested Risk Score</span>
                    <span className="font-mono text-[#3b82f6] font-bold">{suggestedScore} / 100</span>
                  </label>
                  <input
                    id={scoreSliderId}
                    type="range"
                    min="0"
                    max="100"
                    step="5"
                    value={suggestedScore}
                    onChange={(e) => setSuggestedScore(Number(e.target.value))}
                    className="w-full accent-[#3b82f6] cursor-pointer"
                  />
                  <div className="flex justify-between text-[10px] text-[#64748b] mt-1">
                    <span>0 (Benign)</span>
                    <span>50 (Caution)</span>
                    <span>100 (Hostile)</span>
                  </div>
                </div>
              </div>

              {/* Disputed Indictment Counts & Proofs */}
              {disputableCounts.length > 0 && (
                <div>
                  <label className="block text-xs font-semibold text-[#cbd5e1] mb-1.5 uppercase tracking-wide">
                    3. Select Disputed Charges or Evidence (Optional)
                  </label>
                  <div className="max-h-36 overflow-y-auto space-y-1.5 p-2 rounded-xl bg-[#141824] border border-[#1e2333]">
                    {disputableCounts.map((ind) => {
                      const isChecked = selectedIndicators.includes(ind)
                      return (
                        <div
                          key={ind}
                          onClick={() => toggleIndicator(ind)}
                          className={`flex items-center gap-2 p-2 rounded-lg text-xs cursor-pointer transition-colors ${
                            isChecked
                              ? 'bg-[#1e293b] text-white border border-[#3b82f6]/40'
                              : 'text-[#94a3b8] hover:bg-white/5'
                          }`}
                        >
                          <input
                            type="checkbox"
                            checked={isChecked}
                            onChange={() => {}}
                            className="rounded border-[#334155] accent-[#3b82f6] cursor-pointer"
                          />
                          <span className="truncate">{ind}</span>
                        </div>
                      )
                    })}
                  </div>

                  {/* Add custom indicator input */}
                  <div className="flex gap-2 mt-2">
                    <input
                      type="text"
                      placeholder="Add custom disputed rule or missing threat vector..."
                      value={customIndicator}
                      onChange={(e) => setCustomIndicator(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                          e.preventDefault()
                          handleAddCustomIndicator()
                        }
                      }}
                      className="flex-1 bg-[#141824] border border-[#1e2333] rounded-lg px-3 py-1.5 text-xs text-[#f1f5f9] placeholder-[#64748b] focus:outline-none focus:border-[#3b82f6]"
                    />
                    <button
                      type="button"
                      onClick={handleAddCustomIndicator}
                      className="px-3 py-1.5 bg-[#1e293b] hover:bg-[#334155] text-xs font-medium rounded-lg text-[#cbd5e1] transition-colors"
                    >
                      Add
                    </button>
                  </div>
                </div>
              )}

              {/* Analyst Notes & Quick Tags */}
              <div>
                <label className="block text-xs font-semibold text-[#cbd5e1] mb-1.5 uppercase tracking-wide">
                  4. Operational Context / Analyst Notes
                </label>
                <textarea
                  rows={2}
                  placeholder="Explain why this email was misclassified (e.g., routine bank payroll alert, authorized phishing drill, novel evasion payload)..."
                  value={analystNotes}
                  onChange={(e) => setAnalystNotes(e.target.value)}
                  className="w-full bg-[#141824] border border-[#1e2333] rounded-xl p-3 text-xs text-[#f1f5f9] placeholder-[#64748b] focus:outline-none focus:border-[#3b82f6] transition-colors"
                />
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {QUICK_NOTES.map((chip) => (
                    <button
                      type="button"
                      key={chip}
                      onClick={() =>
                        setAnalystNotes((prev) => (prev ? `${prev}. ${chip}` : chip))
                      }
                      className="text-[11px] bg-[#141824] hover:bg-[#1e293b] text-[#94a3b8] hover:text-[#e2e8f0] px-2.5 py-1 rounded-md border border-[#1e2333] transition-colors"
                    >
                      + {chip}
                    </button>
                  ))}
                </div>
              </div>

              {/* Reporter Role */}
              <div className="flex items-center justify-between pt-1">
                <div className="flex items-center gap-2 text-xs text-[#64748b]">
                  <span>Reporter Role:</span>
                  {(['end_user', 'soc_analyst', 'security_admin'] as const).map((role) => (
                    <button
                      type="button"
                      key={role}
                      onClick={() => setReporterRole(role)}
                      className={`text-xs px-2 py-0.5 rounded capitalize ${
                        reporterRole === role
                          ? 'bg-[#3b82f6]/20 text-[#60a5fa] border border-[#3b82f6]/40 font-semibold'
                          : 'text-[#64748b] hover:text-[#94a3b8]'
                      }`}
                    >
                      {role.replace('_', ' ')}
                    </button>
                  ))}
                </div>

                <div className="flex items-center gap-1.5 text-[11px] text-[#22c55e]">
                  <Lock className="w-3.5 h-3.5" />
                  <span>BSA §65B Certified Audit</span>
                </div>
              </div>

              {errorMsg && (
                <div className="bg-red-950/40 border border-red-800 rounded-xl p-3 text-xs text-red-300 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                  <span>{errorMsg}</span>
                </div>
              )}

              {/* Submit Button */}
              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-4 py-2 rounded-xl text-xs font-semibold text-[#94a3b8] hover:text-white hover:bg-white/5 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-bold bg-gradient-to-r from-[#3b82f6] to-[#6366f1] text-white hover:opacity-90 transition-opacity disabled:opacity-50 shadow-lg shadow-indigo-500/20 cursor-pointer"
                >
                  {isSubmitting ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Registering Feedback...
                    </>
                  ) : (
                    <>
                      <Send className="w-4 h-4" />
                      Submit Ground-Truth Feedback
                    </>
                  )}
                </button>
              </div>
            </form>
          ) : (
            /* Success confirmation screen */
            <div className="text-center py-6 space-y-4">
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ type: 'spring', damping: 20, stiffness: 300 }}
                className="w-16 h-16 rounded-full bg-emerald-950/50 border border-emerald-500/50 flex items-center justify-center mx-auto text-emerald-400"
              >
                <CheckCircle2 className="w-8 h-8" />
              </motion.div>
              <div>
                <h3 className="text-lg font-bold text-white mb-1">
                  Feedback Successfully Registered!
                </h3>
                <p className="text-xs text-[#94a3b8] max-w-md mx-auto">
                  Your feedback has been anchored into the ground-truth evaluation vault to adjust confusion matrix metrics and calibrate future courtroom trials.
                </p>
              </div>

              <div className="bg-[#141824] border border-[#1e2333] rounded-xl p-4 max-w-md mx-auto text-left space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-[#64748b]">Feedback ID:</span>
                  <span className="font-mono text-[#3b82f6] font-semibold">{successRecord.feedback_id}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#64748b]">Reported Type:</span>
                  <span className="font-semibold text-white">{successRecord.submission.feedback_type}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#64748b]">Reported Class:</span>
                  <span className="font-semibold text-emerald-400">{successRecord.submission.reported_classification}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#64748b]">Status:</span>
                  <span className="text-amber-400 font-semibold">{successRecord.status}</span>
                </div>
                <div className="pt-2 border-t border-[#1e2333]">
                  <div className="text-[10px] text-[#64748b] uppercase font-bold mb-0.5">BSA §65B Digital Evidence Token:</div>
                  <div className="font-mono text-[10px] text-[#94a3b8] break-all bg-black/40 p-1.5 rounded">
                    {successRecord.evidence_token}
                  </div>
                </div>
              </div>

              <button
                type="button"
                onClick={onClose}
                className="px-6 py-2.5 rounded-xl text-xs font-bold bg-[#1e293b] hover:bg-[#334155] text-white transition-colors cursor-pointer"
              >
                Done / Close
              </button>
            </div>
          )}
        </motion.div>
      </div>
    </AnimatePresence>
  )
}

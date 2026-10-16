import React, { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Sliders,
  FileCheck2,
  Download,
  Sparkles,
  RefreshCw,
  Search,
  Filter,
  Trash2,
  CheckCircle,
  Clock,
  ChevronDown,
  ChevronUp,
  Cpu,
  Layers,
  Lock,
  BarChart3,
  Check,
} from 'lucide-react'
import {
  getFeedbackEvaluation,
  getFeedbackList,
  exportFeedbackCsv,
  seedFeedbackSamples,
  updateFeedbackStatus,
  deleteFeedbackRecord,
  runFeedbackCalibration,
  type EvaluationReport,
  type FeedbackRecord,
  type FeedbackStatus,
  type FeedbackType,
  type CalibrationInsight,
} from '../api'

export const FeedbackDashboard: React.FC = () => {
  const [evaluation, setEvaluation] = useState<EvaluationReport | null>(null)
  const [records, setRecords] = useState<FeedbackRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [actionLoading, setActionLoading] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedType, setSelectedType] = useState<string>('ALL')
  const [selectedStatus, setSelectedStatus] = useState<string>('ALL')
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [calibrationToast, setCalibrationToast] = useState<string | null>(null)

  const loadData = useCallback(async () => {
    setLoading(true)
    try {
      const [evalRes, listRes] = await Promise.all([
        getFeedbackEvaluation(),
        getFeedbackList({
          feedback_type: selectedType === 'ALL' ? undefined : selectedType,
          status: selectedStatus === 'ALL' ? undefined : selectedStatus,
          search: searchQuery || undefined,
        }),
      ])
      setEvaluation(evalRes)
      setRecords(listRes.records)
    } catch (err) {
      console.error('Failed to load feedback data:', err)
    } finally {
      setLoading(false)
    }
  }, [selectedType, selectedStatus, searchQuery])

  useEffect(() => {
    loadData()
  }, [loadData])

  const handleSeedSamples = async () => {
    setActionLoading(true)
    try {
      await seedFeedbackSamples()
      await loadData()
      showToast('Sample benchmark feedback successfully seeded into vault!')
    } catch (err) {
      console.error(err)
    } finally {
      setActionLoading(false)
    }
  }

  const handleExportCsv = async () => {
    try {
      const csvData = await exportFeedbackCsv()
      const blob = new Blob([csvData], { type: 'text/csv' })
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `mailjury_feedback_eval_${new Date().toISOString().slice(0, 10)}.csv`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      showToast('Feedback audit dataset downloaded!')
    } catch (err) {
      console.error(err)
    }
  }

  const handleRunCalibration = async () => {
    setActionLoading(true)
    try {
      const res = await runFeedbackCalibration()
      await loadData()
      showToast(`Model calibrated against ${res.total_feedback_applied} ground-truth feedback reports!`)
    } catch (err) {
      console.error(err)
    } finally {
      setActionLoading(false)
    }
  }

  const handleStatusChange = async (fid: string, newStatus: FeedbackStatus) => {
    try {
      await updateFeedbackStatus(fid, newStatus)
      await loadData()
    } catch (err) {
      console.error(err)
    }
  }

  const handleDelete = async (fid: string) => {
    if (window.confirm('Delete this feedback record permanently?')) {
      try {
        await deleteFeedbackRecord(fid)
        await loadData()
      } catch (err) {
        console.error(err)
      }
    }
  }

  const showToast = (msg: string) => {
    setCalibrationToast(msg)
    setTimeout(() => setCalibrationToast(null), 4000)
  }

  const cm = evaluation?.confusion_matrix

  return (
    <div className="space-y-6">
      {/* Toast Notification */}
      <AnimatePresence>
        {calibrationToast && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="fixed top-5 right-5 z-50 bg-[#1e293b] border border-[#3b82f6] text-white px-4 py-3 rounded-xl shadow-2xl flex items-center gap-3 text-xs"
          >
            <CheckCircle className="w-4 h-4 text-[#22c55e]" />
            <span>{calibrationToast}</span>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Header and Action Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-[#0d0f14] border border-[#1e2130] rounded-2xl p-5">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <BarChart3 className="w-5 h-5 text-[#3b82f6]" />
            <h1 className="text-lg font-bold text-white">
              Ground-Truth Feedback & Accuracy Evaluation
            </h1>
          </div>
          <p className="text-xs text-[#64748b]">
            Evaluate False Positives (FP) & False Negatives (FN), inspect the live Confusion Matrix, and calibrate courtroom adjudication rules.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={handleSeedSamples}
            disabled={actionLoading}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold bg-[#1a2238] border border-[#2d3a66] text-[#60a5fa] hover:bg-[#222e4d] transition-colors cursor-pointer disabled:opacity-50"
          >
            <Sparkles className="w-3.5 h-3.5" />
            Seed Demo Feedback
          </button>
          <button
            onClick={handleRunCalibration}
            disabled={actionLoading}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold bg-gradient-to-r from-[#6366f1] to-[#a855f7] text-white hover:opacity-90 transition-opacity cursor-pointer disabled:opacity-50"
          >
            <Cpu className="w-3.5 h-3.5" />
            Simulate Calibration
          </button>
          <button
            onClick={handleExportCsv}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold bg-[#141824] border border-[#1e2333] text-[#cbd5e1] hover:text-white hover:bg-[#1e293b] transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            Export CSV
          </button>
          <button
            onClick={loadData}
            className="p-2 rounded-xl text-xs bg-[#141824] border border-[#1e2333] text-[#94a3b8] hover:text-white transition-colors cursor-pointer"
            title="Refresh Evaluation"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* KPI Stats Overview */}
      {cm && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          {[
            {
              label: 'Evaluated Accuracy',
              value: `${(cm.accuracy * 100).toFixed(1)}%`,
              sub: `${cm.true_positives + cm.true_negatives} / ${cm.total_samples} correct`,
              color: 'text-emerald-400',
              border: 'border-emerald-900/40',
            },
            {
              label: 'Precision',
              value: `${(cm.precision * 100).toFixed(1)}%`,
              sub: 'TP / (TP + FP)',
              color: 'text-cyan-400',
              border: 'border-cyan-900/40',
            },
            {
              label: 'Recall (TPR)',
              value: `${(cm.recall * 100).toFixed(1)}%`,
              sub: 'Threats Intercepted',
              color: 'text-blue-400',
              border: 'border-blue-900/40',
            },
            {
              label: 'F1-Score',
              value: `${(cm.f1_score * 100).toFixed(1)}%`,
              sub: 'Harmonic Mean',
              color: 'text-purple-400',
              border: 'border-purple-900/40',
            },
            {
              label: 'False Positives (FP)',
              value: `${cm.false_positives}`,
              sub: `FPR: ${(cm.false_positive_rate * 100).toFixed(1)}%`,
              color: cm.false_positives > 0 ? 'text-amber-400' : 'text-emerald-400',
              border: 'border-amber-900/40',
            },
            {
              label: 'False Negatives (FN)',
              value: `${cm.false_negatives}`,
              sub: `FNR: ${(cm.false_negative_rate * 100).toFixed(1)}%`,
              color: cm.false_negatives > 0 ? 'text-rose-400' : 'text-emerald-400',
              border: 'border-rose-900/40',
            },
          ].map((stat, i) => (
            <motion.div
              key={stat.label}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.05 }}
              className={`bg-[#0d0f14] border ${stat.border} rounded-2xl p-4 flex flex-col justify-between`}
            >
              <div className="text-[11px] text-[#64748b] font-medium uppercase tracking-wide">
                {stat.label}
              </div>
              <div className={`text-2xl font-black ${stat.color} my-1`}>
                {stat.value}
              </div>
              <div className="text-[10px] text-[#475569]">{stat.sub}</div>
            </motion.div>
          ))}
        </div>
      )}

      {/* Main Analysis Section: Confusion Matrix + Calibration Recommendations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Confusion Matrix Card */}
        <div className="bg-[#0d0f14] border border-[#1e2130] rounded-2xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-[#3b82f6]" />
              <h2 className="font-bold text-sm text-white">Empirical Confusion Matrix</h2>
            </div>
            <span className="text-[11px] text-[#64748b] font-mono">
              N = {cm?.total_samples || 0} Ground Truth Cases
            </span>
          </div>

          <p className="text-xs text-[#94a3b8] leading-relaxed">
            Compares adjudicated verdicts against verified user feedback and ground-truth benchmark labels.
          </p>

          {/* 2x2 Matrix */}
          <div className="space-y-2 text-xs">
            {/* Header row */}
            <div className="grid grid-cols-[100px_1fr_1fr] gap-2 text-center text-[#64748b] font-semibold text-[11px]">
              <div></div>
              <div className="bg-[#141824] py-1 rounded-md">Predicted Phishing</div>
              <div className="bg-[#141824] py-1 rounded-md">Predicted Legitimate</div>
            </div>

            {/* Row 1: Actual Threat */}
            <div className="grid grid-cols-[100px_1fr_1fr] gap-2">
              <div className="flex items-center justify-center bg-[#141824] text-[#64748b] font-semibold text-[11px] p-2 rounded-lg text-center">
                Actual Threat
              </div>
              {/* True Positive */}
              <div className="bg-emerald-950/30 border border-emerald-800/50 rounded-xl p-3 text-center">
                <div className="text-[10px] text-emerald-400 font-bold uppercase">
                  True Positive (TP)
                </div>
                <div className="text-2xl font-black text-emerald-300 my-0.5">
                  {cm?.true_positives ?? 0}
                </div>
                <div className="text-[10px] text-emerald-400/80">
                  {cm && cm.total_samples > 0
                    ? `${((cm.true_positives / cm.total_samples) * 100).toFixed(1)}%`
                    : '0%'}
                </div>
              </div>
              {/* False Negative */}
              <div className={`rounded-xl p-3 text-center border ${
                (cm?.false_negatives ?? 0) > 0
                  ? 'bg-rose-950/40 border-rose-700 text-rose-300'
                  : 'bg-[#141824] border-[#1e2333] text-[#64748b]'
              }`}>
                <div className="text-[10px] font-bold uppercase text-rose-400">
                  False Negative (FN)
                </div>
                <div className="text-2xl font-black text-rose-400 my-0.5">
                  {cm?.false_negatives ?? 0}
                </div>
                <div className="text-[10px] text-rose-400/80">
                  Missed Threats
                </div>
              </div>
            </div>

            {/* Row 2: Actual Benign */}
            <div className="grid grid-cols-[100px_1fr_1fr] gap-2">
              <div className="flex items-center justify-center bg-[#141824] text-[#64748b] font-semibold text-[11px] p-2 rounded-lg text-center">
                Actual Benign
              </div>
              {/* False Positive */}
              <div className={`rounded-xl p-3 text-center border ${
                (cm?.false_positives ?? 0) > 0
                  ? 'bg-amber-950/40 border-amber-700 text-amber-300'
                  : 'bg-[#141824] border-[#1e2333] text-[#64748b]'
              }`}>
                <div className="text-[10px] font-bold uppercase text-amber-400">
                  False Positive (FP)
                </div>
                <div className="text-2xl font-black text-amber-400 my-0.5">
                  {cm?.false_positives ?? 0}
                </div>
                <div className="text-[10px] text-amber-400/80">
                  False Alarms
                </div>
              </div>
              {/* True Negative */}
              <div className="bg-emerald-950/30 border border-emerald-800/50 rounded-xl p-3 text-center">
                <div className="text-[10px] text-emerald-400 font-bold uppercase">
                  True Negative (TN)
                </div>
                <div className="text-2xl font-black text-emerald-300 my-0.5">
                  {cm?.true_negatives ?? 0}
                </div>
                <div className="text-[10px] text-emerald-400/80">
                  {cm && cm.total_samples > 0
                    ? `${((cm.true_negatives / cm.total_samples) * 100).toFixed(1)}%`
                    : '0%'}
                </div>
              </div>
            </div>
          </div>

          <div className="p-3 bg-[#141824] border border-[#1e2333] rounded-xl text-xs space-y-1">
            <div className="flex justify-between text-[#94a3b8]">
              <span>False Positive Rate (FPR):</span>
              <span className="font-mono text-white font-semibold">
                {cm ? (cm.false_positive_rate * 100).toFixed(2) : 0}%
              </span>
            </div>
            <div className="flex justify-between text-[#94a3b8]">
              <span>False Negative Rate (FNR):</span>
              <span className="font-mono text-white font-semibold">
                {cm ? (cm.false_negative_rate * 100).toFixed(2) : 0}%
              </span>
            </div>
          </div>
        </div>

        {/* Calibration Insights & Recommendations */}
        <div className="bg-[#0d0f14] border border-[#1e2130] rounded-2xl p-5 space-y-4">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-[#a855f7]" />
            <h2 className="font-bold text-sm text-white">Courtroom Rule Calibration Insights</h2>
          </div>

          <p className="text-xs text-[#94a3b8] leading-relaxed">
            Dynamic heuristics synthesized from user dispute reports to optimize Red Team Prosecutor, Blue Team Defender, and Chief Justice Arbiter rules.
          </p>

          <div className="space-y-3 max-h-[300px] overflow-y-auto pr-1">
            {evaluation?.calibration_insights && evaluation.calibration_insights.length > 0 ? (
              evaluation.calibration_insights.map((ins: CalibrationInsight) => {
                const isCrit = ins.severity === 'CRITICAL'
                const isHigh = ins.severity === 'HIGH'
                const badgeColor = isCrit
                  ? 'bg-rose-950 text-rose-300 border-rose-800'
                  : isHigh
                  ? 'bg-amber-950 text-amber-300 border-amber-800'
                  : 'bg-indigo-950 text-indigo-300 border-indigo-800'

                return (
                  <div
                    key={ins.insight_id}
                    className="p-3.5 rounded-xl bg-[#141824] border border-[#1e2333] space-y-2 text-xs"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="font-semibold text-white">{ins.title}</div>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded border shrink-0 ${badgeColor}`}>
                        {ins.severity}
                      </span>
                    </div>
                    <div className="text-[#94a3b8] leading-relaxed">{ins.description}</div>
                    <div className="bg-[#0d0f14] p-2 rounded-lg border border-[#1e2130] text-[11px] text-[#60a5fa]">
                      <span className="font-semibold text-[#cbd5e1]">Recommended Calibration: </span>
                      {ins.recommended_action}
                    </div>
                    <div className="flex items-center justify-between text-[10px] text-[#64748b]">
                      <span>Target: <code className="text-[#cbd5e1]">{ins.rule_target}</code></span>
                      {ins.affected_count > 0 && <span>Affected: {ins.affected_count} cases</span>}
                    </div>
                  </div>
                )
              })
            ) : (
              <div className="text-center py-8 text-[#64748b] text-xs">
                No active calibration warnings. Courtroom rules stable.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Top Disputed Threat Indicators */}
      {evaluation?.top_disputed_indicators && evaluation.top_disputed_indicators.length > 0 && (
        <div className="bg-[#0d0f14] border border-[#1e2130] rounded-2xl p-5 space-y-3">
          <h2 className="font-bold text-sm text-white">Top Disputed Rules & Indicators</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {evaluation.top_disputed_indicators.map((item, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between p-2.5 rounded-xl bg-[#141824] border border-[#1e2333] text-xs"
              >
                <span className="text-[#cbd5e1] truncate mr-2">{item.indicator}</span>
                <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 font-mono text-[11px] shrink-0 border border-rose-800">
                  {item.dispute_count} disputes
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Filterable Feedback History Audit Table */}
      <div className="bg-[#0d0f14] border border-[#1e2130] rounded-2xl p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="font-bold text-sm text-white">Feedback Audit & Ground-Truth Registry</h2>
            <p className="text-xs text-[#64748b]">
              Immutable Section 65B certified records of user-reported classification errors.
            </p>
          </div>

          {/* Search bar */}
          <div className="relative min-w-[240px]">
            <Search className="w-3.5 h-3.5 absolute left-3 top-3 text-[#64748b]" />
            <input
              type="text"
              placeholder="Search subject, hash, notes..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-[#141824] border border-[#1e2333] rounded-xl pl-9 pr-3 py-2 text-xs text-[#f1f5f9] placeholder-[#64748b] focus:outline-none focus:border-[#3b82f6]"
            />
          </div>
        </div>

        {/* Filter Chips */}
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <span className="text-[#64748b] text-[11px] mr-1 flex items-center gap-1">
            <Filter className="w-3 h-3" /> Type:
          </span>
          {['ALL', 'FALSE_POSITIVE', 'FALSE_NEGATIVE', 'INCORRECT_RISK_SCORE', 'ATTACHMENT_MISCLASSIFICATION'].map((type) => (
            <button
              key={type}
              onClick={() => setSelectedType(type)}
              className={`px-2.5 py-1 rounded-lg text-[11px] transition-colors ${
                selectedType === type
                  ? 'bg-[#3b82f6] text-white font-semibold'
                  : 'bg-[#141824] text-[#94a3b8] hover:text-white border border-[#1e2333]'
              }`}
            >
              {type.replace(/_/g, ' ')}
            </button>
          ))}
        </div>

        {/* Records Table */}
        <div className="overflow-x-auto rounded-xl border border-[#1e2333]">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-[#141824] border-b border-[#1e2333] text-[#64748b] font-semibold text-[11px]">
                <th className="p-3">Feedback ID & Date</th>
                <th className="p-3">Email Subject / Sender</th>
                <th className="p-3">Original Verdict</th>
                <th className="p-3">Reported Issue</th>
                <th className="p-3">Status</th>
                <th className="p-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2333]">
              {records.length > 0 ? (
                records.map((rec) => {
                  const sub = rec.submission
                  const isExpanded = expandedId === rec.feedback_id
                  const isFp = sub.feedback_type === 'FALSE_POSITIVE'
                  const isFn = sub.feedback_type === 'FALSE_NEGATIVE'

                  return (
                    <React.Fragment key={rec.feedback_id}>
                      <tr className="hover:bg-white/[0.02] transition-colors">
                        <td className="p-3 whitespace-nowrap">
                          <div className="font-mono text-[#3b82f6] font-semibold">
                            {rec.feedback_id}
                          </div>
                          <div className="text-[10px] text-[#64748b]">
                            {new Date(rec.timestamp * 1000).toLocaleString()}
                          </div>
                        </td>
                        <td className="p-3 max-w-[220px]">
                          <div className="font-medium text-white truncate" title={sub.email_subject}>
                            "{sub.email_subject}"
                          </div>
                          <div className="text-[10px] text-[#64748b] truncate" title={sub.email_from}>
                            {sub.email_from}
                          </div>
                        </td>
                        <td className="p-3 whitespace-nowrap">
                          <div className="font-semibold text-rose-400">{sub.original_verdict}</div>
                          <div className="text-[10px] text-[#64748b]">Score: {sub.original_risk_score}</div>
                        </td>
                        <td className="p-3 whitespace-nowrap">
                          <span
                            className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold border ${
                              isFp
                                ? 'bg-amber-950/60 text-amber-300 border-amber-700'
                                : isFn
                                ? 'bg-rose-950/60 text-rose-300 border-rose-700'
                                : 'bg-indigo-950/60 text-indigo-300 border-indigo-700'
                            }`}
                          >
                            {sub.feedback_type.replace(/_/g, ' ')}
                          </span>
                          <div className="text-[10px] text-emerald-400 mt-0.5 font-medium">
                            ➔ {sub.reported_classification}
                          </div>
                        </td>
                        <td className="p-3 whitespace-nowrap">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                              rec.status === 'VERIFIED'
                                ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                                : rec.status === 'RESOLVED'
                                ? 'bg-blue-950 text-blue-400 border border-blue-800'
                                : 'bg-slate-900 text-slate-400 border border-slate-700'
                            }`}
                          >
                            {rec.status}
                          </span>
                        </td>
                        <td className="p-3 whitespace-nowrap text-right space-x-1.5">
                          <button
                            onClick={() => setExpandedId(isExpanded ? null : rec.feedback_id)}
                            className="p-1 rounded hover:bg-white/5 text-[#94a3b8] hover:text-white transition-colors"
                            title="Expand Details"
                          >
                            {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                          </button>
                          {rec.status !== 'VERIFIED' && (
                            <button
                              onClick={() => handleStatusChange(rec.feedback_id, 'VERIFIED')}
                              className="px-2 py-0.5 rounded bg-emerald-950 hover:bg-emerald-900 text-emerald-300 text-[10px] font-medium border border-emerald-800 transition-colors"
                              title="Verify Feedback"
                            >
                              Verify
                            </button>
                          )}
                          <button
                            onClick={() => handleDelete(rec.feedback_id)}
                            className="p-1 rounded hover:bg-red-950/50 text-[#64748b] hover:text-red-400 transition-colors"
                            title="Delete Record"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>

                      {/* Expandable detail row */}
                      {isExpanded && (
                        <tr className="bg-[#141824]/60">
                          <td colSpan={6} className="p-4 space-y-3">
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                              <div>
                                <span className="text-[#64748b] font-semibold block mb-1">
                                  Disputed Indicators / Rules:
                                </span>
                                {sub.disputed_indicators && sub.disputed_indicators.length > 0 ? (
                                  <ul className="list-disc list-inside space-y-0.5 text-[#cbd5e1] text-[11px]">
                                    {sub.disputed_indicators.map((ind, i) => (
                                      <li key={i}>{ind}</li>
                                    ))}
                                  </ul>
                                ) : (
                                  <span className="text-[#64748b] italic">No specific indicator specified</span>
                                )}
                              </div>
                              <div>
                                <span className="text-[#64748b] font-semibold block mb-1">
                                  Analyst / Operational Context:
                                </span>
                                <p className="text-[#cbd5e1] text-[11px] leading-relaxed bg-[#0d0f14] p-2 rounded-lg border border-[#1e2130]">
                                  {sub.analyst_notes || 'No analyst notes provided.'}
                                </p>
                              </div>
                            </div>
                            <div className="pt-2 border-t border-[#1e2333] flex items-center justify-between text-[11px]">
                              <div className="flex items-center gap-2">
                                <Lock className="w-3.5 h-3.5 text-emerald-400" />
                                <span className="text-[#64748b]">Evidence Token:</span>
                                <span className="font-mono text-[#cbd5e1]">{rec.evidence_token}</span>
                              </div>
                              <div className="text-[#64748b]">
                                Reporter Role: <span className="text-white capitalize">{sub.reporter_role || 'end_user'}</span>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  )
                })
              ) : (
                <tr>
                  <td colSpan={6} className="text-center py-8 text-[#64748b]">
                    No feedback records match the current filters. Click "Seed Demo Feedback" to populate initial records.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

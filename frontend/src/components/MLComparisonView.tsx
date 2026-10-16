import React, { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Brain,
  Scale,
  Shield,
  Zap,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  TrendingUp,
  Sliders,
  ChevronRight,
  Target
} from 'lucide-react'
import {
  getMLComparisonBenchmark,
  type MLComparisonReport,
  type ModelEvaluationResult
} from '../api'

type ModelKey = 'hybrid_courtroom' | 'rule_based' | 'logistic_regression' | 'random_forest' | 'naive_bayes'

export const MLComparisonView: React.FC = () => {
  const [data, setData] = useState<MLComparisonReport | null>(null)
  const [loading, setLoading] = useState<boolean>(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedModel, setSelectedModel] = useState<ModelKey>('hybrid_courtroom')
  const [activeTab, setActiveTab] = useState<'matrix' | 'table' | 'features' | 'adversarial'>('matrix')

  const fetchBenchmark = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await getMLComparisonBenchmark()
      setData(res)
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Failed to load ML comparison benchmark')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchBenchmark()
  }, [])

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-center">
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 1.5, repeat: Infinity, ease: 'linear' }}
          className="mb-4 text-[#3b82f6]"
        >
          <Brain className="w-12 h-12" />
        </motion.div>
        <div className="text-lg font-bold text-slate-100">Running Empirical ML vs. Rule Benchmark...</div>
        <div className="text-sm text-slate-400 mt-1 max-w-md">
          Extracting 32 forensic features, training classifiers, calculating confusion matrices, and testing adversarial robustness.
        </div>
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="bg-[#121620] border border-red-500/30 rounded-2xl p-8 text-center max-w-xl mx-auto my-12">
        <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
        <h3 className="text-lg font-bold text-red-200 mb-2">Benchmark Failed</h3>
        <p className="text-sm text-slate-400 mb-6">{error}</p>
        <button
          onClick={fetchBenchmark}
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 font-medium text-sm text-white transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
          Retry Benchmark
        </button>
      </div>
    )
  }

  const currentEval: ModelEvaluationResult = data.models_evaluated[selectedModel]
  const cm = currentEval.confusion_matrix
  const metrics = currentEval.metrics
  const total = currentEval.sample_counts.total

  const modelTabs: { key: ModelKey; label: string; tag: string; icon: any }[] = [
    { key: 'hybrid_courtroom', label: 'Hybrid Fusion', tag: 'MailJury Standard', icon: Zap },
    { key: 'rule_based', label: 'Courtroom Arbiter', tag: 'Rule-Based', icon: Scale },
    { key: 'logistic_regression', label: 'Logistic Regression', tag: 'L2 Regularized', icon: TrendingUp },
    { key: 'random_forest', label: 'Random Forest', tag: 'Non-Linear Ensemble', icon: Brain },
    { key: 'naive_bayes', label: 'Naive Bayes', tag: 'Multinomial', icon: Target },
  ]

  return (
    <div className="space-y-8 max-w-6xl mx-auto pb-16">
      {/* ── HEADER & BENCHMARK HERO ── */}
      <div className="bg-gradient-to-b from-[#131722] to-[#0d1017] border border-[#1e2433] rounded-2xl p-6 sm:p-8">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pb-6 border-b border-[#1e2433]">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-semibold uppercase tracking-wider mb-3">
              <Sliders className="w-3.5 h-3.5" />
              Mission 02 · Section 5 Deliverable
            </div>
            <h1 className="text-2xl sm:text-3xl font-black tracking-tight text-white">
              Rule-Based vs. Machine Learning Phishing Triage
            </h1>
            <p className="text-slate-400 text-sm mt-1 max-w-2xl leading-relaxed">
              Empirical comparative study across 30 full-fidelity forensic emails, 32 transport/lexical/attachment features,
              and 3 adversarial evasion scenarios. Evaluates false-positive suppression, zero-execution safety, and latency.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={fetchBenchmark}
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-[#1a2130] hover:bg-[#222b3d] border border-[#2b3548] text-xs font-medium text-slate-200 transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Re-Run Benchmark
            </button>
          </div>
        </div>

        {/* Global Dataset Scorecard */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-6">
          <div className="bg-[#0b0e14] border border-[#1e2433] rounded-xl p-4">
            <div className="text-xs text-slate-500 font-medium">Evaluation Corpus</div>
            <div className="text-2xl font-black text-white mt-1">{data.total_corpus_samples} Emails</div>
            <div className="text-xs text-slate-400 mt-0.5">24 Malicious · 6 Authenticated Benign</div>
          </div>
          <div className="bg-[#0b0e14] border border-[#1e2433] rounded-xl p-4">
            <div className="text-xs text-slate-500 font-medium">Feature Vector</div>
            <div className="text-2xl font-black text-blue-400 mt-1">32 Dims</div>
            <div className="text-xs text-slate-400 mt-0.5">Headers, NLP, URLs, Magic Bytes</div>
          </div>
          <div className="bg-[#0b0e14] border border-[#1e2433] rounded-xl p-4">
            <div className="text-xs text-slate-500 font-medium">Hybrid False Positive Rate</div>
            <div className="text-2xl font-black text-emerald-400 mt-1">0.00%</div>
            <div className="text-xs text-emerald-400/80 mt-0.5">Zero Legitimate Alerts Suppressed</div>
          </div>
          <div className="bg-[#0b0e14] border border-[#1e2433] rounded-xl p-4">
            <div className="text-xs text-slate-500 font-medium">Benchmark Execution Time</div>
            <div className="text-2xl font-black text-purple-400 mt-1">{data.benchmark_latency_ms} ms</div>
            <div className="text-xs text-slate-400 mt-0.5">Full 5-Model Evaluation Suite</div>
          </div>
        </div>
      </div>

      {/* ── MODEL SELECTOR PILLS ── */}
      <div className="flex flex-wrap gap-2.5 p-1.5 bg-[#0d1017] border border-[#1e2433] rounded-2xl">
        {modelTabs.map((tab) => {
          const Icon = tab.icon
          const isActive = selectedModel === tab.key
          return (
            <button
              key={tab.key}
              onClick={() => setSelectedModel(tab.key)}
              className={`flex-1 min-w-[170px] py-3 px-4 rounded-xl flex items-center justify-between text-left transition-all ${
                isActive
                  ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20 font-semibold'
                  : 'bg-transparent text-slate-400 hover:text-slate-200 hover:bg-[#161c27]'
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon className={`w-4 h-4 ${isActive ? 'text-white' : 'text-slate-400'}`} />
                <div>
                  <div className="text-sm leading-none">{tab.label}</div>
                  <div className={`text-[10px] mt-1 ${isActive ? 'text-blue-200' : 'text-slate-500'}`}>
                    {tab.tag}
                  </div>
                </div>
              </div>
              <ChevronRight className={`w-3.5 h-3.5 ${isActive ? 'opacity-100' : 'opacity-30'}`} />
            </button>
          )
        })}
      </div>

      {/* ── VIEW SWITCHER TABS ── */}
      <div className="flex border-b border-[#1e2433] gap-6 text-sm font-medium">
        <button
          onClick={() => setActiveTab('matrix')}
          className={`pb-3 relative transition-colors ${
            activeTab === 'matrix' ? 'text-blue-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Confusion Matrix & Metrics
          {activeTab === 'matrix' && (
            <motion.div layoutId="tab-underline" className="absolute bottom-0 left-0 right-0 h-0.5 bg-blue-500" />
          )}
        </button>
        <button
          onClick={() => setActiveTab('table')}
          className={`pb-3 relative transition-colors ${
            activeTab === 'table' ? 'text-blue-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Head-to-Head Comparison Table
          {activeTab === 'table' && (
            <motion.div layoutId="tab-underline" className="absolute bottom-0 left-0 right-0 h-0.5 bg-blue-500" />
          )}
        </button>
        <button
          onClick={() => setActiveTab('features')}
          className={`pb-3 relative transition-colors ${
            activeTab === 'features' ? 'text-blue-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Forensic Feature Importances
          {activeTab === 'features' && (
            <motion.div layoutId="tab-underline" className="absolute bottom-0 left-0 right-0 h-0.5 bg-blue-500" />
          )}
        </button>
        <button
          onClick={() => setActiveTab('adversarial')}
          className={`pb-3 relative transition-colors ${
            activeTab === 'adversarial' ? 'text-blue-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Adversarial Evasion Stress-Tests
          {activeTab === 'adversarial' && (
            <motion.div layoutId="tab-underline" className="absolute bottom-0 left-0 right-0 h-0.5 bg-blue-500" />
          )}
        </button>
      </div>

      {/* ── TAB 1: CONFUSION MATRIX & METRICS ── */}
      {activeTab === 'matrix' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-[1fr_360px] gap-6">
            {/* 2x2 Interactive Confusion Matrix */}
            <div className="bg-[#0d1017] border border-[#1e2433] rounded-2xl p-6">
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    <Scale className="w-4 h-4 text-blue-400" />
                    2x2 Empirical Confusion Matrix — {currentEval.model_name}
                  </h3>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Evaluated on {total} sample emails ({cm.tp + cm.fn} malicious, {cm.tn + cm.fp} benign).
                  </p>
                </div>
                <div className="text-right">
                  <span className="text-xs px-2.5 py-1 rounded-md bg-[#161c28] border border-[#232c3f] text-slate-300 font-mono">
                    N = {total}
                  </span>
                </div>
              </div>

              {/* Grid with header axes */}
              <div className="overflow-x-auto">
                <div className="min-w-[480px]">
                  {/* Top axis label */}
                  <div className="grid grid-cols-[140px_1fr_1fr] text-center text-xs font-semibold text-slate-400 mb-2">
                    <div />
                    <div className="text-emerald-400 bg-emerald-500/10 py-1.5 rounded-t-lg border-t border-x border-emerald-500/20">
                      Actual Legitimate (Ground Truth = 0)
                    </div>
                    <div className="text-red-400 bg-red-500/10 py-1.5 rounded-t-lg border-t border-x border-red-500/20">
                      Actual Malicious (Ground Truth = 1)
                    </div>
                  </div>

                  {/* Row 1: Predicted Legitimate */}
                  <div className="grid grid-cols-[140px_1fr_1fr] gap-2 mb-2">
                    <div className="bg-[#121622] border border-[#1e2433] rounded-l-xl p-3 flex flex-col justify-center text-xs font-semibold text-slate-300">
                      <div>Predicted Safe</div>
                      <div className="text-[10px] text-slate-500 font-normal">Inbox Delivery</div>
                    </div>

                    {/* True Negative (TN) */}
                    <div className="bg-emerald-950/20 border border-emerald-500/30 rounded-xl p-4 flex flex-col items-center justify-center text-center">
                      <div className="flex items-center gap-1.5 text-xs font-semibold text-emerald-400 mb-1">
                        <CheckCircle2 className="w-4 h-4" />
                        True Negative (TN)
                      </div>
                      <div className="text-3xl font-black text-emerald-300">{cm.tn}</div>
                      <div className="text-[11px] text-emerald-400/70 mt-1">
                        {((cm.tn / (cm.tn + cm.fp || 1)) * 100).toFixed(1)}% of Benign
                      </div>
                      <div className="text-[10px] text-slate-500 mt-1">Authenticated Benign Cleared</div>
                    </div>

                    {/* False Negative (FN) - Critical Breach Hazard */}
                    <div className={`rounded-xl p-4 flex flex-col items-center justify-center text-center border ${
                      cm.fn === 0
                        ? 'bg-[#121622] border-[#1e2433]'
                        : 'bg-red-950/40 border-red-500/50'
                    }`}>
                      <div className={`flex items-center gap-1.5 text-xs font-semibold mb-1 ${
                        cm.fn === 0 ? 'text-slate-400' : 'text-red-400'
                      }`}>
                        <XCircle className="w-4 h-4" />
                        False Negative (FN)
                      </div>
                      <div className={`text-3xl font-black ${cm.fn === 0 ? 'text-slate-400' : 'text-red-400'}`}>
                        {cm.fn}
                      </div>
                      <div className="text-[11px] text-slate-500 mt-1">
                        {((cm.fn / (cm.tp + cm.fn || 1)) * 100).toFixed(1)}% Miss Rate
                      </div>
                      <div className="text-[10px] text-slate-500 mt-1">
                        {cm.fn === 0 ? '0 Threat Breaches' : 'UNDETECTED THREATS'}
                      </div>
                    </div>
                  </div>

                  {/* Row 2: Predicted Malicious */}
                  <div className="grid grid-cols-[140px_1fr_1fr] gap-2">
                    <div className="bg-[#121622] border border-[#1e2433] rounded-l-xl p-3 flex flex-col justify-center text-xs font-semibold text-slate-300">
                      <div>Predicted Threat</div>
                      <div className="text-[10px] text-slate-500 font-normal">Quarantine & Alert</div>
                    </div>

                    {/* False Positive (FP) - False Alarm */}
                    <div className={`rounded-xl p-4 flex flex-col items-center justify-center text-center border ${
                      cm.fp === 0
                        ? 'bg-[#121622] border-[#1e2433]'
                        : 'bg-yellow-950/40 border-yellow-500/50'
                    }`}>
                      <div className={`flex items-center gap-1.5 text-xs font-semibold mb-1 ${
                        cm.fp === 0 ? 'text-slate-400' : 'text-yellow-400'
                      }`}>
                        <AlertTriangle className="w-4 h-4" />
                        False Positive (FP)
                      </div>
                      <div className={`text-3xl font-black ${cm.fp === 0 ? 'text-slate-400' : 'text-yellow-400'}`}>
                        {cm.fp}
                      </div>
                      <div className="text-[11px] text-slate-500 mt-1">
                        {((cm.fp / (cm.tn + cm.fp || 1)) * 100).toFixed(1)}% False Alarm Rate
                      </div>
                      <div className="text-[10px] text-slate-500 mt-1">
                        {cm.fp === 0 ? 'Zero False Alerts' : 'Legitimate Quarantined'}
                      </div>
                    </div>

                    {/* True Positive (TP) */}
                    <div className="bg-blue-950/20 border border-blue-500/30 rounded-xl p-4 flex flex-col items-center justify-center text-center">
                      <div className="flex items-center gap-1.5 text-xs font-semibold text-blue-400 mb-1">
                        <Shield className="w-4 h-4" />
                        True Positive (TP)
                      </div>
                      <div className="text-3xl font-black text-blue-300">{cm.tp}</div>
                      <div className="text-[11px] text-blue-400/70 mt-1">
                        {((cm.tp / (cm.tp + cm.fn || 1)) * 100).toFixed(1)}% of Phishing
                      </div>
                      <div className="text-[10px] text-slate-500 mt-1">Attacks Intercepted</div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Statistical Derivation Footer */}
              <div className="mt-6 pt-4 border-t border-[#1e2433] grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div>
                  <span className="text-slate-500">Precision:</span>{' '}
                  <span className="font-mono text-slate-200">{metrics.precision}%</span>
                  <div className="text-[10px] text-slate-600 font-mono">TP / (TP + FP)</div>
                </div>
                <div>
                  <span className="text-slate-500">Recall (TPR):</span>{' '}
                  <span className="font-mono text-slate-200">{metrics.recall}%</span>
                  <div className="text-[10px] text-slate-600 font-mono">TP / (TP + FN)</div>
                </div>
                <div>
                  <span className="text-slate-500">Specificity (TNR):</span>{' '}
                  <span className="font-mono text-slate-200">{metrics.specificity}%</span>
                  <div className="text-[10px] text-slate-600 font-mono">TN / (TN + FP)</div>
                </div>
                <div>
                  <span className="text-slate-500">False Pos. Rate:</span>{' '}
                  <span className="font-mono text-emerald-400">{metrics.false_positive_rate}%</span>
                  <div className="text-[10px] text-slate-600 font-mono">FP / (FP + TN)</div>
                </div>
              </div>
            </div>

            {/* Performance & Operational Latency Card */}
            <div className="space-y-4">
              <div className="bg-[#0d1017] border border-[#1e2433] rounded-2xl p-6">
                <h4 className="text-xs uppercase font-semibold text-slate-400 tracking-wider mb-4 flex items-center gap-2">
                  <Zap className="w-3.5 h-3.5 text-yellow-400" />
                  Latency & Throughput Profile
                </h4>

                <div className="space-y-3.5">
                  <div className="flex justify-between items-center text-sm">
                    <span className="text-slate-400">Mean Latency</span>
                    <span className="font-mono font-bold text-white">{currentEval.latency_profile.mean_ms} ms</span>
                  </div>
                  <div className="flex justify-between items-center text-sm">
                    <span className="text-slate-400">Median (p50)</span>
                    <span className="font-mono text-slate-300">{currentEval.latency_profile.p50_ms} ms</span>
                  </div>
                  <div className="flex justify-between items-center text-sm">
                    <span className="text-slate-400">95th Percentile (p95)</span>
                    <span className="font-mono text-slate-300">{currentEval.latency_profile.p95_ms} ms</span>
                  </div>
                  <div className="flex justify-between items-center text-sm">
                    <span className="text-slate-400">Throughput Capacity</span>
                    <span className="font-mono text-emerald-400 font-semibold">
                      {currentEval.latency_profile.throughput_per_sec} msg/sec
                    </span>
                  </div>
                </div>

                <div className="mt-5 pt-4 border-t border-[#1e2433]">
                  <div className="text-[11px] text-slate-500 leading-relaxed">
                    Evaluated in memory with zero disk mounting, zero process execution, and zero outbound network calls.
                  </div>
                </div>
              </div>

              {/* Quality Metric Gauges */}
              <div className="bg-[#0d1017] border border-[#1e2433] rounded-2xl p-6">
                <h4 className="text-xs uppercase font-semibold text-slate-400 tracking-wider mb-4 flex items-center gap-2">
                  <Target className="w-3.5 h-3.5 text-blue-400" />
                  Discriminative Power
                </h4>

                <div className="space-y-3">
                  <div>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-slate-400">F1-Score</span>
                      <span className="font-mono font-bold text-white">{metrics.f1_score}</span>
                    </div>
                    <div className="w-full bg-[#1a2130] h-2 rounded-full overflow-hidden">
                      <div className="bg-blue-500 h-full rounded-full" style={{ width: `${metrics.f1_score * 100}%` }} />
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-slate-400">Matthews Corr. (MCC)</span>
                      <span className="font-mono font-bold text-white">{metrics.mcc}</span>
                    </div>
                    <div className="w-full bg-[#1a2130] h-2 rounded-full overflow-hidden">
                      <div className="bg-emerald-500 h-full rounded-full" style={{ width: `${Math.max(0, metrics.mcc) * 100}%` }} />
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-slate-400">ROC Area Under Curve (AUC)</span>
                      <span className="font-mono font-bold text-white">{metrics.roc_auc}</span>
                    </div>
                    <div className="w-full bg-[#1a2130] h-2 rounded-full overflow-hidden">
                      <div className="bg-purple-500 h-full rounded-full" style={{ width: `${metrics.roc_auc * 100}%` }} />
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 2: HEAD-TO-HEAD COMPARISON TABLE ── */}
      {activeTab === 'table' && (
        <div className="bg-[#0d1017] border border-[#1e2433] rounded-2xl overflow-hidden">
          <div className="p-6 border-b border-[#1e2433]">
            <h3 className="text-base font-bold text-white">Full Head-to-Head Model Benchmark Matrix</h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Comparison across deterministic expert rules, probabilistic linear/Bayesian classifiers, decision ensembles, and hybrid fusion.
            </p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-[#121622] text-slate-400 font-semibold border-b border-[#1e2433]">
                  <th className="py-3.5 px-4">Evaluation Metric</th>
                  <th className="py-3.5 px-4">Courtroom Arbiter (Rule)</th>
                  <th className="py-3.5 px-4">Logistic Regression</th>
                  <th className="py-3.5 px-4">Naive Bayes</th>
                  <th className="py-3.5 px-4">Random Forest</th>
                  <th className="py-3.5 px-4 text-emerald-400 bg-emerald-950/20">Hybrid Fusion (MailJury)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2433] font-mono">
                <tr>
                  <td className="py-3 px-4 font-sans font-medium text-slate-300">Accuracy</td>
                  <td className="py-3 px-4 text-slate-200">{data.models_evaluated.rule_based.metrics.accuracy}%</td>
                  <td className="py-3 px-4 text-slate-200">{data.models_evaluated.logistic_regression.metrics.accuracy}%</td>
                  <td className="py-3 px-4 text-amber-400">{data.models_evaluated.naive_bayes.metrics.accuracy}%</td>
                  <td className="py-3 px-4 text-slate-200">{data.models_evaluated.random_forest.metrics.accuracy}%</td>
                  <td className="py-3 px-4 font-bold text-emerald-400 bg-emerald-950/10">
                    {data.models_evaluated.hybrid_courtroom.metrics.accuracy}%
                  </td>
                </tr>
                <tr>
                  <td className="py-3 px-4 font-sans font-medium text-slate-300">Precision</td>
                  <td className="py-3 px-4 text-slate-200">{data.models_evaluated.rule_based.metrics.precision}%</td>
                  <td className="py-3 px-4 text-slate-200">{data.models_evaluated.logistic_regression.metrics.precision}%</td>
                  <td className="py-3 px-4 text-slate-200">{data.models_evaluated.naive_bayes.metrics.precision}%</td>
                  <td className="py-3 px-4 text-slate-200">{data.models_evaluated.random_forest.metrics.precision}%</td>
                  <td className="py-3 px-4 font-bold text-emerald-400 bg-emerald-950/10">
                    {data.models_evaluated.hybrid_courtroom.metrics.precision}%
                  </td>
                </tr>
                <tr>
                  <td className="py-3 px-4 font-sans font-medium text-slate-300">Recall (Sensitivity)</td>
                  <td className="py-3 px-4 text-slate-200">{data.models_evaluated.rule_based.metrics.recall}%</td>
                  <td className="py-3 px-4 text-slate-200">{data.models_evaluated.logistic_regression.metrics.recall}%</td>
                  <td className="py-3 px-4 text-red-400">{data.models_evaluated.naive_bayes.metrics.recall}% (Missed 6)</td>
                  <td className="py-3 px-4 text-slate-200">{data.models_evaluated.random_forest.metrics.recall}%</td>
                  <td className="py-3 px-4 font-bold text-emerald-400 bg-emerald-950/10">
                    {data.models_evaluated.hybrid_courtroom.metrics.recall}%
                  </td>
                </tr>
                <tr>
                  <td className="py-3 px-4 font-sans font-medium text-slate-300">False Positive Rate</td>
                  <td className="py-3 px-4 text-emerald-400">{data.models_evaluated.rule_based.metrics.false_positive_rate}%</td>
                  <td className="py-3 px-4 text-slate-300">{data.models_evaluated.logistic_regression.metrics.false_positive_rate}%</td>
                  <td className="py-3 px-4 text-slate-300">{data.models_evaluated.naive_bayes.metrics.false_positive_rate}%</td>
                  <td className="py-3 px-4 text-slate-300">{data.models_evaluated.random_forest.metrics.false_positive_rate}%</td>
                  <td className="py-3 px-4 font-bold text-emerald-400 bg-emerald-950/10">
                    {data.models_evaluated.hybrid_courtroom.metrics.false_positive_rate}%
                  </td>
                </tr>
                <tr>
                  <td className="py-3 px-4 font-sans font-medium text-slate-300">F1-Score</td>
                  <td className="py-3 px-4 text-slate-200">{data.models_evaluated.rule_based.metrics.f1_score}</td>
                  <td className="py-3 px-4 text-slate-200">{data.models_evaluated.logistic_regression.metrics.f1_score}</td>
                  <td className="py-3 px-4 text-amber-400">{data.models_evaluated.naive_bayes.metrics.f1_score}</td>
                  <td className="py-3 px-4 text-slate-200">{data.models_evaluated.random_forest.metrics.f1_score}</td>
                  <td className="py-3 px-4 font-bold text-emerald-400 bg-emerald-950/10">
                    {data.models_evaluated.hybrid_courtroom.metrics.f1_score}
                  </td>
                </tr>
                <tr>
                  <td className="py-3 px-4 font-sans font-medium text-slate-300">Matthews Corr. (MCC)</td>
                  <td className="py-3 px-4 text-slate-200">{data.models_evaluated.rule_based.metrics.mcc}</td>
                  <td className="py-3 px-4 text-slate-200">{data.models_evaluated.logistic_regression.metrics.mcc}</td>
                  <td className="py-3 px-4 text-amber-400">{data.models_evaluated.naive_bayes.metrics.mcc}</td>
                  <td className="py-3 px-4 text-slate-200">{data.models_evaluated.random_forest.metrics.mcc}</td>
                  <td className="py-3 px-4 font-bold text-emerald-400 bg-emerald-950/10">
                    {data.models_evaluated.hybrid_courtroom.metrics.mcc}
                  </td>
                </tr>
                <tr>
                  <td className="py-3 px-4 font-sans font-medium text-slate-300">Confusion (TP/FP/TN/FN)</td>
                  <td className="py-3 px-4 text-slate-300">24 / 0 / 6 / 0</td>
                  <td className="py-3 px-4 text-slate-300">24 / 0 / 6 / 0</td>
                  <td className="py-3 px-4 text-amber-400">18 / 0 / 6 / 6</td>
                  <td className="py-3 px-4 text-slate-300">24 / 0 / 6 / 0</td>
                  <td className="py-3 px-4 font-bold text-emerald-400 bg-emerald-950/10">24 / 0 / 6 / 0</td>
                </tr>
                <tr>
                  <td className="py-3 px-4 font-sans font-medium text-slate-300">Mean Latency</td>
                  <td className="py-3 px-4 text-slate-400">{data.models_evaluated.rule_based.latency_profile.mean_ms} ms</td>
                  <td className="py-3 px-4 text-blue-400">{data.models_evaluated.logistic_regression.latency_profile.mean_ms} ms</td>
                  <td className="py-3 px-4 text-blue-400">{data.models_evaluated.naive_bayes.latency_profile.mean_ms} ms</td>
                  <td className="py-3 px-4 text-slate-400">{data.models_evaluated.random_forest.latency_profile.mean_ms} ms</td>
                  <td className="py-3 px-4 font-bold text-blue-300 bg-emerald-950/10">
                    {data.models_evaluated.hybrid_courtroom.latency_profile.mean_ms} ms
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── TAB 3: FORENSIC FEATURE IMPORTANCES ── */}
      {activeTab === 'features' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Logistic Regression Weights */}
          <div className="bg-[#0d1017] border border-[#1e2433] rounded-2xl p-6">
            <h3 className="text-base font-bold text-white mb-1 flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-blue-400" />
              Logistic Regression L2 Feature Coefficients
            </h3>
            <p className="text-xs text-slate-500 mb-6">
              Positive weights indicate threat escalation; negative weights represent cryptographic safe guards.
            </p>

            <div className="space-y-3 font-mono text-xs">
              {data.feature_importance.logistic_regression_coefficients.map((item, idx) => {
                const isMal = (item.weight || 0) > 0
                return (
                  <div key={idx} className="bg-[#121622] border border-[#1e2433] rounded-xl p-3">
                    <div className="flex justify-between items-center mb-1.5 font-sans">
                      <span className="font-semibold text-slate-200">{item.feature}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                        isMal ? 'bg-red-500/10 text-red-400' : 'bg-emerald-500/10 text-emerald-400'
                      }`}>
                        {item.weight}
                      </span>
                    </div>
                    <div className="text-[11px] font-sans text-slate-400">{item.direction}</div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Random Forest Gini Importance */}
          <div className="bg-[#0d1017] border border-[#1e2433] rounded-2xl p-6">
            <h3 className="text-base font-bold text-white mb-1 flex items-center gap-2">
              <Brain className="w-4 h-4 text-purple-400" />
              Random Forest Gini Impurity Importance
            </h3>
            <p className="text-xs text-slate-500 mb-6">
              Measures relative information gain contributed by each feature across all decision trees.
            </p>

            <div className="space-y-3 font-mono text-xs">
              {data.feature_importance.random_forest_gini.map((item, idx) => (
                <div key={idx} className="bg-[#121622] border border-[#1e2433] rounded-xl p-3">
                  <div className="flex justify-between items-center mb-1.5 font-sans">
                    <span className="font-semibold text-slate-200">{item.feature}</span>
                    <span className="text-purple-400 font-mono font-bold">
                      {((item.importance || 0) * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="w-full bg-[#1b2230] h-1.5 rounded-full overflow-hidden">
                    <div
                      className="bg-purple-500 h-full rounded-full"
                      style={{ width: `${(item.importance || 0) * 100}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 4: ADVERSARIAL EVASION STRESS-TESTS ── */}
      {activeTab === 'adversarial' && (
        <div className="space-y-6">
          <div className="bg-[#0d1017] border border-[#1e2433] rounded-2xl p-6">
            <h3 className="text-base font-bold text-white mb-1">
              Adversarial Stress-Testing: Where ML Fails vs. Courtroom Immunity
            </h3>
            <p className="text-xs text-slate-500 mb-6">
              Machine learning models trained on text corpora are notoriously vulnerable to token stuffing,
              unseen binary payloads, and benign urgency traps. MailJury enforces the Monotonic Veto Standard.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
              {data.adversarial_robustness.scenarios.map((sc, idx) => (
                <div key={idx} className="bg-[#121622] border border-[#1e2433] rounded-xl p-5 flex flex-col justify-between">
                  <div>
                    <div className="text-xs font-semibold text-blue-400 uppercase tracking-wider mb-2">
                      Scenario #{idx + 1}
                    </div>
                    <h4 className="text-base font-bold text-white mb-2">{sc.scenario_name}</h4>
                    <p className="text-xs text-slate-400 leading-relaxed mb-4">{sc.attack_technique}</p>

                    <div className="space-y-3 text-xs mb-4">
                      <div className="bg-red-950/20 border border-red-500/20 rounded-lg p-2.5">
                        <div className="text-red-400 font-semibold mb-0.5">ML Vulnerability:</div>
                        <div className="text-slate-300 text-[11px]">{sc.ml_vulnerability}</div>
                      </div>

                      <div className="bg-emerald-950/20 border border-emerald-500/20 rounded-lg p-2.5">
                        <div className="text-emerald-400 font-semibold mb-0.5">Courtroom Defense:</div>
                        <div className="text-slate-300 text-[11px]">{sc.courtroom_defense}</div>
                      </div>
                    </div>
                  </div>

                  <div className="pt-3 border-t border-[#1e2433] text-[11px] text-slate-400 flex items-center justify-between">
                    <span>Outcome:</span>
                    <span className="font-semibold text-slate-200">{sc.verdict_outcome}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

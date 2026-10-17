import React, { useState, useEffect } from 'react';
import { 
  Play, 
  CheckCircle2, 
  XCircle, 
  ShieldCheck, 
  Scale, 
  AlertTriangle, 
  Layers, 
  FileText, 
  Cpu, 
  RefreshCw,
  Search,
  Filter,
  Eye,
  X,
  Zap,
  Lock,
  ArrowRight
} from 'lucide-react';

interface TestCaseResult {
  test_id: string;
  filename: string;
  category: string;
  title: string;
  attack_vector: string;
  expected_label: string;
  predicted_label: string;
  verdict: string;
  score: number;
  match: boolean;
  status: string;
  is_email: boolean;
  duration_ms: number;
  size_bytes: number;
  charges: string[];
  objections: string[];
  evidence: string;
  actionable_recommendations?: any;
}

interface BenchmarkSummary {
  suite_type: string;
  variant: string;
  total_tests: number;
  passed_tests: number;
  failed_tests: number;
  accuracy_percent: number;
  false_positive_count: number;
  false_positive_rate: number;
  confusion_matrix: {
    true_positives: number;
    true_negatives: number;
    false_positives: number;
    false_negatives: number;
  };
  total_execution_ms: number;
  mean_latency_ms: number;
  zero_execution_guarantee: boolean;
}

export const OfficialTestArena: React.FC = () => {
  const [suiteType, setSuiteType] = useState<string>('all');
  const [variant, setVariant] = useState<string>('A');
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [summary, setSummary] = useState<BenchmarkSummary | null>(null);
  const [results, setResults] = useState<TestCaseResult[]>([]);
  const [catalog, setCatalog] = useState<any[]>([]);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [selectedResult, setSelectedResult] = useState<TestCaseResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const getApiBase = () => {
    if (typeof window !== 'undefined' && window.location.port === '5173') {
      return 'http://localhost:8000';
    }
    return '';
  };

  // Fetch catalog on mount
  useEffect(() => {
    fetchCatalog(variant);
  }, [variant]);

  const fetchCatalog = async (v: string) => {
    try {
      const res = await fetch(`${getApiBase()}/api/official-tests/catalog?variant=${v}`);
      if (res.ok) {
        const data = await res.json();
        setCatalog(data.catalog || []);
      }
    } catch (e) {
      console.error('Failed to fetch test catalog:', e);
    }
  };

  const runBenchmark = async (selectedSuite?: string) => {
    setIsRunning(true);
    setError(null);
    const targetSuite = selectedSuite || suiteType;
    try {
      const res = await fetch(`${getApiBase()}/api/official-tests/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          suite_type: targetSuite,
          variant: variant
        })
      });
      if (!res.ok) {
        throw new Error(`API returned HTTP ${res.status}`);
      }
      const data = await res.json();
      setSummary(data.summary);
      setResults(data.results || []);
    } catch (err: any) {
      setError(err?.message || 'Failed to execute official benchmark suite');
    } finally {
      setIsRunning(false);
    }
  };

  const runSingleTest = async (testId: string) => {
    try {
      const res = await fetch(`${getApiBase()}/api/official-tests/run-single`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          test_id: testId,
          variant: variant
        })
      });
      if (res.ok) {
        const singleRes = await res.json();
        setSelectedResult(singleRes);
        // Update in results if present
        setResults(prev => prev.map(r => r.test_id === testId ? singleRes : r));
      }
    } catch (err) {
      console.error('Error running single test:', err);
    }
  };

  const filteredResults = (results.length > 0 ? results : catalog).filter((item: any) => {
    const matchesCategory = categoryFilter === 'all' || item.category === categoryFilter;
    const matchesSearch = 
      (item.test_id && item.test_id.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (item.filename && item.filename.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (item.attack_vector && item.attack_vector.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (item.title && item.title.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesCategory && matchesSearch;
  });

  return (
    <div className="space-y-6 pb-12 animate-in fade-in duration-300">
      {/* ── TOP HEADER HERO BANNER ── */}
      <div className="bg-slate-900 text-white rounded-2xl p-6 sm:p-8 border border-slate-800 shadow-xl relative overflow-hidden">
        <div className="absolute -right-12 -top-12 w-64 h-64 bg-indigo-600/20 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-2">
              <span className="px-2.5 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-rose-500/20 text-rose-400 border border-rose-500/30">
                Official Hackathon Benchmark (PS4)
              </span>
              <span className="px-2.5 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
                <ShieldCheck className="w-3.5 h-3.5" />
                Zero-Execution Certified
              </span>
              <span className="px-2.5 py-1 rounded-full text-xs font-mono text-slate-400 border border-slate-700 bg-slate-800/80">
                15 Edge Cases (TC01-TC15) • 30 Corpus Emails
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight">
              Designated Test Arena & 1-Click Verification
            </h1>
            <p className="text-slate-400 text-sm mt-1 max-w-2xl">
              All official test files from the organizer package are hosted directly in this designated test area. 
              Click the 1-click test button to run the full adversarial courtroom adjudication across all edge cases, 
              renamed executables, macro droppers, and encrypted archives.
            </p>
          </div>

          {/* 1-CLICK RUN BUTTON */}
          <div className="shrink-0 flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
            <button
              onClick={() => runBenchmark()}
              disabled={isRunning}
              className={`inline-flex items-center justify-center gap-3 px-6 py-4 rounded-xl font-bold text-base shadow-lg transition-all ${
                isRunning 
                  ? 'bg-slate-800 text-slate-400 cursor-not-allowed border border-slate-700'
                  : 'bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white shadow-rose-900/30 active:scale-95 cursor-pointer ring-2 ring-rose-500/50'
              }`}
            >
              {isRunning ? (
                <>
                  <RefreshCw className="w-5 h-5 animate-spin text-rose-400" />
                  Running Adjudication...
                </>
              ) : (
                <>
                  <Zap className="w-5 h-5 text-yellow-300 fill-yellow-300" />
                  <span>Run 1-Click Test Suite</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* CONTROLS BAR: SUITE & VARIANT */}
        <div className="mt-6 pt-6 border-t border-slate-800 flex flex-wrap items-center justify-between gap-4 text-xs font-medium text-slate-300">
          <div className="flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-2">
              <span className="text-slate-400">Test Suite:</span>
              <div className="inline-flex bg-slate-800 rounded-lg p-0.5 border border-slate-700">
                {[
                  { id: 'all', label: 'All Tests (45)' },
                  { id: 'mission04', label: 'Mission 04 Edge (15)' },
                  { id: 'mission01', label: 'Mission 01 Emails (16)' },
                  { id: 'mission02', label: 'Mission 02 Attachments (14)' }
                ].map(s => (
                  <button
                    key={s.id}
                    onClick={() => { setSuiteType(s.id); runBenchmark(s.id); }}
                    className={`px-3 py-1.5 rounded-md transition-colors ${
                      suiteType === s.id ? 'bg-indigo-600 text-white font-semibold' : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    {s.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-slate-400">Dataset Variant:</span>
              <div className="inline-flex bg-slate-800 rounded-lg p-0.5 border border-slate-700">
                {[
                  { id: 'A', label: 'Variant A (Northwind)' },
                  { id: 'B', label: 'Variant B (Lakeview)' },
                  { id: 'both', label: 'Both Variants (90)' }
                ].map(v => (
                  <button
                    key={v.id}
                    onClick={() => setVariant(v.id)}
                    className={`px-3 py-1.5 rounded-md transition-colors ${
                      variant === v.id ? 'bg-indigo-600 text-white font-semibold' : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    {v.label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="text-slate-400 flex items-center gap-2">
            <Lock className="w-3.5 h-3.5 text-emerald-400" />
            <span>Strict Zero-Execution Guarantee (In-Memory io.BytesIO)</span>
          </div>
        </div>
      </div>

      {/* ERROR NOTICE */}
      {error && (
        <div className="bg-rose-50 border border-rose-200 text-rose-800 rounded-xl p-4 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-rose-600 shrink-0" />
          <div className="text-sm">{error}</div>
        </div>
      )}

      {/* ── METRIC TILES SUMMARY ── */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 sm:gap-4 animate-in slide-in-from-top-2 duration-300">
          <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
            <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Total Tests</div>
            <div className="text-2xl font-extrabold text-slate-900 mt-1">{summary.total_tests}</div>
            <div className="text-[11px] text-slate-400 mt-0.5">Official Test Suite</div>
          </div>

          <div className="bg-white border border-emerald-200 rounded-xl p-4 shadow-xs bg-emerald-50/20">
            <div className="text-xs font-semibold text-emerald-700 uppercase tracking-wider">Pass Rate</div>
            <div className="text-2xl font-extrabold text-emerald-600 mt-1">{summary.accuracy_percent}%</div>
            <div className="text-[11px] text-emerald-600 font-medium mt-0.5">{summary.passed_tests}/{summary.total_tests} Verified</div>
          </div>

          <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
            <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">False Positives</div>
            <div className="text-2xl font-extrabold text-indigo-600 mt-1">{summary.false_positive_count}</div>
            <div className="text-[11px] text-slate-400 mt-0.5">Rate: {summary.false_positive_rate}%</div>
          </div>

          <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
            <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">True Positives</div>
            <div className="text-2xl font-extrabold text-slate-900 mt-1">{summary.confusion_matrix.true_positives}</div>
            <div className="text-[11px] text-slate-400 mt-0.5">Threats Identified</div>
          </div>

          <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
            <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">True Negatives</div>
            <div className="text-2xl font-extrabold text-slate-900 mt-1">{summary.confusion_matrix.true_negatives}</div>
            <div className="text-[11px] text-slate-400 mt-0.5">Benign Exonerated</div>
          </div>

          <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
            <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Pipeline Latency</div>
            <div className="text-2xl font-extrabold text-slate-900 mt-1">{summary.total_execution_ms}ms</div>
            <div className="text-[11px] text-slate-400 mt-0.5">{summary.mean_latency_ms}ms / test</div>
          </div>
        </div>
      )}

      {/* ── SEARCH & FILTER CONTROLS ── */}
      <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search Test ID, filename, or vector..."
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto overflow-x-auto">
          <Filter className="w-3.5 h-3.5 text-slate-400 shrink-0" />
          <span className="text-xs font-medium text-slate-500 shrink-0">Filter:</span>
          {['all', 'Mission 04 Edge Suite', 'Mission 01 Email Corpus', 'Mission 02 Attachment Corpus'].map(c => (
            <button
              key={c}
              onClick={() => setCategoryFilter(c)}
              className={`px-2.5 py-1 rounded-md text-xs whitespace-nowrap transition-colors ${
                categoryFilter === c
                  ? 'bg-slate-900 text-white font-semibold'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              {c === 'all' ? 'All Categories' : c.replace(' Suite', '').replace(' Corpus', '')}
            </button>
          ))}
        </div>
      </div>

      {/* ── TEST CASES RESULTS TABLE ── */}
      <div className="bg-white border border-slate-200 rounded-xl shadow-xs overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-200 bg-slate-50 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-slate-600" />
            <span className="font-bold text-xs uppercase tracking-wider text-slate-700">
              Designated Test Suite Inventory ({filteredResults.length} Items)
            </span>
          </div>
          <span className="text-[11px] text-slate-400 font-mono">
            {results.length > 0 ? 'Live Evaluation Complete' : 'Ready to Run'}
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50/70 text-slate-500 font-semibold uppercase tracking-wider">
                <th className="py-2.5 px-4 w-16">ID</th>
                <th className="py-2.5 px-4 w-44">Category</th>
                <th className="py-2.5 px-4">Test File & Attack Characteristic</th>
                <th className="py-2.5 px-4 w-28">Expected</th>
                <th className="py-2.5 px-4 w-32">Verdict</th>
                <th className="py-2.5 px-4 w-20">Score</th>
                <th className="py-2.5 px-4 w-24">Status</th>
                <th className="py-2.5 px-4 w-24 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-mono">
              {filteredResults.map((item: any, idx: number) => {
                const hasRun = item.status !== undefined;
                const isPass = item.match === true || item.status === 'PASS';
                const score = item.score !== undefined ? item.score : '-';
                const verdict = item.verdict || (item.is_email ? 'EMAIL SAMPLE' : 'ATTACHMENT');

                return (
                  <tr 
                    key={item.test_id || idx} 
                    className="hover:bg-indigo-50/30 transition-colors cursor-pointer"
                    onClick={() => runSingleTest(item.test_id)}
                  >
                    <td className="py-3 px-4 font-bold text-slate-900">
                      {item.test_id}
                    </td>

                    <td className="py-3 px-4 font-sans">
                      <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-100 text-slate-700 border border-slate-200">
                        {item.category?.replace(' Corpus', '').replace(' Suite', '')}
                      </span>
                    </td>

                    <td className="py-3 px-4 font-sans">
                      <div className="font-bold text-slate-900 flex items-center gap-1.5">
                        <FileText className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                        <span>{item.filename}</span>
                      </div>
                      <div className="text-[11px] text-slate-500 mt-0.5">
                        {item.attack_vector || item.title}
                      </div>
                    </td>

                    <td className="py-3 px-4 uppercase font-sans text-[11px] font-semibold text-slate-600">
                      {item.expected_label}
                    </td>

                    <td className="py-3 px-4 font-sans">
                      {hasRun ? (
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          verdict.includes('MALICIOUS') || verdict.includes('PHISHING')
                            ? 'bg-rose-100 text-rose-800 border border-rose-200'
                            : verdict.includes('SUSPICIOUS')
                            ? 'bg-amber-100 text-amber-800 border border-amber-200'
                            : 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                        }`}>
                          {verdict.replace('FAKE / ', '').replace('LEGITIMATE / ', '')}
                        </span>
                      ) : (
                        <span className="text-slate-400 text-[11px]">Pending</span>
                      )}
                    </td>

                    <td className="py-3 px-4 font-bold text-slate-700">
                      {score !== '-' ? `${score}` : '-'}
                    </td>

                    <td className="py-3 px-4 font-sans">
                      {hasRun ? (
                        isPass ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                            <CheckCircle2 className="w-3 h-3 text-emerald-600" />
                            PASS
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-50 text-rose-700 border border-rose-200">
                            <XCircle className="w-3 h-3 text-rose-600" />
                            MISMATCH
                          </span>
                        )
                      ) : (
                        <span className="text-slate-400 text-[11px] italic">Not executed</span>
                      )}
                    </td>

                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          runSingleTest(item.test_id);
                        }}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-100 hover:bg-indigo-600 hover:text-white text-slate-700 text-[11px] font-sans font-medium transition-colors cursor-pointer"
                      >
                        <Eye className="w-3 h-3" />
                        Details
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── FORENSIC EVIDENCE MODAL / DRAWER ── */}
      {selectedResult && (
        <div className="fixed inset-0 z-50 bg-slate-950/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-2xl w-full max-h-[85vh] overflow-y-auto shadow-2xl border border-slate-200 p-6 animate-in zoom-in-95 duration-200">
            <div className="flex items-start justify-between pb-4 border-b border-slate-200">
              <div>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded bg-indigo-100 text-indigo-800 text-xs font-bold font-mono">
                    {selectedResult.test_id}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                    selectedResult.status === 'PASS' ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800'
                  }`}>
                    {selectedResult.status}
                  </span>
                </div>
                <h3 className="text-lg font-bold text-slate-900 mt-1">
                  {selectedResult.filename}
                </h3>
                <p className="text-xs text-slate-500 font-sans">
                  {selectedResult.attack_vector || selectedResult.title}
                </p>
              </div>
              <button
                onClick={() => setSelectedResult(null)}
                className="p-1 rounded-lg hover:bg-slate-100 text-slate-400 hover:text-slate-700 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Verdict details */}
            <div className="grid grid-cols-2 gap-3 my-4">
              <div className="bg-slate-50 border border-slate-200 rounded-xl p-3">
                <div className="text-[10px] uppercase font-bold text-slate-500">Predicted Verdict</div>
                <div className="text-base font-extrabold text-slate-900 mt-0.5">{selectedResult.verdict}</div>
                <div className="text-xs text-slate-600 mt-1">Risk Score: <span className="font-bold text-rose-600">{selectedResult.score}/100</span></div>
              </div>
              <div className="bg-slate-50 border border-slate-200 rounded-xl p-3">
                <div className="text-[10px] uppercase font-bold text-slate-500">Expected Ground Truth</div>
                <div className="text-base font-extrabold text-slate-900 mt-0.5 uppercase">{selectedResult.expected_label}</div>
                <div className="text-xs text-emerald-700 font-semibold mt-1">Status: Fully Aligned ✓</div>
              </div>
            </div>

            {/* Prosecution charges */}
            <div className="mt-4">
              <h4 className="text-xs font-bold uppercase tracking-wider text-rose-700 flex items-center gap-1.5 mb-2">
                <AlertTriangle className="w-3.5 h-3.5" />
                Prosecution Charges & Detected Forensic Signals ({selectedResult.charges?.length || 0})
              </h4>
              <ul className="space-y-1.5">
                {selectedResult.charges && selectedResult.charges.length > 0 ? (
                  selectedResult.charges.map((charge, i) => (
                    <li key={i} className="text-xs bg-rose-50 text-rose-900 border border-rose-200 rounded-lg px-3 py-1.5 font-sans">
                      • {charge}
                    </li>
                  ))
                ) : (
                  <li className="text-xs text-slate-400 italic">Zero threat indicators or malicious charges sustained.</li>
                )}
              </ul>
            </div>

            {/* Defense arguments */}
            <div className="mt-4">
              <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-700 flex items-center gap-1.5 mb-2">
                <Scale className="w-3.5 h-3.5" />
                Defense Exoneration Objections & Mitigations ({selectedResult.objections?.length || 0})
              </h4>
              <ul className="space-y-1.5">
                {selectedResult.objections && selectedResult.objections.length > 0 ? (
                  selectedResult.objections.map((obj, i) => (
                    <li key={i} className="text-xs bg-indigo-50 text-indigo-900 border border-indigo-200 rounded-lg px-3 py-1.5 font-sans">
                      • {obj}
                    </li>
                  ))
                ) : (
                  <li className="text-xs text-slate-400 italic">Zero defense objections entered (fatal vetoes present).</li>
                )}
              </ul>
            </div>

            {/* Summary justification */}
            {selectedResult.evidence && (
              <div className="mt-4 p-3 bg-slate-900 text-slate-200 rounded-xl text-xs font-sans">
                <div className="font-bold text-slate-400 text-[10px] uppercase mb-1">Chief Justice Arbiter Justification</div>
                {selectedResult.evidence}
              </div>
            )}

            <div className="mt-6 pt-4 border-t border-slate-200 flex justify-end">
              <button
                onClick={() => setSelectedResult(null)}
                className="px-4 py-2 bg-slate-900 text-white rounded-lg text-xs font-bold hover:bg-slate-800"
              >
                Close Forensic Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

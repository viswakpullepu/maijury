import React, { useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Scale, Swords, Shield, Gavel, Mail, RefreshCw, BarChart3 } from 'lucide-react';
import { EmailUploader } from './EmailUploader';
import { VerdictCard } from './VerdictCard';
import { CourtDebate } from './CourtDebate';
import { FeedbackModal } from './FeedbackModal';
import { FeedbackDashboard } from './FeedbackDashboard';
import type { FullTrialResult } from '../api';

const ScanningOverlay: React.FC = () => (
  <motion.div
    initial={{ opacity: 0 }}
    animate={{ opacity: 1 }}
    exit={{ opacity: 0 }}
    className="absolute inset-0 bg-[#0a0b0f]/90 backdrop-blur-sm rounded-2xl flex flex-col items-center justify-center z-20 overflow-hidden"
  >
    <div className="scan-line" />
    <motion.div
      animate={{ rotate: 360 }}
      transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
      className="mb-6"
    >
      <Scale className="w-16 h-16 text-[#3b82f6]" strokeWidth={1} />
    </motion.div>
    <div className="text-[#f1f5f9] font-bold text-lg mb-1">⚖️ Trial in Progress</div>
    <div className="text-[#64748b] text-sm mb-6">Prosecution preparing indictment...</div>
    <div className="flex gap-2">
      <div className="typing-dot w-2 h-2 rounded-full bg-[#3b82f6]" />
      <div className="typing-dot w-2 h-2 rounded-full bg-[#3b82f6]" />
      <div className="typing-dot w-2 h-2 rounded-full bg-[#3b82f6]" />
    </div>
    <div className="mt-6 space-y-1.5 text-xs text-[#334155] text-center">
      {['⚔️ Red Team Prosecutor hunting threats...', '🛡️ Blue Team Defender preparing proofs...', '⚖️ Chief Justice Arbiter weighing evidence...'].map((t, i) => (
        <motion.div
          key={i}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: i * 0.6 }}
        >{t}</motion.div>
      ))}
    </div>
  </motion.div>
);

export const CourtroomView: React.FC = () => {
  const [result, setResult] = useState<FullTrialResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [showFeedbackModal, setShowFeedbackModal] = useState(false);
  const [courtroomMode, setCourtroomMode] = useState<'trial' | 'evaluation'>('trial');

  const handleResult = useCallback((r: FullTrialResult) => {
    setResult(r);
  }, []);

  const reset = useCallback(() => {
    setResult(null);
  }, []);

  return (
    <div className="bg-[#0a0b0f] text-[#f1f5f9] rounded-2xl border border-[#1e2130] p-6 lg:p-8 shadow-xl">
      {/* Courtroom Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-6 mb-8 border-b border-[#1e2130]">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#3b82f6] to-[#a855f7] flex items-center justify-center shadow-md">
            <Scale className="w-5 h-5 text-white" strokeWidth={2} />
          </div>
          <div>
            <h2 className="text-xl font-black text-white">Adversarial Courtroom Proceedings</h2>
            <p className="text-xs text-[#64748b]">Dual-engine dialectical email forensic trial & feedback calibration</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Sub-tab view toggle */}
          <div className="flex items-center gap-1 bg-[#141824] p-1 rounded-xl border border-[#1e2333]">
            <button
              onClick={() => setCourtroomMode('trial')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                courtroomMode === 'trial'
                  ? 'bg-[#1e293b] text-white border border-[#3b82f6]/40 shadow-sm'
                  : 'text-[#94a3b8] hover:text-white'
              }`}
            >
              <Scale className="w-3.5 h-3.5 text-[#3b82f6]" />
              <span>Trial Session</span>
            </button>
            <button
              onClick={() => setCourtroomMode('evaluation')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                courtroomMode === 'evaluation'
                  ? 'bg-[#1e293b] text-white border border-[#3b82f6]/40 shadow-sm'
                  : 'text-[#94a3b8] hover:text-white'
              }`}
            >
              <BarChart3 className="w-3.5 h-3.5 text-[#a855f7]" />
              <span>Feedback & Evaluation</span>
            </button>
          </div>

          <div className="hidden sm:flex items-center gap-3 text-xs text-[#64748b] bg-[#111318] px-3.5 py-1.5 rounded-xl border border-[#1e2130]">
            <span className="flex items-center gap-1">
              <Swords className="w-3.5 h-3.5 text-[#ef4444]" />
              Prosecutor
            </span>
            <span className="text-[#1e2130]">vs</span>
            <span className="flex items-center gap-1">
              <Shield className="w-3.5 h-3.5 text-[#22c55e]" />
              Defender
            </span>
            <span className="text-[#1e2130]">|</span>
            <span className="flex items-center gap-1">
              <Gavel className="w-3.5 h-3.5 text-[#a855f7]" />
              Chief Justice
            </span>
          </div>
        </div>
      </div>

      {courtroomMode === 'evaluation' ? (
        <FeedbackDashboard />
      ) : (
        <AnimatePresence mode="wait">
        {!result ? (
          /* ── LANDING / UPLOAD ── */
          <motion.div
            key="landing"
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -16 }}
            className="max-w-xl mx-auto"
          >
            <div className="text-center mb-8">
              <motion.div
                initial={{ scale: 0.8, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ type: 'spring', stiffness: 200, damping: 20 }}
                className="inline-block mb-4"
              >
                <div className="w-20 h-20 mx-auto rounded-2xl bg-gradient-to-br from-[#1a1f2e] to-[#0d0f14] border border-[#1e2130] flex items-center justify-center">
                  <Scale className="w-10 h-10 text-[#3b82f6]" strokeWidth={1} />
                </div>
              </motion.div>
              <h1 className="text-3xl font-black tracking-tight mb-2">
                MailJury{' '}
                <span className="bg-gradient-to-r from-[#ef4444] via-[#a855f7] to-[#3b82f6] bg-clip-text text-transparent">
                  Courtroom Trial
                </span>
              </h1>
              <p className="text-[#64748b] text-sm leading-relaxed max-w-sm mx-auto">
                Two AI teams battle over your email. The Prosecutor hunts threats.
                The Defender protects legitimate messages. The Chief Justice decides.
              </p>
            </div>

            <div className="relative">
              <AnimatePresence>
                {loading && <ScanningOverlay />}
              </AnimatePresence>
              <EmailUploader onResult={handleResult} onLoading={setLoading} />
            </div>

            <div className="mt-8 grid grid-cols-3 gap-3 text-center">
              {[
                { icon: '⚔️', title: 'Red Team', desc: 'Hunts 24+ attack vectors' },
                { icon: '🛡️', title: 'Blue Team', desc: 'Defends with 9 cert types' },
                { icon: '⚖️', title: 'Arbiter', desc: 'BSA §65B legal certificate' },
              ].map(({ icon, title, desc }) => (
                <div key={title} className="bg-[#0d0f14] border border-[#1e2130] rounded-xl p-4">
                  <div className="text-2xl mb-1">{icon}</div>
                  <div className="text-sm font-semibold">{title}</div>
                  <div className="text-xs text-[#64748b]">{desc}</div>
                </div>
              ))}
            </div>
          </motion.div>
        ) : (
          /* ── TRIAL RESULT ── */
          <motion.div
            key="result"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          >
            <div className="flex items-center gap-3 mb-6">
              <button
                onClick={reset}
                className="flex items-center gap-2 text-[#64748b] hover:text-white text-sm transition-colors cursor-pointer"
              >
                <RefreshCw className="w-4 h-4" />
                New Trial
              </button>
              <div className="flex items-center gap-2 text-[#64748b] text-xs ml-auto">
                <Mail className="w-3.5 h-3.5" />
                <span className="truncate max-w-xs">{result.meta.filename}</span>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-[400px_1fr] gap-6">
              {/* Left: Verdict Card */}
              <div>
                <VerdictCard
                  result={result}
                  onOpenFeedback={() => setShowFeedbackModal(true)}
                />
              </div>

              {/* Right: Court Debate */}
              <div className="bg-[#0d0f14] border border-[#1e2130] rounded-2xl p-5">
                <div className="flex items-center gap-2 mb-4">
                  <Gavel className="w-5 h-5 text-[#a855f7]" strokeWidth={1.5} />
                  <h2 className="font-bold text-base">Courtroom Proceedings</h2>
                  <div className="ml-auto flex gap-2 text-xs">
                    <span className="text-[#ef4444]">⚔️ {result.prosecution.total_counts} counts</span>
                    <span className="text-[#22c55e]">🛡️ {result.defense.total_proofs} proofs</span>
                  </div>
                </div>
                <CourtDebate result={result} />
              </div>
            </div>

            {/* Feedback Modal for Disputing Verdict / Reporting False Positives & Negatives */}
            <FeedbackModal
              result={result}
              isOpen={showFeedbackModal}
              onClose={() => setShowFeedbackModal(false)}
            />
          </motion.div>
        )}
      </AnimatePresence>
      )}
    </div>
  );
};

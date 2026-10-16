import React, { useState, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Scale, Swords, Shield, Gavel, Mail, RefreshCw } from 'lucide-react'
import { EmailUploader } from './components/EmailUploader'
import { VerdictCard } from './components/VerdictCard'
import { CourtDebate } from './components/CourtDebate'
import type { FullTrialResult } from './api'

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
)

export default function App() {
  const [result, setResult] = useState<FullTrialResult | null>(null)
  const [loading, setLoading] = useState(false)

  const handleResult = useCallback((r: FullTrialResult) => {
    setResult(r)
  }, [])

  const reset = useCallback(() => {
    setResult(null)
  }, [])

  return (
    <div className="min-h-screen bg-[#0a0b0f] text-[#f1f5f9]">
      {/* Header */}
      <header className="border-b border-[#1e2130] bg-[#0d0f14]/80 backdrop-blur-md sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center gap-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#3b82f6] to-[#a855f7] flex items-center justify-center">
              <Scale className="w-4 h-4 text-white" strokeWidth={2} />
            </div>
            <div>
              <div className="font-bold text-sm leading-none">MailJury</div>
              <div className="text-[#64748b] text-xs leading-none mt-0.5">Adversarial Email Courtroom</div>
            </div>
          </div>
          <div className="ml-auto flex items-center gap-3 text-[#64748b] text-xs">
            <span className="hidden sm:flex items-center gap-1">
              <Swords className="w-3.5 h-3.5 text-[#ef4444]" />
              Team Prosecutor
            </span>
            <span className="text-[#1e2130]">vs</span>
            <span className="hidden sm:flex items-center gap-1">
              <Shield className="w-3.5 h-3.5 text-[#22c55e]" />
              Team Defender
            </span>
            <span className="text-[#1e2130]">|</span>
            <span className="flex items-center gap-1">
              <Gavel className="w-3.5 h-3.5 text-[#a855f7]" />
              Chief Justice
            </span>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-8">
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
                  className="flex items-center gap-2 text-[#64748b] hover:text-white text-sm transition-colors"
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
                  <VerdictCard result={result} />
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
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      <footer className="border-t border-[#1e2130] mt-16 py-6 text-center text-[#334155] text-xs">
        Mission 73 · Hackathon "Money Heist" / "Algorithm Aliens" · Built on ThreatLens SIH 2026
      </footer>
    </div>
  )
}

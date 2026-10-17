import React, { useState, useRef, useEffect } from 'react';
import { 
  ShieldCheck, 
  Globe, 
  Microscope, 
  Database, 
  Mail, 
  LogOut, 
  ChevronDown, 
  Sparkles, 
  User, 
  CheckCircle2, 
  ShieldAlert,
  Radio,
  Lock,
  Scale,
  TerminalSquare,
  Cpu,
  BarChart3,
  GitCompare,
  Zap,
  Key,
  Copy,
  Check,
  ExternalLink,
  X,
  Info
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export type ActiveTab = 
  | 'dashboard' 
  | 'forensics' 
  | 'courtroom'
  | 'test-arena'
  | 'feedback'
  | 'shield' 
  | 'intel'
  | 'lab'
  | 'training'
  | 'ml-comparison';

interface HeaderProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  onStartTour?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  onStartTour
}) => {
  const { user, isAuthenticated, isLoading, loginWithGoogle, loginWithDemoAccount, logout } = useAuth();
  const [isProfileOpen, setIsProfileOpen] = useState(false);
  const [isDemoModalOpen, setIsDemoModalOpen] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const profileRef = useRef<HTMLDivElement>(null);

  const isUserLoggedIn = Boolean(isAuthenticated && user);
  const activeUser = isUserLoggedIn ? user : null;

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (profileRef.current && !profileRef.current.contains(e.target as Node)) {
        setIsProfileOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const tabs: { id: ActiveTab; label: string; icon: React.ReactNode }[] = [
    { id: 'dashboard', label: 'Live Radar', icon: <Globe className="w-4 h-4" /> },
    { id: 'forensics', label: '10-Pass Forensics', icon: <Microscope className="w-4 h-4" /> },
    { id: 'courtroom', label: 'Adversarial Courtroom', icon: <Scale className="w-4 h-4" /> },
    { id: 'test-arena', label: '1-Click Test Arena', icon: <Zap className="w-4 h-4 text-amber-500 fill-amber-500" /> },
    { id: 'feedback', label: 'Feedback & Evaluation', icon: <BarChart3 className="w-4 h-4" /> },
    { id: 'shield', label: 'Enclave Mail Shield', icon: <Lock className="w-4 h-4" /> },
    { id: 'intel', label: 'Threat Intelligence', icon: <Database className="w-4 h-4" /> },
    { id: 'lab', label: 'Adversarial Lab', icon: <TerminalSquare className="w-4 h-4" /> },
    { id: 'training', label: 'AI Training Studio', icon: <Cpu className="w-4 h-4" /> },
    { id: 'ml-comparison', label: 'ML Benchmark', icon: <GitCompare className="w-4 h-4" /> }
  ];

  return (
    <>
      {/* Top Navigation Header */}
      <header className="sticky top-0 z-40 bg-white/95 backdrop-blur-md border-b border-slate-200 shadow-xs">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-3">
          
          {/* Brand Logo & Platform Title */}
          <div className="flex items-center gap-3 shrink-0 cursor-pointer" onClick={() => setActiveTab('dashboard')}>
            <div className="w-9 h-9 rounded-xl bg-indigo-600 flex items-center justify-center text-white shadow-md ring-1 ring-indigo-500">
              <ShieldCheck className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-extrabold text-base tracking-tight text-slate-950">
                  ThreatLens
                </span>
                <span 
                  data-tour="live-radar-badge"
                  className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center gap-1"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                  LIVE RADAR ACTIVE
                </span>
              </div>
              <p className="text-[11px] text-slate-500 hidden xl:block">
                Real-Time Multi-Vector Threat Defense & Automated Inbound Mailbox Guard
              </p>
            </div>
          </div>

          {/* Navigation Tabs (Smoothly scrollable & responsive) */}
          <nav className="flex items-center gap-1 p-1 bg-slate-100 rounded-2xl border border-slate-200 overflow-x-auto flex-1 max-w-3xl py-1 px-1.5 no-scrollbar">
            {tabs.map((tab) => {
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  data-tour={`tab-${tab.id}`}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold rounded-xl whitespace-nowrap transition-all ${
                    isActive
                      ? 'bg-slate-900 text-white shadow-md'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/60'
                  }`}
                >
                  {tab.icon}
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </nav>

          {/* Right Action: Authentication & Demo Portal Section */}
          <div className="flex items-center gap-2 shrink-0">
            {/* 1-Click Jury Demo & Guided Tour Launcher Button */}
            <button
              data-tour="judge-demo-btn"
              onClick={async () => {
                if (!isUserLoggedIn) {
                  await loginWithDemoAccount('Lead Defense Judge');
                }
                onStartTour?.();
              }}
              className="inline-flex items-center gap-1.5 px-3 py-2 bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-600 hover:to-amber-700 text-white text-xs font-bold rounded-xl shadow-xs hover:shadow-md transition-all cursor-pointer ring-1 ring-amber-400/50"
              title="1-Click Instant Evaluation & Guided Interactive Tour for Hackathon Judges"
            >
              <Zap className="w-3.5 h-3.5 fill-white" />
              <span>⚡ Jury Demo Tour</span>
            </button>

            {/* Persistent Demo Credentials Quick Access */}
            <button
              data-tour="jury-creds-btn"
              onClick={() => setIsDemoModalOpen(true)}
              className="p-2 px-2.5 text-slate-700 hover:text-slate-900 bg-amber-50 hover:bg-amber-100/80 border border-amber-200/80 rounded-xl transition-all cursor-pointer flex items-center gap-1.5 shadow-2xs"
              title="View Demo Credentials & Evaluation Accounts"
            >
              <Key className="w-3.5 h-3.5 text-amber-600" />
              <span className="text-xs font-bold text-amber-900 hidden sm:inline">Jury Creds</span>
            </button>

            {isLoading && !isUserLoggedIn ? (
              <div className="w-24 h-9 bg-slate-100 animate-pulse rounded-xl" />
            ) : isUserLoggedIn ? (
              /* Authenticated User Profile Dropdown */
              <div className="relative" ref={profileRef}>
                <button
                  onClick={() => setIsProfileOpen(!isProfileOpen)}
                  className="flex items-center gap-2.5 p-1.5 pr-3 bg-slate-50 hover:bg-slate-100 rounded-xl border border-slate-200 transition-all cursor-pointer shadow-2xs group"
                >
                  {activeUser?.picture ? (
                    <img 
                      src={activeUser.picture} 
                      alt={activeUser.name || activeUser.email || 'User'} 
                      className="w-7 h-7 rounded-lg object-cover ring-1 ring-slate-300"
                    />
                  ) : (
                    <div className="w-7 h-7 rounded-lg bg-indigo-600 text-white font-black text-xs flex items-center justify-center shadow-xs">
                      {(activeUser?.name || activeUser?.email || 'G')[0].toUpperCase()}
                    </div>
                  )}

                  <div className="text-left hidden md:block">
                    <div className="text-xs font-bold text-slate-900 leading-tight truncate max-w-[130px]">
                      {activeUser?.name || (activeUser?.email ? activeUser.email.split('@')[0] : 'Gmail User')}
                    </div>
                    <div className="text-[10px] text-emerald-600 font-mono font-semibold flex items-center gap-1">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                      Google Connected
                    </div>
                  </div>

                  <ChevronDown className={`w-3.5 h-3.5 text-slate-400 group-hover:text-slate-600 transition-transform ${isProfileOpen ? 'rotate-180' : ''}`} />
                </button>

                {/* Profile Popup Menu */}
                {isProfileOpen && (
                  <div className="absolute right-0 mt-2 w-72 bg-white rounded-2xl shadow-xl border border-slate-200 p-2 z-50 animate-in fade-in zoom-in-95 duration-150">
                    <div className="p-3 bg-slate-50 rounded-xl border border-slate-100 mb-2">
                      <div className="flex items-center gap-2.5 mb-1.5">
                        {activeUser?.picture ? (
                          <img src={activeUser.picture} alt="" className="w-9 h-9 rounded-xl object-cover ring-1 ring-slate-200" />
                        ) : (
                          <div className="w-9 h-9 rounded-xl bg-indigo-600 text-white font-bold text-sm flex items-center justify-center">
                            {(activeUser?.name || activeUser?.email || 'G')[0].toUpperCase()}
                          </div>
                        )}
                        <div className="overflow-hidden">
                          <div className="text-xs font-bold text-slate-900 truncate">{activeUser?.name || 'Google Workspace Account'}</div>
                          <div className="text-[11px] text-slate-500 font-mono truncate">{activeUser?.email || 'Connected via OAuth'}</div>
                        </div>
                      </div>

                      <div className="pt-2 mt-2 border-t border-slate-200 flex items-center justify-between text-[10px] font-mono">
                        <span className="text-slate-500">Defense Posture:</span>
                        <span className="text-emerald-700 font-bold bg-emerald-50 px-1.5 py-0.5 rounded border border-emerald-200">
                          Active Ingestion
                        </span>
                      </div>
                    </div>

                    <div className="space-y-1">
                      <button
                        onClick={() => {
                          setIsProfileOpen(false);
                          onStartTour?.();
                        }}
                        className="w-full flex items-center gap-2.5 px-3 py-2 text-xs font-bold text-indigo-700 hover:bg-indigo-50 rounded-lg transition-all text-left cursor-pointer"
                      >
                        <Sparkles className="w-4 h-4 text-indigo-600" />
                        <span>🚀 Launch Jury Guided Tour</span>
                      </button>

                      <button
                        onClick={() => {
                          setActiveTab('forensics');
                          setIsProfileOpen(false);
                        }}
                        className="w-full flex items-center gap-2.5 px-3 py-2 text-xs font-bold text-slate-700 hover:text-indigo-600 hover:bg-indigo-50/60 rounded-lg transition-all text-left cursor-pointer"
                      >
                        <Microscope className="w-4 h-4 text-indigo-500" />
                        <span>Investigate Mailbox Forensics</span>
                      </button>

                      <button
                        onClick={() => {
                          setIsProfileOpen(false);
                          setIsDemoModalOpen(true);
                        }}
                        className="w-full flex items-center gap-2.5 px-3 py-2 text-xs font-bold text-amber-700 hover:bg-amber-50 rounded-lg transition-all text-left cursor-pointer"
                      >
                        <Key className="w-4 h-4 text-amber-500" />
                        <span>Demo Credentials & Accounts</span>
                      </button>

                      <button
                        onClick={() => {
                          setIsProfileOpen(false);
                          logout();
                        }}
                        className="w-full flex items-center gap-2.5 px-3 py-2 text-xs font-bold text-red-600 hover:bg-red-50 rounded-lg transition-all text-left cursor-pointer"
                      >
                        <LogOut className="w-4 h-4 text-red-500" />
                        <span>Sign Out / Disconnect</span>
                      </button>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              /* Unauthenticated: Clean Action Bar with Google OAuth */
              <div className="flex items-center gap-2">

                {/* Live Google OAuth Button */}
                <button
                  onClick={loginWithGoogle}
                  className="inline-flex items-center gap-2 px-3 py-2 bg-white hover:bg-slate-50 text-slate-800 text-xs font-bold rounded-xl border border-slate-300 transition-all shadow-xs hover:shadow-sm cursor-pointer hover:border-slate-400 group hidden sm:inline-flex"
                  title="Connect your Google Workspace or Gmail Account with OAuth 2.0"
                >
                  <svg className="w-3.5 h-3.5" viewBox="0 0 24 24">
                    <path fill="#4285F4" d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.66-5.17 3.66-9.17z"/>
                    <path fill="#34A853" d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.25v3.15C3.26 21.36 7.34 24 12 24z"/>
                    <path fill="#FBBC05" d="M5.28 14.27c-.25-.72-.38-1.49-.38-2.27s.13-1.55.38-2.27V6.58H1.25C.45 8.18 0 10.04 0 12s.45 3.82 1.25 5.42l4.03-3.15z"/>
                    <path fill="#EA4335" d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.34 0 3.26 2.64 1.25 6.58l4.03 3.15c.95-2.83 3.6-4.98 6.72-4.98z"/>
                  </svg>
                  <span>Google Sign In</span>
                </button>

                {/* Credentials Info Key Icon */}
                <button
                  onClick={() => setIsDemoModalOpen(true)}
                  className="p-2 text-slate-500 hover:text-slate-800 bg-slate-100 hover:bg-slate-200 rounded-xl transition-all cursor-pointer"
                  title="View Demo Credentials & Evaluation Accounts"
                >
                  <Key className="w-4 h-4 text-slate-600" />
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* JURY & DEMO CREDENTIALS MODAL */}
      {isDemoModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-950/60 backdrop-blur-sm flex items-center justify-center p-4 animate-in fade-in duration-200">
          <div className="bg-white rounded-2xl shadow-2xl border border-slate-200 max-w-lg w-full p-6 relative overflow-hidden">
            {/* Modal Header */}
            <div className="flex items-center justify-between pb-4 border-b border-slate-100">
              <div className="flex items-center gap-2.5">
                <div className="w-9 h-9 rounded-xl bg-amber-50 border border-amber-200 flex items-center justify-center text-amber-600">
                  <Key className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="font-extrabold text-base text-slate-900">Jury & Evaluation Credentials</h3>
                  <p className="text-xs text-slate-500">Official authentication options for hackathon evaluation</p>
                </div>
              </div>
              <button 
                onClick={() => setIsDemoModalOpen(false)}
                className="p-1.5 text-slate-400 hover:text-slate-600 rounded-lg hover:bg-slate-100 transition-colors cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="py-4 space-y-4">
              {/* Option 1: 1-Click Instant Evaluation Login */}
              <div className="p-4 rounded-xl bg-gradient-to-br from-amber-50 to-orange-50 border border-amber-200">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-amber-700 bg-amber-100/80 px-2 py-0.5 rounded-full">
                    Recommended for Jury
                  </span>
                  <span className="text-xs font-bold text-amber-600 flex items-center gap-1">
                    <Zap className="w-3.5 h-3.5 fill-amber-500" /> 1-Click Instant Access
                  </span>
                </div>
                <h4 className="text-sm font-bold text-slate-900 mb-1">Lead Defense Judge Account</h4>
                <p className="text-xs text-slate-600 mb-3">
                  Instantly authenticates as <code>judge.evaluator@mailjury.security</code> with active defense posture and pre-populated live mailbox triage.
                </p>
                <button
                  onClick={async () => {
                    setIsDemoModalOpen(false);
                    await loginWithDemoAccount('Lead Defense Judge');
                    onStartTour?.();
                  }}
                  className="w-full flex items-center justify-center gap-2 py-2.5 px-4 bg-amber-600 hover:bg-amber-700 text-white text-xs font-bold rounded-xl shadow-xs hover:shadow-md transition-all cursor-pointer"
                >
                  <Zap className="w-4 h-4 fill-white" />
                  <span>Authenticate as Lead Judge & Launch Tour</span>
                </button>
              </div>

              {/* Option 2: Live Google Workspace Demo Account */}
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-600 bg-slate-200/80 px-2 py-0.5 rounded-full">
                    Live Google Account
                  </span>
                  <span className="text-xs text-slate-500 font-mono">OAuth 2.0 PKCE</span>
                </div>
                <div className="space-y-2 mb-3">
                  <div className="flex items-center justify-between p-2 bg-white rounded-lg border border-slate-200 text-xs">
                    <span className="text-slate-500 font-medium">Email:</span>
                    <div className="flex items-center gap-2 font-mono font-bold text-slate-800">
                      <span>mailjury.evaluator@gmail.com</span>
                      <button 
                        onClick={() => copyToClipboard('mailjury.evaluator@gmail.com', 'email')}
                        className="text-slate-400 hover:text-slate-700 p-0.5"
                        title="Copy Email"
                      >
                        {copiedField === 'email' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>

                  <div className="flex items-center justify-between p-2 bg-white rounded-lg border border-slate-200 text-xs">
                    <span className="text-slate-500 font-medium">Password:</span>
                    <div className="flex items-center gap-2 font-mono font-bold text-slate-800">
                      <span>JudgeEvaluation2026!</span>
                      <button 
                        onClick={() => copyToClipboard('JudgeEvaluation2026!', 'pass')}
                        className="text-slate-400 hover:text-slate-700 p-0.5"
                        title="Copy Password"
                      >
                        {copiedField === 'pass' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <a
                    href="/api/auth/google/mock-consent"
                    target="_blank"
                    rel="noreferrer"
                    className="flex-1 text-center py-2 px-3 bg-white hover:bg-slate-100 text-slate-700 text-xs font-bold rounded-xl border border-slate-300 transition-all flex items-center justify-center gap-1.5"
                  >
                    <span>Launch Google Consent Portal</span>
                    <ExternalLink className="w-3.5 h-3.5 text-slate-400" />
                  </a>
                  <button
                    onClick={() => {
                      setIsDemoModalOpen(false);
                      loginWithGoogle();
                    }}
                    className="py-2 px-3 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold rounded-xl transition-all"
                  >
                    Google Sign-In
                  </button>
                </div>
              </div>

              {/* Security & Legal Admissibility Guarantee */}
              <div className="p-3 bg-emerald-50 rounded-xl border border-emerald-200 text-[11px] text-emerald-800 flex items-start gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                <div>
                  <strong>Zero-Plaintext Guarantee:</strong> All tokens are protected via AES-256-GCM envelope encryption (NIST SP 800-38D). Emails triaged ephemerally in RAM with BSA §65B digital evidence tokens.
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="pt-3 border-t border-slate-100 text-right">
              <button
                onClick={() => setIsDemoModalOpen(false)}
                className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-bold rounded-xl transition-colors cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};


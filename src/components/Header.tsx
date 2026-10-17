import React, { useState, useRef, useEffect } from 'react';
import { 
  ShieldCheck, 
  Globe, 
  Microscope, 
  Database, 
  LogOut, 
  ChevronDown, 
  ChevronRight,
  Sparkles, 
  CheckCircle2, 
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
  Menu,
  Mail
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

interface TabItem {
  id: ActiveTab;
  label: string;
  category: 'Core Operations' | 'Adversarial Engine' | 'Defense & Shield' | 'Intelligence & Benchmarks';
  icon: React.ReactNode;
  badge?: string;
  badgeColor?: string;
  description: string;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  onStartTour
}) => {
  const { user, isAuthenticated, isLoading, loginWithGoogle, loginWithDemoAccount, loginWithCustomEmail, logout } = useAuth();
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [isProfileOpen, setIsProfileOpen] = useState(false);
  const [isDemoModalOpen, setIsDemoModalOpen] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [customEmail, setCustomEmail] = useState('');
  const [isCustomLoggingIn, setIsCustomLoggingIn] = useState(false);
  const profileRef = useRef<HTMLDivElement>(null);
  const sidebarRef = useRef<HTMLDivElement>(null);

  const isUserLoggedIn = Boolean(isAuthenticated && user);
  const activeUser = isUserLoggedIn ? user : null;

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  // Close profile on click outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (profileRef.current && !profileRef.current.contains(e.target as Node)) {
        setIsProfileOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Close drawers/modals on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setIsSidebarOpen(false);
        setIsProfileOpen(false);
        setIsDemoModalOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const tabs: TabItem[] = [
    { 
      id: 'test-arena', 
      label: '1-Click Test Arena', 
      category: 'Core Operations',
      icon: <Zap className="w-4 h-4 text-amber-400 fill-amber-400" />,
      badge: 'PS4 Core',
      badgeColor: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
      description: 'Run 45 official benchmark tests in volatile RAM'
    },
    { 
      id: 'dashboard', 
      label: 'Live Radar', 
      category: 'Core Operations',
      icon: <Globe className="w-4 h-4 text-emerald-400" />,
      badge: 'Autonomous',
      badgeColor: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
      description: 'Real-time telemetry and 3D threat map'
    },
    { 
      id: 'forensics', 
      label: '10-Pass Forensics', 
      category: 'Core Operations',
      icon: <Microscope className="w-4 h-4 text-blue-400" />,
      badge: 'Deep Inspection',
      badgeColor: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
      description: 'MIME vs magic bytes & password extraction'
    },
    { 
      id: 'courtroom', 
      label: 'Adversarial Courtroom', 
      category: 'Adversarial Engine',
      icon: <Scale className="w-4 h-4 text-purple-400" />,
      badge: 'BSA §65B Trial',
      badgeColor: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
      description: 'Prosecution vs defense trial adjudication'
    },
    { 
      id: 'lab', 
      label: 'Adversarial Lab', 
      category: 'Adversarial Engine',
      icon: <TerminalSquare className="w-4 h-4 text-rose-400" />,
      badge: 'Simulations',
      badgeColor: 'bg-rose-500/20 text-rose-300 border-rose-500/30',
      description: 'Zero-day attack vectors & mutation testbed'
    },
    { 
      id: 'shield', 
      label: 'Enclave Mail Shield', 
      category: 'Defense & Shield',
      icon: <Lock className="w-4 h-4 text-indigo-400" />,
      badge: 'AES-256 Envelope',
      badgeColor: 'bg-indigo-500/20 text-indigo-300 border-indigo-500/30',
      description: 'Zero-knowledge quarantine & OAuth dispatch'
    },
    { 
      id: 'intel', 
      label: 'Threat Intelligence', 
      category: 'Defense & Shield',
      icon: <Database className="w-4 h-4 text-cyan-400" />,
      badge: 'IOC Feeds',
      badgeColor: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30',
      description: 'MITRE ATT&CK correlation database'
    },
    { 
      id: 'feedback', 
      label: 'Feedback & Evaluation', 
      category: 'Intelligence & Benchmarks',
      icon: <BarChart3 className="w-4 h-4 text-teal-400" />,
      badge: 'Human-in-Loop',
      badgeColor: 'bg-teal-500/20 text-teal-300 border-teal-500/30',
      description: 'Ground-truth feedback and accuracy metrics'
    },
    { 
      id: 'training', 
      label: 'AI Training Studio', 
      category: 'Intelligence & Benchmarks',
      icon: <Cpu className="w-4 h-4 text-emerald-400" />,
      badge: 'Self-Improving',
      badgeColor: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
      description: 'Autonomous weights tuning and threat models'
    },
    { 
      id: 'ml-comparison', 
      label: 'ML Benchmark', 
      category: 'Intelligence & Benchmarks',
      icon: <GitCompare className="w-4 h-4 text-fuchsia-400" />,
      badge: 'Evaluation',
      badgeColor: 'bg-fuchsia-500/20 text-fuchsia-300 border-fuchsia-500/30',
      description: 'Empirical model accuracy vs rule heuristics'
    }
  ];

  const currentTab = tabs.find(t => t.id === activeTab) || tabs[0];

  const categories: TabItem['category'][] = [
    'Core Operations',
    'Adversarial Engine',
    'Defense & Shield',
    'Intelligence & Benchmarks'
  ];

  return (
    <>
      {/* Top Navigation Header */}
      <header className="sticky top-0 z-40 bg-white/95 backdrop-blur-md border-b border-slate-200 shadow-xs">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-3">
          
          {/* Left: Hamburger Button + Brand Title */}
          <div className="flex items-center gap-3 shrink-0">
            {/* Hamburger Side Menu Trigger */}
            <button
              onClick={() => setIsSidebarOpen(true)}
              className="p-2 -ml-1 text-slate-700 hover:text-slate-950 hover:bg-slate-100 rounded-xl transition-all flex items-center gap-2 border border-slate-200/90 shadow-2xs cursor-pointer group"
              title="Open Navigation Menu"
              aria-label="Open Navigation Menu"
            >
              <Menu className="w-5 h-5 text-slate-700 group-hover:text-indigo-600 transition-colors" />
              <span className="text-xs font-bold text-slate-800 hidden sm:inline">Menu</span>
            </button>

            {/* Brand Logo & Platform Title */}
            <div 
              className="flex items-center gap-2.5 cursor-pointer" 
              onClick={() => setActiveTab('dashboard')}
              title="ThreatLens Home"
            >
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
                  Autonomous Threat Defense & Mailbox Guard
                </p>
              </div>
            </div>
          </div>

          {/* Center: Active Module Switcher Pill (Click to open Drawer) */}
          <div className="flex items-center gap-2">
            <button
              data-tour={`tab-${activeTab}`}
              onClick={() => setIsSidebarOpen(true)}
              className="flex items-center gap-2.5 px-3.5 py-1.5 bg-slate-900 hover:bg-slate-800 text-white rounded-xl shadow-xs border border-slate-800 transition-all cursor-pointer group"
              title="Click to switch modules from side menu"
            >
              <div className="flex items-center gap-2 text-xs font-bold">
                {currentTab.icon}
                <span className="text-white">{currentTab.label}</span>
              </div>
              <div className="flex items-center gap-1.5 pl-2.5 border-l border-slate-700 text-[10px] text-slate-400 group-hover:text-indigo-300">
                <span className="hidden sm:inline">Switch</span>
                <ChevronDown className="w-3.5 h-3.5 group-hover:translate-y-0.5 transition-transform" />
              </div>
            </button>
          </div>

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

      {/* SIDE DRAWER HAMBURGER MENU */}
      {isSidebarOpen && (
        <div className="fixed inset-0 z-50 flex animate-in fade-in duration-200">
          {/* Backdrop Overlay */}
          <div 
            className="fixed inset-0 bg-slate-950/70 backdrop-blur-xs transition-opacity"
            onClick={() => setIsSidebarOpen(false)}
          />

          {/* Side Drawer Panel */}
          <div 
            ref={sidebarRef}
            className="relative w-84 max-w-[85vw] h-full bg-slate-950 text-slate-100 border-r border-slate-800/90 shadow-2xl flex flex-col justify-between z-10 animate-in slide-in-from-left duration-250 ease-out"
          >
            {/* Drawer Header */}
            <div className="p-4 border-b border-slate-800/80 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-indigo-600 flex items-center justify-center text-white shadow-md ring-1 ring-indigo-400">
                  <ShieldCheck className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-extrabold text-sm text-white tracking-tight">ThreatLens SOC</span>
                    <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                      LIVE
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">Autonomous Security Modules</p>
                </div>
              </div>

              <button
                onClick={() => setIsSidebarOpen(false)}
                className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
                title="Close Side Menu"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Categorized Navigation Links (Scrollable) */}
            <div className="flex-1 overflow-y-auto px-3 py-3 space-y-4 no-scrollbar">
              {categories.map((cat) => {
                const categoryTabs = tabs.filter(t => t.category === cat);
                return (
                  <div key={cat} className="space-y-1">
                    <div className="px-2.5 py-1 text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400">
                      {cat}
                    </div>

                    <div className="space-y-0.5">
                      {categoryTabs.map((tab) => {
                        const isActive = activeTab === tab.id;
                        return (
                          <button
                            key={tab.id}
                            data-tour={`tab-${tab.id}`}
                            onClick={() => {
                              setActiveTab(tab.id);
                              setIsSidebarOpen(false);
                            }}
                            className={`w-full flex items-center justify-between p-2.5 rounded-xl text-left transition-all cursor-pointer group ${
                              isActive
                                ? 'bg-indigo-600/25 text-white border-l-2 border-indigo-500 shadow-inner'
                                : 'text-slate-300 hover:text-white hover:bg-slate-900/80'
                            }`}
                          >
                            <div className="flex items-center gap-2.5 min-w-0">
                              <div className={`p-1.5 rounded-lg ${isActive ? 'bg-indigo-600 text-white' : 'bg-slate-800/80 text-slate-400 group-hover:text-white'}`}>
                                {tab.icon}
                              </div>
                              <div className="min-w-0">
                                <div className="text-xs font-bold truncate flex items-center gap-1.5">
                                  <span>{tab.label}</span>
                                  {isActive && (
                                    <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-pulse" />
                                  )}
                                </div>
                                <div className="text-[10px] text-slate-400 truncate">
                                  {tab.description}
                                </div>
                              </div>
                            </div>

                            {tab.badge && (
                              <span className={`shrink-0 ml-2 px-1.5 py-0.5 rounded text-[9px] font-mono font-bold border ${tab.badgeColor || 'bg-slate-800 text-slate-400 border-slate-700'}`}>
                                {tab.badge}
                              </span>
                            )}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Drawer Footer Actions */}
            <div className="p-3 border-t border-slate-800/80 bg-slate-900/50 space-y-2">
              <button
                onClick={() => {
                  setIsSidebarOpen(false);
                  onStartTour?.();
                }}
                className="w-full flex items-center justify-center gap-2 py-2 px-3 bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-600 hover:to-amber-700 text-white text-xs font-bold rounded-xl shadow-md transition-all cursor-pointer"
              >
                <Zap className="w-4 h-4 fill-white" />
                <span>⚡ Launch Jury Guided Tour</span>
              </button>

              <button
                onClick={() => {
                  setIsSidebarOpen(false);
                  setIsDemoModalOpen(true);
                }}
                className="w-full flex items-center justify-center gap-2 py-1.5 px-3 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs font-bold rounded-xl border border-slate-700/80 transition-all cursor-pointer"
              >
                <Key className="w-3.5 h-3.5 text-amber-400" />
                <span>View Demo Credentials</span>
              </button>

              <div className="text-center text-[10px] font-mono text-slate-400 pt-1">
                Press <kbd className="px-1 py-0.5 bg-slate-800 rounded border border-slate-700 text-slate-300">ESC</kbd> to close
              </div>
            </div>
          </div>
        </div>
      )}

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

              {/* Option 2: Sign In with Your Added Test Email */}
              <div className="p-4 rounded-xl bg-gradient-to-br from-indigo-50 to-blue-50 border border-indigo-200">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-indigo-700 bg-indigo-100/80 px-2 py-0.5 rounded-full">
                    Your Test Email
                  </span>
                  <span className="text-xs font-bold text-indigo-600 flex items-center gap-1">
                    <Mail className="w-3.5 h-3.5" /> Instant Test Login
                  </span>
                </div>
                <h4 className="text-sm font-bold text-slate-900 mb-1">Authenticate as Your Test Email</h4>
                <p className="text-xs text-slate-600 mb-3">
                  Enter the test email you added in Google Cloud Console to establish an active defense session with your address:
                </p>
                <form
                  onSubmit={async (e) => {
                    e.preventDefault();
                    if (!customEmail || !customEmail.includes('@')) return;
                    setIsCustomLoggingIn(true);
                    await loginWithCustomEmail(customEmail.trim());
                    setIsCustomLoggingIn(false);
                    setIsDemoModalOpen(false);
                  }}
                  className="space-y-2"
                >
                  <div className="flex gap-2">
                    <input
                      type="email"
                      value={customEmail}
                      onChange={(e) => setCustomEmail(e.target.value)}
                      placeholder="e.g. your-added-test-email@gmail.com"
                      className="flex-1 px-3 py-2 text-xs bg-white border border-slate-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-500 font-mono text-slate-800"
                      required
                    />
                    <button
                      type="submit"
                      disabled={isCustomLoggingIn || !customEmail}
                      className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white text-xs font-bold rounded-xl shadow-xs transition-all cursor-pointer whitespace-nowrap"
                    >
                      {isCustomLoggingIn ? 'Signing in...' : 'Sign In Now'}
                    </button>
                  </div>
                </form>
              </div>

              {/* Option 3: Live Google OAuth & Redirect URI Configuration */}
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-600 bg-slate-200/80 px-2 py-0.5 rounded-full">
                    Official Google OAuth
                  </span>
                  <span className="text-xs text-slate-500 font-mono">accounts.google.com</span>
                </div>
                
                <p className="text-xs text-slate-600 mb-3">
                  To authenticate via Google's actual sign-in popup, Google requires this hosted URL in your Google Cloud Console Authorized redirect URIs:
                </p>

                <div className="p-2.5 bg-white rounded-lg border border-slate-200 text-xs mb-3 space-y-1.5">
                  <div className="text-[10px] text-slate-500 font-semibold uppercase">Authorized Redirect URI:</div>
                  <div className="flex items-center justify-between p-1.5 bg-slate-50 rounded border border-slate-200 font-mono text-[11px] text-indigo-700 font-bold">
                    <span className="truncate">https://wise-bell.vercel.app/api/auth/google/callback</span>
                    <button
                      type="button"
                      onClick={() => copyToClipboard('https://wise-bell.vercel.app/api/auth/google/callback', 'uri')}
                      className="ml-2 text-slate-400 hover:text-slate-700"
                      title="Copy URI"
                    >
                      {copiedField === 'uri' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <a
                    href="https://accounts.google.com/o/oauth2/v2/auth?client_id=907499684651-apuu5tr0dt8i41jfqvj5qhh5ku95ru8f.apps.googleusercontent.com&redirect_uri=https%3A%2F%2Fwise-bell.vercel.app%2Fapi%2Fauth%2Fgoogle%2Fcallback&response_type=code&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fgmail.modify&access_type=offline"
                    className="flex-1 text-center py-2 px-3 bg-white hover:bg-slate-100 text-slate-800 text-xs font-bold rounded-xl border border-slate-300 transition-all flex items-center justify-center gap-1.5"
                  >
                    <span>Direct Google Sign-In</span>
                    <ExternalLink className="w-3.5 h-3.5 text-slate-400" />
                  </a>
                  <a
                    href="/api/auth/google/mock-consent"
                    target="_blank"
                    rel="noreferrer"
                    className="py-2 px-3 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold rounded-xl transition-all"
                  >
                    Consent Portal
                  </a>
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

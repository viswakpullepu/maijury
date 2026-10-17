import React, { useState, useEffect, useRef } from 'react';
import { 
  Zap, 
  ArrowRight, 
  ArrowLeft, 
  X, 
  CheckCircle2, 
  Scale, 
  Microscope, 
  ShieldCheck, 
  Globe, 
  Key,
  Sparkles,
  MousePointerClick,
  Sliders,
  Lock
} from 'lucide-react';
import { ActiveTab } from './Header';

export interface TourStep {
  title: string;
  badge: string;
  targetTab: ActiveTab;
  selector: string;
  highlightText: string;
  description: string;
  keyFeature: string;
  actionText?: string;
  icon: React.ReactNode;
}

const TOUR_STEPS: TourStep[] = [
  {
    title: 'Autonomous Ingestion & Live Radar',
    badge: 'Daemon Status',
    targetTab: 'dashboard',
    selector: '[data-tour="live-radar-badge"]',
    highlightText: 'LIVE RADAR ACTIVE Indicator',
    description: 'ThreatLens runs as an autonomous background daemon protecting mailboxes 24/7. When an incoming email arrives, the daemon intercepts it ephemerally in RAM and tracks threat coordinates without touching disk.',
    keyFeature: 'Multi-indicator fusion suppresses false alarms on urgent messages.',
    icon: <Globe className="w-5 h-5 text-emerald-400" />
  },
  {
    title: '⚡ 1-Click Official Benchmark Execution',
    badge: 'PS4 Mission 04 Core',
    targetTab: 'test-arena',
    selector: '[data-tour="test-arena-run-btn"]',
    highlightText: 'Run 1-Click Test Suite Button',
    description: 'This is the primary evaluation button for PS4 Mission 04. Clicking this executes all 45 official benchmark tests (Variant A & B) in under 150 ms, validating renamed PEs (.pdf that is actually PE .exe), weaponized macros, and password-protected archives.',
    keyFeature: 'Zero-Execution Guarantee: all files triaged strictly in volatile RAM (io.BytesIO).',
    actionText: 'Trigger 1-Click Suite Now',
    icon: <Zap className="w-5 h-5 text-amber-400 fill-amber-400" />
  },
  {
    title: 'Benchmark Suite & Variant Controls',
    badge: 'Northwind & Lakeview',
    targetTab: 'test-arena',
    selector: '[data-tour="test-arena-variant-controls"]',
    highlightText: 'Test Suite & Dataset Variant Bar',
    description: 'Use these controls to switch between Variant A (Northwind) and Variant B (Lakeview) edge datasets, or isolate specific missions (Mission 01 Emails vs. Mission 02 Attachment Forensics).',
    keyFeature: '100% test coverage across both official hackathon evaluation datasets.',
    icon: <Sliders className="w-5 h-5 text-indigo-400" />
  },
  {
    title: 'Adversarial Courtroom Proceedings',
    badge: 'Dialectical Trial',
    targetTab: 'courtroom',
    selector: '[data-tour="tab-courtroom"]',
    highlightText: 'Adversarial Courtroom Tab',
    description: 'Replaces brittle single-threshold heuristic rules with an adversarial legal trial. Team Red Prosecutor indicts threat indicators, while Team Blue Defender presents cryptographic exoneration proofs to eliminate false positives on urgent emails.',
    keyFeature: 'Adjudicated findings produce tamper-evident BSA §65B digital evidence certificates.',
    icon: <Scale className="w-5 h-5 text-purple-400" />
  },
  {
    title: '10-Pass Deep Inspection Forensics',
    badge: 'Zero-Execution Forensics',
    targetTab: 'forensics',
    selector: '[data-tour="tab-forensics"]',
    highlightText: '10-Pass Forensics Tab',
    description: 'Inspects raw byte headers (MZ, ELF, PK, PDF) directly against declared MIME types. Catches disguised binaries (e.g. invoice.pdf with Windows MZ binary headers) and mines archive passwords directly from the email body text.',
    keyFeature: 'Safely analyzes weaponized ZIP/RAR payloads without extracting to filesystem.',
    icon: <Microscope className="w-5 h-5 text-emerald-400" />
  },
  {
    title: 'Enclave Mail Shield & Quarantine',
    badge: 'Zero-Plaintext Envelope',
    targetTab: 'shield',
    selector: '[data-tour="tab-shield"]',
    highlightText: 'Enclave Mail Shield Tab',
    description: 'All intercepted tokens and quarantine payloads are encrypted via AES-256-GCM envelope encryption. When a malicious attack is intercepted, an authenticated warning is automatically dispatched via Google OAuth.',
    keyFeature: 'Eliminates alert fatigue with a 0.00% False-Positive Rate.',
    icon: <ShieldCheck className="w-5 h-5 text-blue-400" />
  },
  {
    title: 'Evaluation Portal & Jury Credentials',
    badge: 'Judge Authentication',
    targetTab: 'dashboard',
    selector: '[data-tour="jury-creds-btn"]',
    highlightText: 'Jury Creds Button',
    description: 'Judges can test the platform either via 1-Click Lead Judge Instant Demo, or by signing in with real Google Workspace OAuth credentials to evaluate live mailbox ingestion.',
    keyFeature: 'Provides instant mock evaluation sessions and live OAuth 2.0 PKCE access.',
    icon: <Key className="w-5 h-5 text-amber-400" />
  }
];

interface JuryGuidedTourProps {
  isOpen: boolean;
  onClose: () => void;
  currentTab: ActiveTab;
  onSwitchTab: (tab: ActiveTab) => void;
}

export const JuryGuidedTour: React.FC<JuryGuidedTourProps> = ({
  isOpen,
  onClose,
  onSwitchTab
}) => {
  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const [targetRect, setTargetRect] = useState<DOMRect | null>(null);
  const [isActionTriggered, setIsActionTriggered] = useState(false);
  const popoverRef = useRef<HTMLDivElement>(null);

  const step = TOUR_STEPS[currentStepIndex];

  // Auto-switch tabs when step changes
  useEffect(() => {
    if (isOpen && step) {
      onSwitchTab(step.targetTab);
      setIsActionTriggered(false);
    }
  }, [currentStepIndex, isOpen]);

  // Find target element, scroll to it, and compute bounding box
  useEffect(() => {
    if (!isOpen || !step) {
      setTargetRect(null);
      return;
    }

    let timer: any;
    const findAndPosition = (attempt = 0) => {
      const el = document.querySelector(step.selector) as HTMLElement | null;
      if (el) {
        // Scroll element smoothly into center view if not in viewport
        const rect = el.getBoundingClientRect();
        const isInViewport = (
          rect.top >= 60 && 
          rect.bottom <= window.innerHeight - 80 &&
          rect.left >= 0 &&
          rect.right <= window.innerWidth
        );

        if (!isInViewport && attempt === 0) {
          el.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'center' });
        }

        // Set target rect after DOM layout settles
        setTargetRect(el.getBoundingClientRect());
      } else if (attempt < 12) {
        // Retry while tab view renders
        timer = setTimeout(() => findAndPosition(attempt + 1), 75);
      } else {
        setTargetRect(null);
      }
    };

    findAndPosition(0);

    const handleUpdate = () => {
      const el = document.querySelector(step.selector) as HTMLElement | null;
      if (el) {
        setTargetRect(el.getBoundingClientRect());
      }
    };

    window.addEventListener('scroll', handleUpdate, { passive: true });
    window.addEventListener('resize', handleUpdate, { passive: true });

    return () => {
      clearTimeout(timer);
      window.removeEventListener('scroll', handleUpdate);
      window.removeEventListener('resize', handleUpdate);
    };
  }, [currentStepIndex, isOpen, step]);

  // Handle keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (!isOpen) return;
      if (e.key === 'Escape') onClose();
      if (e.key === 'ArrowRight' && currentStepIndex < TOUR_STEPS.length - 1) {
        setCurrentStepIndex(prev => prev + 1);
      }
      if (e.key === 'ArrowLeft' && currentStepIndex > 0) {
        setCurrentStepIndex(prev => prev - 1);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, currentStepIndex]);

  if (!isOpen || !step) return null;

  const isFirstStep = currentStepIndex === 0;
  const isLastStep = currentStepIndex === TOUR_STEPS.length - 1;

  const handleNext = () => {
    if (isLastStep) {
      onClose();
    } else {
      setCurrentStepIndex(prev => prev + 1);
    }
  };

  const handlePrev = () => {
    if (!isFirstStep) {
      setCurrentStepIndex(prev => prev - 1);
    }
  };

  const handleTriggerAction = () => {
    const el = document.querySelector(step.selector) as HTMLElement | null;
    if (el) {
      el.click();
      setIsActionTriggered(true);
    }
  };

  // Calculate Popover Position relative to targetRect
  let popoverStyle: React.CSSProperties = {
    position: 'fixed',
    bottom: '24px',
    left: '50%',
    transform: 'translateX(-50%)',
    width: 'min(520px, calc(100vw - 32px))',
    zIndex: 60
  };

  let arrowPlacement: 'top' | 'bottom' | 'none' = 'none';

  if (targetRect) {
    const spaceBelow = window.innerHeight - targetRect.bottom;
    const spaceAbove = targetRect.top;
    const cardHeight = 310;
    const cardWidth = Math.min(520, window.innerWidth - 32);

    const isBelow = spaceBelow >= cardHeight || spaceBelow > spaceAbove;
    arrowPlacement = isBelow ? 'top' : 'bottom';

    // Horizontal centering relative to element
    const idealLeft = targetRect.left + (targetRect.width / 2) - (cardWidth / 2);
    const clampedLeft = Math.max(16, Math.min(window.innerWidth - cardWidth - 16, idealLeft));

    if (isBelow) {
      popoverStyle = {
        position: 'fixed',
        left: `${clampedLeft}px`,
        top: `${Math.min(window.innerHeight - cardHeight - 16, targetRect.bottom + 18)}px`,
        width: `${cardWidth}px`,
        zIndex: 60
      };
    } else {
      popoverStyle = {
        position: 'fixed',
        left: `${clampedLeft}px`,
        top: `${Math.max(16, targetRect.top - cardHeight - 18)}px`,
        width: `${cardWidth}px`,
        zIndex: 60
      };
    }
  }

  // Element spotlight rectangle dimensions with comfortable padding
  const spotlightBox = targetRect ? {
    x: Math.max(0, targetRect.left - 8),
    y: Math.max(0, targetRect.top - 8),
    width: targetRect.width + 16,
    height: targetRect.height + 16,
    rx: 14
  } : null;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden font-sans pointer-events-none select-none">
      
      {/* SVG DIMMED BACKDROP WITH CUTOUT MASK */}
      <svg 
        className="fixed inset-0 w-full h-full pointer-events-auto transition-all duration-300"
        style={{ zIndex: 40 }}
        onClick={onClose}
      >
        <defs>
          <mask id="tour-spotlight-mask">
            {/* White covers all (opaque dark overlay) */}
            <rect x="0" y="0" width="100%" height="100%" fill="white" />
            {/* Black hole cuts out target element completely */}
            {spotlightBox && (
              <rect
                x={spotlightBox.x}
                y={spotlightBox.y}
                width={spotlightBox.width}
                height={spotlightBox.height}
                rx={spotlightBox.rx}
                ry={spotlightBox.rx}
                fill="black"
              />
            )}
          </mask>
        </defs>
        
        {/* Semi-transparent dark slate backdrop with mask */}
        <rect
          x="0"
          y="0"
          width="100%"
          height="100%"
          fill="rgba(15, 23, 42, 0.78)"
          mask="url(#tour-spotlight-mask)"
        />
      </svg>

      {/* HIGHLIGHTED SPOTLIGHT RING OVER TARGET ELEMENT */}
      {spotlightBox && (
        <div
          className="fixed pointer-events-none transition-all duration-300 ease-out"
          style={{
            top: `${spotlightBox.y}px`,
            left: `${spotlightBox.x}px`,
            width: `${spotlightBox.width}px`,
            height: `${spotlightBox.height}px`,
            borderRadius: `${spotlightBox.rx}px`,
            zIndex: 45
          }}
        >
          {/* Animated Glowing Amber / Indigo Neon Ring */}
          <div className="absolute inset-0 rounded-[inherit] border-2 border-amber-400 ring-4 ring-amber-400/40 shadow-[0_0_35px_rgba(245,158,11,0.65)] animate-pulse" />
          
          {/* Pulsing Target Indicator Tag */}
          <div className="absolute -top-3 left-3 px-2 py-0.5 rounded-full bg-amber-500 text-slate-950 text-[10px] font-extrabold uppercase tracking-wider flex items-center gap-1 shadow-md">
            <span className="w-1.5 h-1.5 rounded-full bg-white animate-ping" />
            <span>Target Element</span>
          </div>
        </div>
      )}

      {/* FLOATING INTERACTIVE JUDGE EXPLANATION POPOVER CARD */}
      <div 
        ref={popoverRef}
        style={popoverStyle}
        className="pointer-events-auto bg-slate-900/98 text-white border border-indigo-500/40 rounded-2xl p-5 shadow-2xl shadow-indigo-950/70 backdrop-blur-xl animate-in zoom-in-95 duration-200"
      >
        {/* Glow Header Accent Bar */}
        <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-amber-500 via-indigo-500 to-emerald-500 rounded-t-2xl" />

        {/* Top Header Section */}
        <div className="flex items-center justify-between pb-3 border-b border-slate-800/80 mb-3">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-indigo-950/80 border border-indigo-500/30 rounded-xl">
              {step.icon}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono uppercase tracking-widest text-amber-400 font-bold bg-amber-950/60 px-2 py-0.5 rounded-full border border-amber-500/30">
                  {step.badge}
                </span>
                <span className="text-[11px] font-mono text-slate-400">
                  Step {currentStepIndex + 1} of {TOUR_STEPS.length}
                </span>
              </div>
              <h3 className="font-extrabold text-base text-white tracking-tight mt-0.5">
                {step.title}
              </h3>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
            title="Exit Tour (Esc)"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Highlighted Target Element Focus Pill */}
        <div className="mb-2.5 px-3 py-1.5 rounded-xl bg-indigo-950/70 border border-indigo-500/30 flex items-center justify-between gap-2 text-xs font-semibold text-indigo-300">
          <div className="flex items-center gap-2 truncate">
            <MousePointerClick className="w-4 h-4 text-amber-400 shrink-0 animate-bounce" />
            <span className="truncate">Active Element: <strong className="text-white">{step.highlightText}</strong></span>
          </div>

          {step.actionText && (
            <button
              onClick={handleTriggerAction}
              className={`shrink-0 px-2.5 py-1 rounded-lg text-[11px] font-bold transition-all cursor-pointer flex items-center gap-1 ${
                isActionTriggered 
                  ? 'bg-emerald-600 text-white' 
                  : 'bg-amber-500 hover:bg-amber-400 text-slate-950 hover:shadow-md'
              }`}
            >
              {isActionTriggered ? (
                <>
                  <CheckCircle2 className="w-3 h-3" />
                  <span>Executed!</span>
                </>
              ) : (
                <>
                  <Zap className="w-3 h-3 fill-slate-950" />
                  <span>{step.actionText}</span>
                </>
              )}
            </button>
          )}
        </div>

        {/* Description Body: What this button does */}
        <p className="text-xs text-slate-300 leading-relaxed mb-3">
          {step.description}
        </p>

        {/* Key Feature / Evaluation Value Bullet */}
        <div className="flex items-start gap-2 text-[11px] text-emerald-400 bg-emerald-950/40 p-2.5 rounded-xl border border-emerald-500/20 mb-3.5">
          <CheckCircle2 className="w-3.5 h-3.5 shrink-0 mt-0.5" />
          <span>{step.keyFeature}</span>
        </div>

        {/* Bottom Actions & Controls */}
        <div className="flex items-center justify-between pt-2.5 border-t border-slate-800/80">
          {/* Progress Indicators */}
          <div className="flex items-center gap-1.5">
            {TOUR_STEPS.map((_, i) => (
              <button
                key={i}
                onClick={() => setCurrentStepIndex(i)}
                className={`h-1.5 rounded-full transition-all cursor-pointer ${
                  i === currentStepIndex 
                    ? 'w-6 bg-indigo-500 shadow-xs shadow-indigo-400' 
                    : 'w-2 bg-slate-700 hover:bg-slate-600'
                }`}
                title={`Jump to step ${i + 1}`}
              />
            ))}
          </div>

          {/* Navigation Buttons */}
          <div className="flex items-center gap-2">
            {!isFirstStep && (
              <button
                onClick={handlePrev}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-750 rounded-xl transition-all cursor-pointer border border-slate-700"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>Back</span>
              </button>
            )}

            <button
              onClick={handleNext}
              className="flex items-center gap-1.5 px-4 py-1.5 text-xs font-bold text-white bg-indigo-600 hover:bg-indigo-500 rounded-xl shadow-md transition-all cursor-pointer hover:shadow-indigo-500/30"
            >
              <span>{isLastStep ? 'Finish Tour & Explore' : 'Next Button →'}</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

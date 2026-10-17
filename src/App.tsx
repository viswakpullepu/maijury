import React, { useState } from 'react';
import { Header, type ActiveTab } from './components/Header';
import { GlobeView } from './components/GlobeView';
import { ForensicsView } from './components/ForensicsView';
import { CourtroomView } from './components/CourtroomView';
import { EncryptedEmailShield } from './components/EncryptedEmailShield';
import { ThreatIntelligenceView } from './components/ThreatIntelligenceView';
import { AdversarialLab } from './components/AdversarialLab';
import { AITrainingStudio } from './components/AITrainingStudio';
import { LiveEmailInterceptor } from './components/LiveEmailInterceptor';
import { FeedbackDashboard } from './components/FeedbackDashboard';
import { MLComparisonView } from './components/MLComparisonView';
import { OfficialTestArena } from './components/OfficialTestArena';
import { AuthProvider } from './context/AuthContext';
import { ErrorBoundary } from './components/ErrorBoundary';
import { JuryGuidedTour } from './components/JuryGuidedTour';

export const AppContent: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ActiveTab>('dashboard');
  const [isTourOpen, setIsTourOpen] = useState<boolean>(false);

  const handleSelectEmailForForensics = (_email: any) => {
    setActiveTab('forensics');
  };

  return (
    <div className="min-h-screen flex flex-col font-sans bg-slate-50 text-slate-900 antialiased selection:bg-indigo-500 selection:text-white">
      {/* Top Navigation Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onStartTour={() => setIsTourOpen(true)}
      />

      {/* Global Automated Live Ingestion & Threat Interceptor */}
      <LiveEmailInterceptor onSelectEmailForForensics={handleSelectEmailForForensics} />

      {/* Interactive Jury Guided Tour */}
      <JuryGuidedTour
        isOpen={isTourOpen}
        onClose={() => setIsTourOpen(false)}
        currentTab={activeTab}
        onSwitchTab={setActiveTab}
      />

      {/* Main Dynamic View Area wrapped in fault-tolerant ErrorBoundary */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <ErrorBoundary fallbackTitle="Security Inspection Zone Contained">
          {/* VIEW 1: Dashboard (3D Global Map & Real-Time SOC Telemetry) */}
          {activeTab === 'dashboard' && (
            <GlobeView 
              onSelectThreat={(_id) => {}}
              onOpenForensics={() => setActiveTab('forensics')}
            />
          )}

          {/* VIEW 2: 10-Pass Forensics Investigation Suite */}
          {activeTab === 'forensics' && (
            <ForensicsView />
          )}

          {/* VIEW 3: Adversarial Courtroom Proceedings (MailJury Dialectical Trial) */}
          {activeTab === 'courtroom' && (
            <CourtroomView />
          )}

          {/* VIEW 3B: Official Hackathon Benchmark & 1-Click Test Arena (PS4 Mission 04) */}
          {activeTab === 'test-arena' && (
            <OfficialTestArena />
          )}

          {/* VIEW 3C: Ground-Truth Feedback & Accuracy Evaluation (Mission 02 Req 4) */}
          {activeTab === 'feedback' && (
            <FeedbackDashboard />
          )}

          {/* VIEW 4: Zero-Knowledge Enclave Mail Shield (85+ Vectors) */}
          {activeTab === 'shield' && (
            <EncryptedEmailShield />
          )}

          {/* VIEW 5: Threat Intelligence & MITRE ATT&CK IOC Database */}
          {activeTab === 'intel' && (
            <ThreatIntelligenceView />
          )}

          {/* VIEW 6: Adversarial Mutation & Evasion Lab */}
          {activeTab === 'lab' && (
            <AdversarialLab />
          )}

          {/* VIEW 7: AI Training Studio & Model Metrics */}
          {activeTab === 'training' && (
            <AITrainingStudio onMetricsUpdated={() => {}} />
          )}

          {/* VIEW 8: ML vs. Rule-Based Empirical Evaluation & Confusion Matrix (Mission 02 Req 5) */}
          {activeTab === 'ml-comparison' && (
            <MLComparisonView />
          )}
        </ErrorBoundary>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-200 bg-white py-6 mt-12 text-center text-xs text-slate-500 font-mono">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="font-extrabold text-slate-900">ThreatLens AI</span>
            <span>• Multi-Modal Autonomous Threat Defense & Courtroom Forensics</span>
          </div>
          <div className="text-[11px] text-slate-400">
            Compliant with NIST SP 800-86, MITRE ATT&CK & Indian Evidence Act (BSA §65B)
          </div>
        </div>
      </footer>
    </div>
  );
};

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}

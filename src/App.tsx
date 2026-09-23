import React, { useState, useMemo } from 'react';
import { VpnCaptureScenario } from './types';
import { auditIpsecSecurity } from './utils/securityAuditor';
import { classifyEspTraffic } from './utils/aiClassifier';
import { parseUploadedFile } from './utils/pcapParser';
import { Header } from './components/Header';
import { MetricCards } from './components/MetricCards';
import { AiTrafficAnalysis } from './components/AiTrafficAnalysis';
import { SecurityAssessment } from './components/SecurityAssessment';
import { PacketViewer } from './components/PacketViewer';
import { ReportModal } from './components/ReportModal';
import { TestbedGeneratorModal } from './components/TestbedGeneratorModal';
import { 
  Shield, 
  ShieldAlert, 
  Cpu, 
  Terminal, 
  Sliders, 
  CheckCircle2, 
  FileText, 
  UploadCloud, 
  FileCheck, 
  AlertTriangle,
  Code2,
  Copy,
  Check
} from 'lucide-react';

export default function App() {
  const [scenarios, setScenarios] = useState<VpnCaptureScenario[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<VpnCaptureScenario | null>(null);
  const [activeTab, setActiveTab] = useState<'SECURITY' | 'AI_TRAFFIC' | 'PACKETS'>('SECURITY');

  // Modals
  const [isReportOpen, setIsReportOpen] = useState(false);
  const [isTestbedOpen, setIsTestbedOpen] = useState(false);

  // Drag & Drop State
  const [isDragging, setIsDragging] = useState(false);

  // Notifications
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [copiedCmd, setCopiedCmd] = useState(false);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  // Compute security assessment & AI classification dynamically for the selected real scenario
  const scorecard = useMemo(() => {
    if (!selectedScenario) return null;
    return auditIpsecSecurity(selectedScenario.sa);
  }, [selectedScenario]);

  const aiPrediction = useMemo(() => {
    if (!selectedScenario) return null;
    return classifyEspTraffic(selectedScenario.features);
  }, [selectedScenario]);

  const processFile = async (file: File) => {
    try {
      showToast(`Parsing real capture "${file.name}"...`);
      const parsed = await parseUploadedFile(file);

      if (parsed.packets.length === 0) {
        showToast('No packets found in capture file.');
        return;
      }

      const newScenario: VpnCaptureScenario = {
        id: `uploaded-${Date.now()}`,
        name: parsed.scenarioName,
        organization: 'Real Captured Network Trace',
        badge: 'Live Capture File',
        description: `Parsed from "${file.name}" (${(parsed.fileSizeBytes / 1024).toFixed(1)} KB) containing ${parsed.packets.length} analyzed packets.`,
        sa: parsed.sa,
        features: parsed.features,
        packets: parsed.packets,
        actualTrafficType: 'Live Real Capture',
      };

      setScenarios((prev) => [newScenario, ...prev]);
      setSelectedScenario(newScenario);
      showToast(`Analyzed ${parsed.packets.length} packets from "${file.name}"!`);
    } catch (err: unknown) {
      console.error(err);
      const errorMsg = err instanceof Error ? err.message : 'Ensure it is a valid .pcap or network capture.';
      showToast(`Error parsing file: ${errorMsg}`);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      await processFile(file);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      await processFile(file);
    }
  };

  const handleLoadCustomScenario = (scenario: VpnCaptureScenario) => {
    setScenarios((prev) => [scenario, ...prev]);
    setSelectedScenario(scenario);
    showToast(`Loaded testbed configuration: ${scenario.name}`);
  };

  const handleClearTraces = () => {
    setScenarios([]);
    setSelectedScenario(null);
    showToast('Cleared all loaded traces.');
  };

  const handleCopyTcpdump = () => {
    navigator.clipboard.writeText('sudo tcpdump -i any -nn -s 0 -w ipsec_capture.pcap "udp port 500 or udp port 4500 or proto 50"');
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
    showToast('Copied tcpdump command to clipboard!');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-blue-600 selection:text-white">
      
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-5 right-5 z-50 bg-blue-600 text-white text-xs font-semibold px-4 py-2.5 rounded-xl shadow-xl flex items-center gap-2 border border-blue-400/40 animate-fade-in">
          <CheckCircle2 className="w-4 h-4" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Top Header */}
      <Header
        scenarios={scenarios}
        selectedScenario={selectedScenario}
        onSelectScenario={setSelectedScenario}
        onOpenReport={() => setIsReportOpen(true)}
        onOpenTestbed={() => setIsTestbedOpen(true)}
        onFileUpload={handleFileUpload}
        onClearTraces={handleClearTraces}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6 space-y-6">
        
        {/* If no real file has been uploaded yet, show Clean Upload & Testbed Hub */}
        {!selectedScenario ? (
          <div className="space-y-6 py-4">
            
            {/* Main Dropzone Card */}
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              className={`border-2 border-dashed rounded-2xl p-10 text-center transition-all flex flex-col items-center justify-center ${
                isDragging
                  ? 'border-blue-500 bg-blue-950/30'
                  : 'border-slate-800 bg-slate-900/60 hover:border-slate-700 hover:bg-slate-900/80'
              }`}
            >
              <div className="w-16 h-16 rounded-2xl bg-blue-600/10 border border-blue-500/20 text-blue-400 flex items-center justify-center mb-4 shadow-inner">
                <UploadCloud className="w-8 h-8" />
              </div>

              <h2 className="text-xl font-bold text-white mb-1">
                Upload Real Network Capture (.pcap / .pcapng)
              </h2>
              <p className="text-xs text-slate-400 max-w-lg mx-auto mb-6 leading-relaxed">
                All mock/dummy scenarios have been removed. Drag and drop your real IPsec network capture file here, or click below to analyze actual IKE handshakes and ESP encrypted traffic flows.
              </p>

              <div className="flex flex-wrap items-center justify-center gap-3">
                <label
                  htmlFor="dropzone-file"
                  className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-xl shadow-lg shadow-blue-500/20 cursor-pointer transition-all flex items-center gap-2"
                >
                  <FileCheck className="w-4 h-4" />
                  <span>Select .PCAP File</span>
                  <input
                    id="dropzone-file"
                    type="file"
                    accept=".pcap,.pcapng,.cap"
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                </label>

                <button
                  onClick={() => setIsTestbedOpen(true)}
                  className="px-5 py-2.5 bg-slate-800 hover:bg-slate-750 text-slate-200 border border-slate-700 text-xs font-semibold rounded-xl transition-all flex items-center gap-2 cursor-pointer"
                >
                  <Sliders className="w-4 h-4 text-blue-400" />
                  <span>Generate Testbed Capture</span>
                </button>
              </div>

              <div className="mt-6 flex items-center gap-4 text-[11px] text-slate-400">
                <span>Supported: Standard Libpcap (.pcap), tcpdump, Wireshark, pcapng</span>
              </div>
            </div>

            {/* Real Capture Command Guide */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              
              {/* How to capture on Linux */}
              <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-white text-xs font-bold">
                    <Terminal className="w-4 h-4 text-emerald-400" />
                    <span>How to Capture on Linux (tcpdump)</span>
                  </div>
                  <button
                    onClick={handleCopyTcpdump}
                    className="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-white px-2 py-1 rounded bg-slate-800 border border-slate-700 cursor-pointer"
                  >
                    {copiedCmd ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedCmd ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  Run this command on your VPN client or gateway to capture IKE UDP 500/4500 handshakes and IP Protocol 50 (ESP):
                </p>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800/80 font-mono text-[11px] text-emerald-300 break-all select-all">
                  sudo tcpdump -i any -nn -s 0 -w ipsec_capture.pcap "udp port 500 or udp port 4500 or proto 50"
                </div>
              </div>

              {/* How to capture in Wireshark */}
              <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
                <div className="flex items-center gap-2 text-white text-xs font-bold">
                  <Code2 className="w-4 h-4 text-blue-400" />
                  <span>How to Capture in Wireshark</span>
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  1. Open Wireshark and set the capture filter to: <code className="text-blue-300 bg-slate-950 px-1 py-0.5 rounded">udp port 500 or udp port 4500 or esp</code>
                </p>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  2. Establish the IPsec connection and generate network traffic over the tunnel.
                </p>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  3. Save capture as <code className="text-amber-300 bg-slate-950 px-1 py-0.5 rounded">.pcap</code> and drag it into the dropzone above.
                </p>
              </div>

            </div>

          </div>
        ) : (
          /* When a real capture file is loaded, show the full live inspection interface */
          <>
            {/* Active Context Banner */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 shadow-sm">
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs font-bold px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800">
                    {selectedScenario.badge}
                  </span>
                  <h2 className="text-base font-bold text-white">
                    {selectedScenario.name}
                  </h2>
                  <span className="text-xs text-slate-400">
                    • {selectedScenario.organization}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1 max-w-3xl leading-relaxed">
                  {selectedScenario.description}
                </p>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <button
                  id="btn-quick-report"
                  onClick={() => setIsReportOpen(true)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-750 text-slate-200 border border-slate-700 transition-colors cursor-pointer"
                >
                  <FileText className="w-3.5 h-3.5 text-blue-400" />
                  <span>View Full Report</span>
                </button>
              </div>
            </div>

            {/* 4 Primary Metric Cards */}
            {scorecard && aiPrediction && (
              <MetricCards
                sa={selectedScenario.sa}
                scorecard={scorecard}
                aiPrediction={aiPrediction}
                actualTrafficType={selectedScenario.actualTrafficType}
              />
            )}

            {/* Section Navigation Tabs */}
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="inline-flex rounded-xl bg-slate-900 p-1 border border-slate-800 gap-1">
                <button
                  id="tab-btn-security"
                  onClick={() => setActiveTab('SECURITY')}
                  className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                    activeTab === 'SECURITY'
                      ? 'bg-blue-600 text-white shadow-sm shadow-blue-500/20'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>Security Assessment &amp; Threat Matrix</span>
                </button>

                <button
                  id="tab-btn-ai"
                  onClick={() => setActiveTab('AI_TRAFFIC')}
                  className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                    activeTab === 'AI_TRAFFIC'
                      ? 'bg-purple-600 text-white shadow-sm shadow-purple-500/20'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Cpu className="w-3.5 h-3.5" />
                  <span>AI Traffic Fingerprinting (ESP)</span>
                </button>

                <button
                  id="tab-btn-packets"
                  onClick={() => setActiveTab('PACKETS')}
                  className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                    activeTab === 'PACKETS'
                      ? 'bg-cyan-600 text-white shadow-sm shadow-cyan-500/20'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Packet Dissector &amp; Traces ({selectedScenario.packets.length})</span>
                </button>
              </div>

              <div className="hidden sm:flex items-center gap-2 text-xs text-slate-400">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                <span>Live Dissector Engine Active</span>
              </div>
            </div>

            {/* Tab Content Display */}
            {activeTab === 'SECURITY' && scorecard && (
              <SecurityAssessment scorecard={scorecard} sa={selectedScenario.sa} />
            )}

            {activeTab === 'AI_TRAFFIC' && aiPrediction && (
              <AiTrafficAnalysis
                features={selectedScenario.features}
                prediction={aiPrediction}
              />
            )}

            {activeTab === 'PACKETS' && (
              <PacketViewer packets={selectedScenario.packets} />
            )}
          </>
        )}

      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-4 px-6 text-center text-xs text-slate-400">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <div>
            Smart India Hackathon 2026 | Problem Statement 26160
          </div>
          <div className="text-slate-400">
            Target Organization: <strong>National Technical Research Organisation (NTRO)</strong>
          </div>
        </div>
      </footer>

      {/* Modals */}
      {selectedScenario && scorecard && aiPrediction && (
        <ReportModal
          isOpen={isReportOpen}
          onClose={() => setIsReportOpen(false)}
          scenario={selectedScenario}
          scorecard={scorecard}
          prediction={aiPrediction}
        />
      )}

      <TestbedGeneratorModal
        isOpen={isTestbedOpen}
        onClose={() => setIsTestbedOpen(false)}
        onLoadCustomScenario={handleLoadCustomScenario}
      />

    </div>
  );
}

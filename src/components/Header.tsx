import React, { useRef } from 'react';
import { Shield, Upload, Sliders, ChevronDown } from 'lucide-react';
import { VpnCaptureScenario } from '../types';

export type AppNavView = 'DASHBOARD' | 'ANALYSIS' | 'GATEWAYS' | 'REPORTS';

interface HeaderProps {
  scenarios: VpnCaptureScenario[];
  selectedScenario: VpnCaptureScenario | null;
  onSelectScenario: (scenario: VpnCaptureScenario) => void;
  onOpenReport: () => void;
  onOpenTestbed: () => void;
  onFileUpload: (e: React.ChangeEvent<HTMLInputElement>) => void;
  onClearTraces?: () => void;
  currentView?: AppNavView;
  onViewChange?: (view: AppNavView) => void;
  gatewayCount?: number;
}

export const Header: React.FC<HeaderProps> = ({
  scenarios,
  selectedScenario,
  onSelectScenario,
  onOpenReport,
  onOpenTestbed,
  onFileUpload,
  onClearTraces,
  currentView = 'DASHBOARD',
  onViewChange,
  gatewayCount = 0,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);

  const navItems: { id: AppNavView; label: string; badge?: number }[] = [
    { id: 'DASHBOARD', label: 'Dashboard' },
    { id: 'ANALYSIS', label: 'PCAP Analysis' },
    { id: 'GATEWAYS', label: 'Gateways', badge: gatewayCount },
    { id: 'REPORTS', label: 'Reports' },
  ];

  return (
    <header className="bg-white border-b border-slate-200 sticky top-0 z-30 shadow-xs">
      <div className="max-w-7xl mx-auto px-4 sm:px-6">
        <div className="flex items-center justify-between h-14">
          
          {/* Brand / Logo */}
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-md bg-blue-600 flex items-center justify-center text-white shrink-0 shadow-xs">
              <Shield className="w-4 h-4" />
            </div>
            <div className="flex items-center gap-2">
              <span className="font-semibold text-slate-900 text-sm tracking-tight">
                VPN/PCAP Analyzer
              </span>
              <span className="hidden sm:inline-block text-[11px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                NTRO PS 26160
              </span>
            </div>
          </div>

          {/* Main Navigation Tabs */}
          <nav className="flex items-center space-x-1 sm:space-x-2">
            {navItems.map((item) => {
              const isActive = currentView === item.id;
              return (
                <button
                  key={item.id}
                  id={`nav-btn-${item.id.toLowerCase()}`}
                  onClick={() => onViewChange?.(item.id)}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                    isActive
                      ? 'bg-slate-100 text-slate-900 font-semibold'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                  }`}
                >
                  <span>{item.label}</span>
                  {item.badge !== undefined && item.badge > 0 && (
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.2 rounded-full font-medium ${
                        isActive
                          ? 'bg-blue-100 text-blue-700'
                          : 'bg-slate-200 text-slate-700'
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>

          {/* Right Utility Actions */}
          <div className="flex items-center gap-2">
            {/* Quick PCAP Upload Button */}
            <input
              type="file"
              ref={fileInputRef}
              onChange={onFileUpload}
              accept=".pcap,.pcapng,.cap"
              className="hidden"
            />
            <button
              id="btn-header-quick-upload"
              onClick={() => fileInputRef.current?.click()}
              className="hidden md:inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-slate-300 rounded-md transition-colors cursor-pointer"
              title="Upload and analyze a network capture file"
            >
              <Upload className="w-3.5 h-3.5 text-slate-500" />
              <span>Upload PCAP</span>
            </button>

            {/* Testbed Generator */}
            <button
              id="btn-open-testbed"
              onClick={onOpenTestbed}
              className="hidden lg:inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-slate-300 rounded-md transition-colors cursor-pointer"
              title="Generate synthetic or controlled testbed traffic"
            >
              <Sliders className="w-3.5 h-3.5 text-slate-500" />
              <span>Testbed</span>
            </button>

            {/* Status indicator */}
            <div className="flex items-center gap-1.5 pl-2 border-l border-slate-200 text-[11px] text-slate-500">
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
              <span className="hidden sm:inline">Engine Online</span>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};

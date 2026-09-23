import React from 'react';
import { ShieldCheck, ShieldAlert, ShieldX, Key, Activity, Layers, Lock, Unlock, ArrowRight } from 'lucide-react';
import { AiPrediction, IkeSecurityAssociation, SecurityScorecard } from '../types';

interface MetricCardsProps {
  sa: IkeSecurityAssociation;
  scorecard: SecurityScorecard;
  aiPrediction: AiPrediction;
  actualTrafficType: string;
}

export const MetricCards: React.FC<MetricCardsProps> = ({
  sa,
  scorecard,
  aiPrediction,
  actualTrafficType,
}) => {
  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-emerald-400 bg-emerald-950/60 border-emerald-800';
    if (score >= 70) return 'text-blue-400 bg-blue-950/60 border-blue-800';
    if (score >= 50) return 'text-amber-400 bg-amber-950/60 border-amber-800';
    return 'text-rose-400 bg-rose-950/60 border-rose-800';
  };

  const getScoreIcon = (score: number) => {
    if (score >= 80) return <ShieldCheck className="w-5 h-5 text-emerald-400" />;
    if (score >= 50) return <ShieldAlert className="w-5 h-5 text-amber-400" />;
    return <ShieldX className="w-5 h-5 text-rose-400" />;
  };

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      
      {/* 1. Security Scorecard */}
      <div id="card-security-score" className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm relative overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Security Posture
          </span>
          {getScoreIcon(scorecard.totalScore)}
        </div>

        <div className="mt-2.5 flex items-baseline gap-2">
          <span className="text-3xl font-extrabold tracking-tight text-white">
            {scorecard.totalScore}
          </span>
          <span className="text-sm font-semibold text-slate-400">/ 100</span>
          
          <span className={`ml-auto text-xs px-2.5 py-0.5 rounded-full border font-bold uppercase ${getScoreColor(scorecard.totalScore)}`}>
            {scorecard.rating}
          </span>
        </div>

        <div className="mt-3 flex items-center gap-1.5 flex-wrap text-[11px]">
          <span className={`px-1.5 py-0.5 rounded ${scorecard.complianceNist ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-rose-950/70 text-rose-300 border border-rose-900'}`}>
            {scorecard.complianceNist ? '✓ NIST SP 800-77' : '✗ NIST Non-Compliant'}
          </span>
          <span className={`px-1.5 py-0.5 rounded ${scorecard.complianceRfc8221 ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-rose-950/70 text-rose-300 border border-rose-900'}`}>
            {scorecard.complianceRfc8221 ? '✓ RFC 8221' : '✗ RFC Deprecated'}
          </span>
        </div>
      </div>

      {/* 2. Operational Mode & Tunnel Encapsulation */}
      <div id="card-operational-mode" className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            VPN Operating Mode
          </span>
          <Layers className="w-5 h-5 text-blue-400" />
        </div>

        <div className="mt-2.5">
          <div className="text-lg font-bold text-white flex items-center gap-2">
            <span>{sa.operationalMode}</span>
            <span className="text-xs px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
              {sa.ipVersion}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            {sa.operationalMode === 'Tunnel Mode'
              ? 'Full datagram encapsulated (Inner IP headers masked)'
              : 'End-to-end transport (Host-to-host IP exposed)'}
          </p>
        </div>

        <div className="mt-2 text-[11px] text-slate-400 border-t border-slate-800/80 pt-2 flex items-center justify-between">
          <span>Key Exchange: <strong className="text-slate-200">{sa.ikeVersion}</strong></span>
          <span>Lifetime: <strong className="text-slate-200">{sa.keyLifetimeSeconds === null ? 'Not observed' : `${sa.keyLifetimeSeconds / 3600}h`}</strong></span>
        </div>
      </div>

      {/* 3. AI Traffic Inference (Task c) */}
      <div id="card-ai-traffic" className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm relative">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            AI Inferred ESP Traffic
          </span>
          <Activity className="w-5 h-5 text-purple-400" />
        </div>

        <div className="mt-2.5">
          <div className="text-base font-bold text-white truncate" title={aiPrediction.predictedClass}>
            {aiPrediction.predictedClass}
          </div>
          <div className="flex items-center gap-2 mt-1.5">
            <div className="flex-1 bg-slate-800 rounded-full h-2 overflow-hidden">
              <div
                className="bg-gradient-to-r from-purple-500 to-blue-500 h-2 rounded-full transition-all duration-500"
                style={{ width: `${aiPrediction.confidenceScore}%` }}
              />
            </div>
            <span className="text-xs font-bold text-purple-300">
              {aiPrediction.confidenceScore}% Conf.
            </span>
          </div>
        </div>

        <div className="mt-2 text-[11px] text-slate-400 border-t border-slate-800/80 pt-2 flex items-center justify-between">
          <span>True Class:</span>
          <span className="font-semibold text-slate-200">{actualTrafficType.split(' (')[0]}</span>
        </div>
      </div>

      {/* 4. Cryptographic Suite & PFS */}
      <div id="card-crypto-suite" className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Cipher &amp; Key Exchange
          </span>
          <Key className="w-5 h-5 text-cyan-400" />
        </div>

        <div className="mt-2.5">
          <div className="text-sm font-bold text-white truncate" title={sa.encryptionAlgorithm}>
            {sa.encryptionAlgorithm}
          </div>
          <div className="text-xs text-slate-400 mt-0.5 truncate" title={sa.dhGroup}>
            {sa.dhGroup}
          </div>
        </div>

        <div className="mt-2.5 flex items-center justify-between border-t border-slate-800/80 pt-2 text-[11px]">
          <span className="text-slate-400">PFS Status:</span>
          {sa.pfsEnabled === null ? (
            <span className="font-semibold text-slate-400">Not determined</span>
          ) : sa.pfsEnabled ? (
            <span className="inline-flex items-center gap-1 font-semibold text-emerald-400">
              <Lock className="w-3 h-3" /> Enabled
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 font-semibold text-rose-400">
              <Unlock className="w-3 h-3" /> Disabled (Risk)
            </span>
          )}
        </div>
      </div>

    </div>
  );
};

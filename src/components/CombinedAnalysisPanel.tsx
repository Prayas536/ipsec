import React from 'react';
import {
  FileCode,
  Server,
  GitCompare,
  Clock,
  CheckCircle2,
  AlertCircle,
} from 'lucide-react';
import { GatewayCorrelationResult, GatewayTelemetrySummary, IkeSecurityAssociation } from '../types';

interface CombinedAnalysisPanelProps {
  sa: IkeSecurityAssociation;
  gatewayTelemetry: GatewayTelemetrySummary;
  correlation?: GatewayCorrelationResult | null;
  packetCount?: number;
}

export const CombinedAnalysisPanel: React.FC<CombinedAnalysisPanelProps> = ({
  sa,
  gatewayTelemetry,
  correlation,
  packetCount,
}) => {
  const isConfirmed =
    (correlation?.correlation_status === 'CONFIRMED' || gatewayTelemetry.correlationStatus === 'CONFIRMED') &&
    gatewayTelemetry.matchedSpis.length > 0;

  const pcapSpis: string[] = gatewayTelemetry.pcapSpis || [];
  const matchedSpis: string[] = gatewayTelemetry.matchedSpis || [];
  const unmatchedPcap: string[] = gatewayTelemetry.unmatchedPcapSpis || [];

  return (
    <div className="space-y-5">
      
      {/* Overview & Verdict Banner */}
      <div className="bg-white border border-slate-200 rounded-lg p-4 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200">
              MODE 3: COMBINED AUDIT
            </span>
            <span
              className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-semibold ${
                isConfirmed
                  ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                  : 'bg-amber-50 text-amber-700 border border-amber-200'
              }`}
            >
              {isConfirmed ? (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                  <span>Correlation Confirmed: Exact SPI Match</span>
                </>
              ) : (
                <>
                  <AlertCircle className="w-3.5 h-3.5 text-amber-600" />
                  <span>Correlation Status: Unknown</span>
                </>
              )}
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1 max-w-2xl">
            Correlating empirical packet evidence from network capture against authenticated StrongSwan daemon state using exact normalized hexadecimal SPI matching.
          </p>
        </div>

        <div className="flex items-center gap-4 text-xs font-mono shrink-0">
          <div className="bg-slate-50 border border-slate-200 rounded p-2 text-right">
            <span className="text-[10px] text-slate-400 block font-sans uppercase">Matched SPIs</span>
            <span className="font-bold text-slate-900">{matchedSpis.length} / {pcapSpis.length}</span>
          </div>
          <div className="bg-slate-50 border border-slate-200 rounded p-2 text-right">
            <span className="text-[10px] text-slate-400 block font-sans uppercase">Gateway Status</span>
            <span className="font-bold text-slate-900">{gatewayTelemetry.gatewayStatus}</span>
          </div>
        </div>
      </div>

      {/* 3 Explicit Evidence Tables (Section 14) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        
        {/* ========================================================================= */}
        {/* SECTION A: PCAP OBSERVED */}
        {/* ========================================================================= */}
        <div className="bg-white border border-slate-200 rounded-lg overflow-hidden shadow-xs flex flex-col justify-between">
          <div>
            <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-slate-500" />
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                  Section A: PCAP Observed
                </h4>
              </div>
              <span className="text-[11px] font-mono text-slate-500">Source: Capture</span>
            </div>

            <div className="p-4 space-y-3">
              <table className="w-full text-xs text-left">
                <tbody className="divide-y divide-slate-100">
                  <tr>
                    <td className="py-2 text-slate-500 font-medium w-28">Packets</td>
                    <td className="py-2 font-mono text-slate-900 font-semibold">{packetCount ? packetCount.toLocaleString() : 'N/A'}</td>
                  </tr>
                  <tr>
                    <td className="py-2 text-slate-500 font-medium">Protocol</td>
                    <td className="py-2 font-mono text-slate-900">{sa.operationalMode} ({sa.ipVersion})</td>
                  </tr>
                  <tr>
                    <td className="py-2 text-slate-500 font-medium">IKE Version</td>
                    <td className="py-2 font-mono text-slate-900">{sa.ikeVersion}</td>
                  </tr>
                  <tr>
                    <td className="py-2 text-slate-500 font-medium">Cipher</td>
                    <td className="py-2 font-mono text-slate-900 truncate" title={sa.encryptionAlgorithm}>
                      {sa.encryptionAlgorithm}
                    </td>
                  </tr>
                </tbody>
              </table>

              <div className="pt-2 border-t border-slate-100">
                <span className="text-[11px] font-semibold text-slate-600 block mb-1">
                  Observed ESP SPIs ({pcapSpis.length}):
                </span>
                {pcapSpis.length === 0 ? (
                  <span className="text-xs text-slate-400 italic">None detected</span>
                ) : (
                  <div className="flex flex-wrap gap-1">
                    {pcapSpis.map((spi, i) => (
                      <span
                        key={i}
                        className={`text-[11px] font-mono px-1.5 py-0.5 rounded border ${
                          matchedSpis.includes(spi)
                            ? 'bg-emerald-50 text-emerald-800 border-emerald-300 font-semibold'
                            : 'bg-slate-100 text-slate-700 border-slate-200'
                        }`}
                      >
                        {spi}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="px-4 py-2 bg-slate-50 border-t border-slate-200 text-[11px] text-slate-400">
            Empirical observation from captured frames.
          </div>
        </div>

        {/* ========================================================================= */}
        {/* SECTION B: GATEWAY OBSERVED */}
        {/* ========================================================================= */}
        <div className="bg-white border border-slate-200 rounded-lg overflow-hidden shadow-xs flex flex-col justify-between">
          <div>
            <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-slate-500" />
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                  Section B: Gateway Observed
                </h4>
              </div>
              <span className="text-[11px] font-mono text-slate-500">Source: Telemetry</span>
            </div>

            <div className="p-4 space-y-3">
              <table className="w-full text-xs text-left">
                <tbody className="divide-y divide-slate-100">
                  <tr>
                    <td className="py-2 text-slate-500 font-medium w-28">Gateway ID</td>
                    <td className="py-2 font-mono text-slate-900 truncate" title={gatewayTelemetry.gatewayId}>
                      {gatewayTelemetry.gatewayId || 'N/A'}
                    </td>
                  </tr>
                  <tr>
                    <td className="py-2 text-slate-500 font-medium">Adapter</td>
                    <td className="py-2 font-mono text-slate-900">{gatewayTelemetry.adapter || 'STRONGSWAN'}</td>
                  </tr>
                  <tr>
                    <td className="py-2 text-slate-500 font-medium">Collected At</td>
                    <td className="py-2 font-mono text-slate-900 text-[11px] truncate">
                      {gatewayTelemetry.collectedAt || 'N/A'}
                    </td>
                  </tr>
                </tbody>
              </table>

              <div className="pt-2 border-t border-slate-100">
                <span className="text-[11px] font-semibold text-slate-600 block mb-1">
                  Active SA Records ({gatewayTelemetry.telemetry?.length || 0}):
                </span>
                {(!gatewayTelemetry.telemetry || gatewayTelemetry.telemetry.length === 0) ? (
                  <span className="text-xs text-slate-400 italic">No SA records reported</span>
                ) : (
                  <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
                    {gatewayTelemetry.telemetry.map((rawT, idx) => {
                      const t = rawT as Record<string, any>;
                      return (
                        <div key={idx} className="p-2 rounded bg-slate-50 border border-slate-200 text-[11px] font-mono">
                          <div className="font-semibold text-slate-800">{String(t.name || `SA #${idx + 1}`)}</div>
                          <div className="text-slate-600">
                            Inbound: {String(t.inbound_spi || t.spi || 'N/A')}
                            {t.outbound_spi ? ` | Outbound: ${String(t.outbound_spi)}` : ''}
                          </div>
                          {t.encr ? <div className="text-slate-500">Cipher: {String(t.encr)}</div> : null}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="px-4 py-2 bg-slate-50 border-t border-slate-200 text-[11px] text-slate-400">
            Reported directly from local kernel/daemon via VICI.
          </div>
        </div>

        {/* ========================================================================= */}
        {/* SECTION C: CORRELATION */}
        {/* ========================================================================= */}
        <div className="bg-white border border-slate-200 rounded-lg overflow-hidden shadow-xs flex flex-col justify-between">
          <div>
            <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <GitCompare className="w-4 h-4 text-slate-500" />
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                  Section C: Correlation
                </h4>
              </div>
              <span className={`text-[11px] font-mono font-semibold ${isConfirmed ? 'text-emerald-700' : 'text-amber-700'}`}>
                {isConfirmed ? 'CONFIRMED' : 'UNKNOWN'}
              </span>
            </div>

            <div className="p-4 space-y-3">
              <div>
                <span className="text-[11px] font-semibold text-slate-600 block mb-1">
                  Exact Matched SPIs ({matchedSpis.length}):
                </span>
                {matchedSpis.length === 0 ? (
                  <div className="p-2 rounded bg-amber-50 border border-amber-200 text-xs text-amber-800">
                    No matching SPIs between PCAP packets and active gateway SAs.
                  </div>
                ) : (
                  <div className="flex flex-wrap gap-1">
                    {matchedSpis.map((spi, i) => (
                      <span
                        key={i}
                        className="font-mono text-[11px] px-2 py-0.5 rounded bg-emerald-50 text-emerald-800 border border-emerald-300 font-semibold"
                      >
                        {spi}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {unmatchedPcap.length > 0 && (
                <div>
                  <span className="text-[11px] font-semibold text-slate-600 block mb-1">
                    Unmatched PCAP SPIs ({unmatchedPcap.length}):
                  </span>
                  <div className="text-[11px] font-mono text-slate-500 truncate" title={unmatchedPcap.join(', ')}>
                    {unmatchedPcap.slice(0, 4).join(', ')}
                    {unmatchedPcap.length > 4 ? ` (+${unmatchedPcap.length - 4} more)` : ''}
                  </div>
                </div>
              )}

              <div className="pt-2 border-t border-slate-100">
                <span className="text-[11px] font-semibold text-slate-600 block mb-1">
                  Technical Evidence &amp; Justification:
                </span>
                <p className="text-xs text-slate-600 leading-relaxed">
                  {isConfirmed
                    ? 'Exact normalized hex SPI match established between observed ESP packets and active gateway Child SA.'
                    : 'No cryptographic correspondence could be verified with current gateway state.'}
                </p>
              </div>

              {gatewayTelemetry.evidence && gatewayTelemetry.evidence.length > 0 && (
                <div className="pt-2 border-t border-slate-100">
                  <span className="text-[10px] uppercase font-semibold text-slate-400 block mb-1">
                    Audit Trail:
                  </span>
                  <ul className="text-[11px] font-mono text-slate-600 list-disc list-inside space-y-0.5">
                    {gatewayTelemetry.evidence.slice(0, 3).map((evi, i) => (
                      <li key={i}>{evi}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>

          <div className="px-4 py-2 bg-slate-50 border-t border-slate-200 text-[11px] text-slate-400">
            Deterministic hex comparison only. No heuristic guessing.
          </div>
        </div>

      </div>

    </div>
  );
};

import React from 'react';
import { ShieldCheck, AlertTriangle, CheckCircle2, XCircle, Wrench } from 'lucide-react';
import { SecurityScorecard, IkeSecurityAssociation, GatewayCorrelationResult, GatewayTelemetrySummary } from '../types';
import { CombinedAnalysisPanel } from './CombinedAnalysisPanel';

interface SecurityAssessmentProps {
  scorecard: SecurityScorecard;
  sa: IkeSecurityAssociation;
  gatewayTelemetry?: GatewayTelemetrySummary;
  correlation?: GatewayCorrelationResult;
}

export const SecurityAssessment: React.FC<SecurityAssessmentProps> = ({
  scorecard,
  sa,
  gatewayTelemetry,
  correlation,
}) => {
  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return 'bg-rose-50 text-rose-700 border-rose-200';
      case 'High':
        return 'bg-orange-50 text-orange-700 border-orange-200';
      case 'Medium':
        return 'bg-amber-50 text-amber-700 border-amber-200';
      case 'Low':
        return 'bg-slate-100 text-slate-700 border-slate-200';
      default:
        return 'bg-emerald-50 text-emerald-700 border-emerald-200';
    }
  };

  const observations = sa.observations;

  return (
    <div className="space-y-6">
      
      {/* Mode 3 Combined Analysis Panel if Gateway Telemetry is present */}
      {gatewayTelemetry && (
        <CombinedAnalysisPanel
          sa={sa}
          gatewayTelemetry={gatewayTelemetry}
          correlation={correlation}
        />
      )}

      {/* 1. Cryptographic Parameter Audit Table (Section 10) */}
      <div className="bg-white border border-slate-200 rounded-lg shadow-xs overflow-hidden">
        <div className="p-4 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-semibold text-slate-900">
              Cryptographic Parameter Audit &amp; Compliance Matrix
            </h3>
            <p className="text-xs text-slate-500">
              Evaluated against NIST SP 800-77 Rev. 1, RFC 8221, and NSA CNSA standards
            </p>
          </div>
          <div className="text-xs text-slate-500">
            Total Penalty: <span className="font-mono font-bold text-slate-900">-{100 - scorecard.totalScore} pts</span>
          </div>
        </div>

        {/* Findings Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs table-compact">
            <thead>
              <tr>
                <th>Security Parameter</th>
                <th>Detected Configuration</th>
                <th>Standard Requirement</th>
                <th>Severity</th>
                <th className="text-right">Score Impact</th>
              </tr>
            </thead>
            <tbody>
              {scorecard.findings.map((f) => (
                <tr key={f.id} className="hover:bg-slate-50">
                  <td className="font-medium text-slate-900">{f.parameter}</td>
                  <td className="font-mono text-slate-700">{f.detectedValue}</td>
                  <td className="text-slate-600">{f.recommendedValue}</td>
                  <td>
                    <span className={`inline-block px-2 py-0.5 rounded text-[11px] font-semibold border ${getSeverityBadge(f.severity)}`}>
                      {f.severity}
                    </span>
                  </td>
                  <td className="text-right font-mono font-medium">
                    {f.penalty > 0 ? (
                      <span className="text-rose-600">-{f.penalty}</span>
                    ) : (
                      <span className="text-slate-400">0</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* 2. Structured IPsec / IKE Protocol Attributes Table (Section 10) */}
      <div className="bg-white border border-slate-200 rounded-lg shadow-xs overflow-hidden">
        <div className="p-4 border-b border-slate-200">
          <h3 className="text-sm font-semibold text-slate-900">IPsec / IKE Negotiation Details</h3>
          <p className="text-xs text-slate-500">Specific transform parameters extracted from the capture session</p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs table-compact">
            <thead>
              <tr>
                <th className="w-1/3">Field</th>
                <th>Value</th>
                <th>Standard Reference</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td className="font-medium text-slate-900">IKE Protocol Version</td>
                <td className="font-mono text-slate-700">{sa.ikeVersion}</td>
                <td className="text-slate-500">RFC 7296 (IKEv2)</td>
              </tr>
              <tr>
                <td className="font-medium text-slate-900">Operating Mode</td>
                <td className="font-mono text-slate-700">{sa.operationalMode} ({sa.ipVersion})</td>
                <td className="text-slate-500">RFC 4301 Security Architecture</td>
              </tr>
              <tr>
                <td className="font-medium text-slate-900">Encryption Algorithm (Cipher)</td>
                <td className="font-mono text-slate-700">{sa.encryptionAlgorithm} ({sa.encryptionKeyBits}-bit)</td>
                <td className="text-slate-500">NIST SP 800-77 (AES-GCM / AES-CBC)</td>
              </tr>
              <tr>
                <td className="font-medium text-slate-900">Integrity / Hash Function</td>
                <td className="font-mono text-slate-700">{sa.authIntegrityAlgorithm}</td>
                <td className="text-slate-500">RFC 8221 (SHA-256 or AEAD recommended)</td>
              </tr>
              <tr>
                <td className="font-medium text-slate-900">Diffie-Hellman Group</td>
                <td className="font-mono text-slate-700">{sa.dhGroup} ({sa.dhBits}-bit)</td>
                <td className="text-slate-500">NIST SP 800-56A (Group 14+ / 2048-bit min)</td>
              </tr>
              <tr>
                <td className="font-medium text-slate-900">Perfect Forward Secrecy (PFS)</td>
                <td className="font-mono text-slate-700">
                  {sa.pfsEnabled === null ? 'Not determined from capture' : sa.pfsEnabled ? 'Enabled' : 'Disabled'}
                </td>
                <td className="text-slate-500">Mandatory per NIST SP 800-77 Section 4.2</td>
              </tr>
              <tr>
                <td className="font-medium text-slate-900">Replay Protection</td>
                <td className="font-mono text-slate-700">
                  {sa.replayProtection === null ? 'Not determined' : sa.replayProtection ? `Enabled (Window: ${sa.replayWindowSize || 64})` : 'Disabled'}
                </td>
                <td className="text-slate-500">RFC 4303 Anti-Replay Service</td>
              </tr>
              <tr>
                <td className="font-medium text-slate-900">SA Lifetime</td>
                <td className="font-mono text-slate-700">
                  {sa.keyLifetimeSeconds === null ? 'Not observed' : `${sa.keyLifetimeSeconds / 3600} hours (${sa.keyLifetimeSeconds}s)`}
                </td>
                <td className="text-slate-500">Maximum recommended: 8-24 hours</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* 3. Wire-Visible Capture Observations Table */}
      {observations && (
        <div className="bg-white border border-slate-200 rounded-lg shadow-xs overflow-hidden">
          <div className="p-4 border-b border-slate-200">
            <h3 className="text-sm font-semibold text-slate-900">Wire-Visible Frame Observations</h3>
            <p className="text-xs text-slate-500">
              Deterministic protocol counts and sequence range data observed on the wire
            </p>
          </div>

          <div className="p-4 grid grid-cols-2 md:grid-cols-4 gap-3 bg-slate-50/50">
            {[
              ['Total Packets', observations.totalPackets],
              ['IKE Frames', observations.ikePackets],
              ['ESP Packets', observations.espPackets],
              ['AH Packets', observations.ahPackets],
              ['UDP Packets', observations.udpPackets],
              ['TCP Packets', observations.tcpPackets],
              ['ICMP Packets', observations.icmpPackets],
              ['NAT Traversal', observations.natTraversal],
            ].map(([label, value]) => (
              <div key={label} className="bg-white border border-slate-200 rounded p-2.5">
                <span className="text-[11px] text-slate-500 block">{label}</span>
                <span className="font-mono font-semibold text-slate-900 text-sm mt-0.5 block">{value}</span>
              </div>
            ))}
          </div>

          <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs border-t border-slate-200">
            <div className="space-y-1.5 font-mono text-slate-700">
              <div><span className="font-sans text-slate-500">IKE Exchanges:</span> {observations.ikeExchanges.join(', ') || 'None'}</div>
              <div><span className="font-sans text-slate-500">IKE Payloads:</span> {observations.ikePayloads.join(', ') || 'None'}</div>
              <div><span className="font-sans text-slate-500">Vendor IDs:</span> {observations.ikeVendorIds.join(', ') || 'None'}</div>
              <div><span className="font-sans text-slate-500">NAT Detection:</span> {observations.natDetection}</div>
            </div>
            <div className="space-y-1.5 font-mono text-slate-700">
              <div><span className="font-sans text-slate-500">ESP SPIs:</span> {observations.espSpis.join(', ') || 'None'}</div>
              <div><span className="font-sans text-slate-500">ESP Sequence Range:</span> {observations.espSequenceRange}</div>
              <div><span className="font-sans text-slate-500">Capture Duration:</span> {observations.captureDurationMs.toFixed(1)} ms</div>
              {observations.captureNotes.map((note, i) => (
                <div key={i} className="text-amber-700 font-sans">Note: {note}</div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 4. Threat Matrix & Remediation Actions */}
      <div className="bg-white border border-slate-200 rounded-lg shadow-xs overflow-hidden">
        <div className="p-4 border-b border-slate-200">
          <h3 className="text-sm font-semibold text-slate-900">
            Identified Threat Vectors &amp; Remediation Plan
          </h3>
          <p className="text-xs text-slate-500">
            Tactical security risks of detected weak configurations with mitigation guidelines
          </p>
        </div>

        {scorecard.findings.filter((f) => f.severity !== 'Pass').length === 0 ? (
          <div className="p-6 text-center text-emerald-700">
            <CheckCircle2 className="w-6 h-6 mx-auto mb-1 text-emerald-600" />
            <span className="text-xs font-semibold">No critical or high-risk vulnerabilities identified.</span>
          </div>
        ) : (
          <div className="divide-y divide-slate-100">
            {scorecard.findings
              .filter((f) => f.severity !== 'Pass')
              .map((f) => (
                <div key={f.id} className="p-4 space-y-2 hover:bg-slate-50">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${getSeverityBadge(f.severity)}`}>
                        {f.severity}
                      </span>
                      <span className="font-semibold text-slate-900 text-xs">{f.threatName}</span>
                      <span className="text-[11px] text-slate-400 font-mono">({f.parameter})</span>
                    </div>
                    {f.cveReference && (
                      <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
                        {f.cveReference}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-600 leading-relaxed">{f.description}</p>
                  <div className="pt-2 flex items-start gap-1.5 text-xs text-slate-700 bg-slate-50 p-2.5 rounded border border-slate-200">
                    <Wrench className="w-3.5 h-3.5 text-blue-600 shrink-0 mt-0.5" />
                    <div>
                      <strong className="text-slate-900">Remediation:</strong> {f.remediation}
                    </div>
                  </div>
                </div>
              ))}
          </div>
        )}
      </div>

    </div>
  );
};

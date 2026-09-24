import React from 'react';
import { Info } from 'lucide-react';
import { AiPrediction, EspTrafficFeatures } from '../types';

interface AiTrafficAnalysisProps {
  features: EspTrafficFeatures;
  prediction: AiPrediction;
}

export const AiTrafficAnalysis: React.FC<AiTrafficAnalysisProps> = ({ features, prediction }) => {
  return (
    <div className="space-y-6">
      
      {/* Section Info Banner */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-3 flex items-start gap-3">
        <Info className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
        <div className="text-xs text-blue-800">
          <strong>Where AI operates:</strong> ESP payloads are cryptographically unreadable. The classifier analyzes statistical frame patterns — packet length distribution, inter-arrival timing, burst cadence, and flow symmetry — to infer workload type without breaking encryption.
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* Classification Results */}
        <div className="bg-white border border-slate-200 rounded-lg shadow-xs overflow-hidden">
          <div className="p-4 border-b border-slate-200 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-slate-900">Traffic Classification</h3>
              <p className="text-xs text-slate-500">Supervised Random Forest · Softmax normalized</p>
            </div>
            <div className="text-right">
              <span className="text-xs font-medium text-slate-500 block">Top prediction</span>
              <span className="text-sm font-bold text-slate-900">{prediction.predictedClass}</span>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs table-compact">
              <thead>
                <tr>
                  <th>Traffic Class</th>
                  <th>Probability</th>
                  <th className="w-40">Distribution</th>
                </tr>
              </thead>
              <tbody>
                {prediction.probabilities.map((item) => {
                  const isTop = item.category === prediction.predictedClass;
                  return (
                    <tr key={item.category} className={isTop ? 'bg-blue-50' : 'hover:bg-slate-50'}>
                      <td className={`font-medium ${isTop ? 'text-blue-800' : 'text-slate-700'}`}>
                        <span className={isTop ? 'font-bold' : ''}>{item.category}</span>
                      </td>
                      <td className="font-mono font-semibold text-slate-900">{item.probability}%</td>
                      <td>
                        <div className="w-full bg-slate-200 rounded-full h-1.5 overflow-hidden">
                          <div
                            className={`h-1.5 rounded-full transition-all duration-300 ${isTop ? 'bg-blue-600' : 'bg-slate-400'}`}
                            style={{ width: `${Math.max(item.probability, 2)}%` }}
                          />
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className="px-4 py-3 bg-slate-50 border-t border-slate-200 flex items-center justify-between text-xs">
            <span className="text-slate-500">Model confidence</span>
            <span className="font-mono font-bold text-slate-900">{prediction.confidenceScore}%</span>
          </div>
        </div>

        {/* Extracted Flow Features */}
        <div className="bg-white border border-slate-200 rounded-lg shadow-xs overflow-hidden">
          <div className="p-4 border-b border-slate-200">
            <h3 className="text-sm font-semibold text-slate-900">Extracted Flow Features</h3>
            <p className="text-xs text-slate-500">Statistical shape characteristics used for classification</p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs table-compact">
              <thead>
                <tr>
                  <th>Feature</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td className="text-slate-600">Payload Entropy (bits)</td>
                  <td className="font-mono font-semibold text-slate-900">{features.calculatedEntropy?.toFixed(4) ?? 'N/A'}</td>
                </tr>
                <tr>
                  <td className="text-slate-600">Avg Packet Length (bytes)</td>
                  <td className="font-mono font-semibold text-slate-900">{features.meanPacketLength?.toFixed(1) ?? 'N/A'}</td>
                </tr>
                <tr>
                  <td className="text-slate-600">Std Dev Packet Length</td>
                  <td className="font-mono font-semibold text-slate-900">{features.stdPacketLength?.toFixed(1) ?? 'N/A'}</td>
                </tr>
                <tr>
                  <td className="text-slate-600">Mean Inter-Arrival Time (ms)</td>
                  <td className="font-mono font-semibold text-slate-900">{features.meanInterArrivalTimeMs?.toFixed(2) ?? 'N/A'}</td>
                </tr>
                <tr>
                  <td className="text-slate-600">Flow Duration (ms)</td>
                  <td className="font-mono font-semibold text-slate-900">{features.flowDurationMs?.toFixed(1) ?? 'N/A'}</td>
                </tr>
                <tr>
                  <td className="text-slate-600">ESP Packet Count</td>
                  <td className="font-mono font-semibold text-slate-900">{features.packetCount ?? 'N/A'}</td>
                </tr>
                <tr>
                  <td className="text-slate-600">Burst Ratio</td>
                  <td className="font-mono font-semibold text-slate-900">{features.burstRatio?.toFixed(2) ?? 'N/A'}</td>
                </tr>
                <tr>
                  <td className="text-slate-600">Flow Symmetry Ratio</td>
                  <td className="font-mono font-semibold text-slate-900">{features.flowSymmetry?.toFixed(3) ?? 'N/A'}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </div>
  );
};

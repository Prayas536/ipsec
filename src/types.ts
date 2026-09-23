export type IkeVersion = 'IKEv1' | 'IKEv2' | 'Not observed in capture';
export type OperationalMode = 'Tunnel Mode' | 'Transport Mode' | 'Not determined from capture';
export type IpVersion = 'IPv4' | 'IPv6' | 'Not observed in capture';

export type EvidenceConfidence = 'exact' | 'heuristic' | 'unavailable';

export interface EvidenceRecord {
  value: string | number | boolean | null;
  confidence: EvidenceConfidence;
  source: string;
  packetNumber?: number;
  rawBytes?: string;
  fieldPath: string;
}

export interface ParsedTransform {
  type: number;
  id: number;
  name: string;
  attributes: Record<number, number>;
  attributeRawBytes?: Record<number, string>;
  rawBytes: string;
  packetNumber: number;
}

export interface ParsedProposal {
  number: number;
  protocolId: number;
  spi: string;
  transforms: ParsedTransform[];
  packetNumber: number;
}

export type TrafficCategory = 
  | 'VoIP / Audio Call'
  | 'Video Streaming'
  | 'Web Browsing / HTTPS'
  | 'Bulk Data Transfer (DB/FTP)'
  | 'Telemetry / Heartbeat (ICMP)'
  | 'Live Real Capture';

export interface PacketInfo {
  id: number;
  timestamp: number; // relative ms
  sourceIp: string;
  destIp: string;
  protocol: 'IKE' | 'ESP' | 'AH' | 'ICMP' | 'UDP' | 'OTHER';
  length: number;
  info: string;
  spi?: string;
  seq?: number;
  rawPreview?: string;
  sourcePort?: number;
  destPort?: number;
  ipVersion?: IpVersion;
  debug?: string;
}

export interface IkeSecurityAssociation {
  ikeVersion: IkeVersion;
  operationalMode: OperationalMode;
  ipVersion: IpVersion;
  encryptionAlgorithm: string;
  encryptionKeyBits: number;
  authIntegrityAlgorithm: string;
  dhGroup: string;
  dhGroupNumber: number;
  dhBits: number;
  pfsEnabled: boolean | null;
  keyLifetimeSeconds: number | null;
  replayProtection: boolean | null;
  replayWindowSize?: number | null;
  initiatorSpi: string;
  responderSpi: string;
  proposals?: ParsedProposal[];
  evidence?: EvidenceRecord[];
}

export interface EspTrafficFeatures {
  packetCount: number;
  totalBytes: number;
  meanPacketLength: number;
  stdPacketLength: number;
  minPacketLength: number;
  maxPacketLength: number;
  meanInterArrivalTimeMs: number;
  burstRatio: number;
  flowSymmetry: number; // 0-1 ratio between uplink and downlink
  calculatedEntropy: number; // 0-8 bits per byte
}

export interface AiPrediction {
  predictedClass: TrafficCategory;
  confidenceScore: number; // 0-100
  probabilities: {
    category: TrafficCategory;
    probability: number; // 0-100
  }[];
  primaryFeatures: {
    name: string;
    value: string;
    impact: 'Supporting' | 'Neutral' | 'Contradicting';
    explanation: string;
  }[];
}

export interface SecurityFinding {
  id: string;
  parameter: string;
  detectedValue: string;
  recommendedValue: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Pass';
  penalty: number;
  cveReference?: string;
  threatName: string;
  description: string;
  remediation: string;
}

export interface SecurityScorecard {
  totalScore: number; // 0-100
  rating: 'Hardened' | 'Secure' | 'Moderate' | 'Weak' | 'Critical';
  findings: SecurityFinding[];
  complianceNist: boolean;
  complianceRfc8221: boolean;
  complianceNsaCnsa: boolean;
  metadataLeakageRisk: 'High' | 'Medium' | 'Low';
}

export interface VpnCaptureScenario {
  id: string;
  name: string;
  organization: string;
  badge: string;
  description: string;
  sa: IkeSecurityAssociation;
  features: EspTrafficFeatures;
  packets: PacketInfo[];
  actualTrafficType: TrafficCategory;
}

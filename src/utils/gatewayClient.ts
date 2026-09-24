import type {
  GatewayEnrollmentResult,
  GatewaySummary,
  GatewayTelemetrySummary,
} from '../types';
import { getApiBaseUrl, buildGatewayTelemetrySummary } from './scapyClient';

export async function fetchGateways(): Promise<GatewaySummary[]> {
  const response = await fetch(`${getApiBaseUrl()}/api/gateways`);
  if (!response.ok) {
    throw new Error(`Failed to fetch gateways (HTTP ${response.status})`);
  }
  return (await response.json()) as GatewaySummary[];
}

export async function fetchGateway(
  gatewayId: string,
): Promise<GatewaySummary | null> {
  const response = await fetch(
    `${getApiBaseUrl()}/api/gateways/${encodeURIComponent(gatewayId)}`,
  );
  if (response.status === 404) {
    return null;
  }
  if (!response.ok) {
    throw new Error(`Failed to fetch gateway ${gatewayId} (HTTP ${response.status})`);
  }
  return (await response.json()) as GatewaySummary;
}

export async function createGateway(
  displayName: string,
  gatewayType: string = 'STRONGSWAN',
): Promise<GatewayEnrollmentResult> {
  const response = await fetch(`${getApiBaseUrl()}/api/gateways`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: jsonStringify({
      display_name: displayName,
      gateway_type: gatewayType,
    }),
  });

  const payload = (await response.json()) as
    | GatewayEnrollmentResult
    | { error?: string; detail?: string };

  if (!response.ok || 'error' in payload) {
    const errorMsg =
      ('error' in payload && (payload.error ?? payload.detail)) ||
      'Gateway registration failed';
    throw new Error(errorMsg);
  }

  return payload as GatewayEnrollmentResult;
}

export async function regenerateEnrollmentToken(
  gatewayId: string,
): Promise<{ enrollment_token: string; expires_at: number }> {
  const response = await fetch(
    `${getApiBaseUrl()}/api/gateways/${encodeURIComponent(gatewayId)}/token`,
    {
      method: 'POST',
    },
  );

  const payload = (await response.json()) as
    | { enrollment_token: string; expires_at: number }
    | { error?: string };

  if (!response.ok || 'error' in payload) {
    throw new Error(('error' in payload && payload.error) || 'Failed to regenerate token');
  }

  return payload as { enrollment_token: string; expires_at: number };
}

export async function revokeGateway(gatewayId: string): Promise<boolean> {
  const response = await fetch(
    `${getApiBaseUrl()}/api/gateways/${encodeURIComponent(gatewayId)}/revoke`,
    {
      method: 'POST',
    },
  );
  if (!response.ok) {
    throw new Error(`Failed to revoke gateway (HTTP ${response.status})`);
  }
  return true;
}

export async function removeGateway(gatewayId: string): Promise<boolean> {
  const response = await fetch(
    `${getApiBaseUrl()}/api/gateways/${encodeURIComponent(gatewayId)}`,
    {
      method: 'DELETE',
    },
  );
  if (!response.ok) {
    throw new Error(`Failed to remove gateway (HTTP ${response.status})`);
  }
  return true;
}

export async function correlateWithGateway(
  analysisId: string,
  gatewayId: string,
): Promise<GatewayTelemetrySummary | null> {
  const response = await fetch(
    `${getApiBaseUrl()}/api/analysis/${encodeURIComponent(analysisId)}/correlate`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: jsonStringify({ gateway_id: gatewayId }),
    },
  );

  if (!response.ok) {
    return null;
  }

  const payload = (await response.json()) as any;
  return buildGatewayTelemetrySummary({
    analysisId: payload.analysisId ?? analysisId,
    pcapSpis: payload.pcapSpis ?? [],
    telemetry: payload.telemetry ?? [],
    correlation: payload.correlation ?? null,
  });
}

function jsonStringify(obj: unknown): string {
  return JSON.stringify(obj);
}

export function getInstallCommand(serverUrl: string): string {
  const target = serverUrl.replace(/\/$/, '');
  return `curl -sSL ${target}/api/agent/install.sh | bash`;
}

export function getEnrollCommand(serverUrl: string, token: string): string {
  const target = serverUrl.replace(/\/$/, '');
  return `vpn-analyzer-agent enroll --server ${target} --token ${token}`;
}

export function getStartCommand(): string {
  return `vpn-analyzer-agent run`;
}

export function getDownloadUrl(serverUrl: string): string {
  const target = serverUrl.replace(/\/$/, '');
  return `${target}/api/agent/download`;
}

export interface GatewaySecurityReport {
  reportType: 'GATEWAY_SECURITY_REPORT';
  reportGeneratedAt: string;
  gateway: {
    gateway_id: string;
    display_name: string;
    gateway_type: string;
    status: string;
    enrolled_at?: string | null;
    last_seen_at?: string | null;
    agent_version?: string | null;
    telemetry_adapter: string;
    active_ike_sa_count: number;
    active_child_sa_count: number;
  };
  telemetry: {
    status: string;
    adapter: string;
    collectedAt?: string | null;
    receivedAt?: string | null;
    ikeRecords: Record<string, unknown>[];
    childRecords: Record<string, unknown>[];
    evidence: string[];
  };
  securityAssessment: {
    findings: Array<{ category: string; severity: string; value: string; detail: string }>;
    source: string;
    limitations: string[];
  };
}

export async function fetchGatewayReport(gatewayId: string): Promise<GatewaySecurityReport> {
  const response = await fetch(
    `${getApiBaseUrl()}/api/gateways/${encodeURIComponent(gatewayId)}/report`,
  );
  if (!response.ok) {
    const payload = await response.json().catch(() => ({})) as { error?: string };
    throw new Error(payload.error ?? `Failed to generate gateway report (HTTP ${response.status})`);
  }
  return (await response.json()) as GatewaySecurityReport;
}

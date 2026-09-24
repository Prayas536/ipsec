import assert from 'node:assert/strict';
import test from 'node:test';
import { auditIpsecSecurity } from '../src/utils/securityAuditor';

test('unknown cryptography cannot be reported as standards compliant', () => {
  const scorecard = auditIpsecSecurity({
    ikeVersion: 'IKEv2',
    operationalMode: 'Not determined from capture',
    ipVersion: 'IPv4',
    encryptionAlgorithm: 'Not observed in capture',
    encryptionKeyBits: 0,
    authIntegrityAlgorithm: 'Not observed in capture',
    dhGroup: 'Not observed in capture',
    dhGroupNumber: 0,
    dhBits: 0,
    pfsEnabled: null,
    keyLifetimeSeconds: null,
    replayProtection: null,
    initiatorSpi: '0x1',
    responderSpi: 'Not observed in capture',
    proposals: [],
  });

  assert.equal(scorecard.complianceNist, false);
  assert.equal(scorecard.complianceRfc8221, false);
  assert.equal(scorecard.complianceNsaCnsa, false);
});
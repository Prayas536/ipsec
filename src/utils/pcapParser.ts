import {
  EvidenceRecord,
  EspTrafficFeatures,
  IkeSecurityAssociation,
  ParsedProposal,
  ParsedTransform,
  PacketInfo,
  VpnCaptureScenario,
} from '../types';

import { calculateEntropy } from './aiClassifier';

export interface ParsedPcapResult {
  scenarioName: string;
  packets: PacketInfo[];
  sa: IkeSecurityAssociation;
  features: EspTrafficFeatures;
  fileSizeBytes: number;
  evidence: EvidenceRecord[];
}

/* =========================================================
   Constants
========================================================= */

const PCAP_MAGIC_BE_USEC = 0xa1b2c3d4;
const PCAP_MAGIC_LE_USEC = 0xd4c3b2a1;
const PCAP_MAGIC_BE_NSEC = 0xa1b23c4d;
const PCAP_MAGIC_LE_NSEC = 0x4d3cb2a1;

const LINKTYPE_ETHERNET = 1;
const LINKTYPE_RAW = 101;
const LINKTYPE_LINUX_SLL = 113;
const LINKTYPE_LINUX_SLL2 = 276;

const ETHERTYPE_IPV4 = 0x0800;
const ETHERTYPE_IPV6 = 0x86dd;
const ETHERTYPE_VLAN = 0x8100;
const ETHERTYPE_QINQ = 0x88a8;
const ETHERTYPE_QINQ2 = 0x9100;

const IPPROTO_ICMP = 1;
const IPPROTO_TCP = 6;
const IPPROTO_UDP = 17;
const IPPROTO_AH = 51;
const IPPROTO_ESP = 50;

/* IKEv2 exchange types */
const IKE_SA_INIT = 34;
const IKE_AUTH = 35;
const CREATE_CHILD_SA = 36;

/* IKEv2 payload types */
const IKE_PAYLOAD_NONE = 0;
const IKE_PAYLOAD_SA = 33;
const IKE_PAYLOAD_KE = 34;
const IKE_PAYLOAD_IDi = 35;
const IKE_PAYLOAD_IDr = 36;
const IKE_PAYLOAD_CERT = 37;
const IKE_PAYLOAD_CERTREQ = 38;
const IKE_PAYLOAD_AUTH = 39;
const IKE_PAYLOAD_NONCE = 40;
const IKE_PAYLOAD_NOTIFY = 41;
const IKE_PAYLOAD_DELETE = 42;
const IKE_PAYLOAD_VENDOR = 43;
const IKE_PAYLOAD_TSi = 44;
const IKE_PAYLOAD_TSr = 45;
const IKE_PAYLOAD_ENCRYPTED = 46;
const IKE_PAYLOAD_CONFIGURATION = 47;
const IKE_PAYLOAD_EAP = 48;
const IKE_PAYLOAD_GSPM = 49;
const IKE_PAYLOAD_GROUP = 50;

/* IKEv2 transform types */
const TRANSFORM_ENCR = 1;
const TRANSFORM_PRF = 2;
const TRANSFORM_INTEG = 3;
const TRANSFORM_DH = 4;
const TRANSFORM_ESN = 5;

/* IKEv2 transform attributes */
const ATTR_KEY_LENGTH = 14;

/* =========================================================
   Small helpers
========================================================= */

function hex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hex0x(bytes: Uint8Array): string {
  return `0x${hex(bytes)}`;
}

function readU16(
  bytes: Uint8Array,
  offset: number,
  littleEndian = false
): number {
  if (offset + 2 > bytes.length) return 0;

  return littleEndian
    ? bytes[offset] | (bytes[offset + 1] << 8)
    : (bytes[offset] << 8) | bytes[offset + 1];
}

function readU32(
  bytes: Uint8Array,
  offset: number,
  littleEndian = false
): number {
  if (offset + 4 > bytes.length) return 0;

  if (littleEndian) {
    return (
      bytes[offset] |
      (bytes[offset + 1] << 8) |
      (bytes[offset + 2] << 16) |
      (bytes[offset + 3] * 0x1000000)
    ) >>> 0;
  }

  return (
    (bytes[offset] * 0x1000000) |
    (bytes[offset + 1] << 16) |
    (bytes[offset + 2] << 8) |
    bytes[offset + 3]
  ) >>> 0;
}

function readU64Hex(bytes: Uint8Array, offset: number): string {
  if (offset + 8 > bytes.length) return '0x0000000000000000';

  return `0x${hex(bytes.slice(offset, offset + 8))}`;
}

function ipv4ToString(bytes: Uint8Array, offset: number): string {
  if (offset + 4 > bytes.length) return 'Unknown';

  return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
}

function ipv6ToString(bytes: Uint8Array, offset: number): string {
  if (offset + 16 > bytes.length) return 'Unknown';

  const groups: string[] = [];

  for (let i = 0; i < 16; i += 2) {
    groups.push(
      ((bytes[offset + i] << 8) | bytes[offset + i + 1])
        .toString(16)
        .padStart(4, '0')
    );
  }

  return groups.join(':');
}

function isZero4(bytes: Uint8Array, offset: number): boolean {
  return (
    offset + 4 <= bytes.length &&
    bytes[offset] === 0 &&
    bytes[offset + 1] === 0 &&
    bytes[offset + 2] === 0 &&
    bytes[offset + 3] === 0
  );
}

function payloadName(type: number): string {
  const names: Record<number, string> = {
    33: 'SA',
    34: 'KE',
    35: 'IDi',
    36: 'IDr',
    37: 'CERT',
    38: 'CERTREQ',
    39: 'AUTH',
    40: 'NONCE',
    41: 'NOTIFY',
    42: 'DELETE',
    43: 'VENDOR',
    44: 'TSi',
    45: 'TSr',
    46: 'ENCRYPTED',
    47: 'CONFIGURATION',
    48: 'EAP',
    49: 'GSPM',
    50: 'GROUP',
  };

  return names[type] || `Payload-${type}`;
}

function exchangeName(exchangeType: number): string {
  const names: Record<number, string> = {
    34: 'IKE_SA_INIT',
    35: 'IKE_AUTH',
    36: 'CREATE_CHILD_SA',
    37: 'INFORMATIONAL',
  };

  return names[exchangeType] || `Exchange ${exchangeType}`;
}

/* =========================================================
   Crypto mappings
========================================================= */

export function encryptionName(id: number): {
  name: string;
  bits: number;
} {
  const map: Record<number, { name: string; bits: number }> = {
    1: { name: 'DES-IV64', bits: 64 },
    2: { name: 'DES', bits: 56 },
    3: { name: '3DES', bits: 168 },
    4: { name: 'RC5', bits: 0 },
    5: { name: 'IDEA', bits: 0 },
    6: { name: '3IDEA', bits: 0 },
    7: { name: 'CAST', bits: 0 },
    8: { name: 'BLOWFISH', bits: 0 },
    9: { name: '3IDEA', bits: 0 },
    10: { name: 'NULL', bits: 0 },
    11: { name: 'AES-CBC-OLD', bits: 0 },
    12: { name: 'AES-CBC', bits: 0 },
    13: { name: 'AES-CTR', bits: 0 },

    // Important AES-GCM values
    18: { name: 'AES-GCM-8', bits: 0 },
    19: { name: 'AES-GCM-12', bits: 0 },
    20: { name: 'AES-GCM-16', bits: 0 },

    14: { name: 'AES-CCM-8', bits: 0 },
    15: { name: 'AES-CCM-12', bits: 0 },
    16: { name: 'AES-CCM-16', bits: 0 },

    24: { name: 'AES-GMAC-128', bits: 128 },
    25: { name: 'AES-GMAC-192', bits: 192 },
    26: { name: 'AES-GMAC-256', bits: 256 },

    28: { name: 'CHACHA20-POLY1305', bits: 256 },
  };

  return map[id] || {
    name: `Unknown Transform ID ${id}`,
    bits: 0,
  };
}

export function prfName(id: number): string {
  const map: Record<number, string> = {
    1: 'PRF-HMAC-MD5',
    2: 'PRF-HMAC-SHA1',
    3: 'PRF-HMAC-TIGER',
    4: 'AES128-XCBC',
    5: 'PRF-HMAC-SHA2-256',
    6: 'PRF-HMAC-SHA2-384',
    7: 'PRF-HMAC-SHA2-512',
    8: 'PRF-AES128-CMAC',
  };

  return map[id] || `Unknown Transform ID ${id}`;
}

function integrityName(id: number): string {
  const map: Record<number, string> = {
    1: 'AUTH-HMAC-MD5-96',
    2: 'AUTH-HMAC-SHA1-96',
    3: 'AUTH-DES-MAC',
    4: 'AUTH-KPDK-MD5',
    5: 'AUTH-AES-XCBC-96',
    6: 'AUTH-HMAC-MD5-96',
    7: 'AUTH-HMAC-SHA1-160',
    8: 'AUTH-AES-CMAC-96',
    9: 'AUTH-AES-128-GMAC',
    10: 'AUTH-AES-192-GMAC',
    11: 'AUTH-AES-256-GMAC',
    12: 'AUTH-HMAC-SHA2-256-128',
    13: 'AUTH-HMAC-SHA2-384-192',
    14: 'AUTH-HMAC-SHA2-512-256',
  };

  return map[id] || `Unknown Transform ID ${id}`;
}

function dhName(id: number): {
  name: string;
  bits: number;
} {
  const map: Record<number, { name: string; bits: number }> = {
    1: { name: 'DH Group 1 (MODP 768-bit)', bits: 768 },
    2: { name: 'DH Group 2 (MODP 1024-bit)', bits: 1024 },
    5: { name: 'DH Group 5 (MODP 1536-bit)', bits: 1536 },
    14: { name: 'DH Group 14 (MODP 2048-bit)', bits: 2048 },
    15: { name: 'DH Group 15 (MODP 3072-bit)', bits: 3072 },
    16: { name: 'DH Group 16 (MODP 4096-bit)', bits: 4096 },
    17: { name: 'DH Group 17 (MODP 6144-bit)', bits: 6144 },
    18: { name: 'DH Group 18 (MODP 8192-bit)', bits: 8192 },

    19: { name: 'DH Group 19 (ECP 256-bit)', bits: 256 },
    20: { name: 'DH Group 20 (ECP 384-bit)', bits: 384 },
    21: { name: 'DH Group 21 (ECP 521-bit)', bits: 521 },

    31: { name: 'DH Group 31 (Curve25519)', bits: 255 },
  };

  return map[id] || {
    name: `Unknown Transform ID ${id}`,
    bits: 0,
  };
}

function esnName(id: number): string {
  if (id === 0) return 'No Extended Sequence Numbers';
  if (id === 1) return 'Extended Sequence Numbers';

  return `ESN ID ${id}`;
}

function transformName(transform: IkeTransform): string {
  if (transform.type === TRANSFORM_ENCR) return encryptionName(transform.id).name;
  if (transform.type === TRANSFORM_PRF) return prfName(transform.id);
  if (transform.type === TRANSFORM_INTEG) return integrityName(transform.id);
  if (transform.type === TRANSFORM_DH) return dhName(transform.id).name;
  if (transform.type === TRANSFORM_ESN) return esnName(transform.id);
  return `Unknown Transform Type ${transform.type} ID ${transform.id}`;
}

/* =========================================================
   Internal IKE structures
========================================================= */

interface IkeTransform {
  type: number;
  id: number;
  attributes: Record<number, number>;
  rawBytes: string;
  attributeRawBytes: Record<number, string>;
}

interface IkeProposal {
  number: number;
  protocolId: number;
  spi: string;
  transforms: IkeTransform[];
  packetNumber: number;
}

interface IkeParseResult {
  valid: boolean;
  ikeVersion?: 'IKEv1' | 'IKEv2';
  exchangeType?: number;
  initiatorSpi?: string;
  responderSpi?: string;
  firstPayload?: number;
  proposals: IkeProposal[];
  payloads: string[];
}

/* =========================================================
   Parse transform attributes
========================================================= */

function parseTransformAttributes(
  body: Uint8Array,
  start: number,
  end: number
): { values: Record<number, number>; rawBytes: Record<number, string> } {
  const attributes: Record<number, number> = {};
  const rawBytes: Record<number, string> = {};

  let offset = start;

  while (offset + 4 <= end) {
    const rawType = readU16(body, offset);
    const value = readU16(body, offset + 2);

    // High bit = TV/TLV format.
    // For TV, value is directly the 16-bit value.
    // For TLV, the next two bytes are length.
    const isTV = (rawType & 0x8000) !== 0;
    const type = rawType & 0x7fff;

    if (isTV) {
      attributes[type] = value;
      rawBytes[type] = hex(body.slice(offset, offset + 4));
      offset += 4;
      continue;
    }

    const tlvLength = value;

    if (offset + 4 + tlvLength > end) {
      break;
    }

    // We only need a numeric value for known attributes.
    if (tlvLength <= 4) {
      let numeric = 0;

      for (let i = 0; i < tlvLength; i++) {
        numeric = numeric * 256 + body[offset + 4 + i];
      }

      attributes[type] = numeric;
      rawBytes[type] = hex(body.slice(offset, offset + 4 + tlvLength));
    }

    offset += 4 + tlvLength;
  }

  return { values: attributes, rawBytes };
}

/* =========================================================
   Parse IKEv2 Transform
========================================================= */

function parseTransform(
  body: Uint8Array,
  offset: number,
  end: number
): {
  transform?: IkeTransform;
  nextOffset: number;
} {
  if (offset + 8 > end) {
    return { nextOffset: end };
  }

  const transformLength = readU16(body, offset + 2);

  if (
    transformLength < 8 ||
    offset + transformLength > end
  ) {
    return {
      nextOffset: end,
    };
  }

  const transformType = body[offset + 5];
  const transformId = readU16(body, offset + 6);

  const parsedAttributes = parseTransformAttributes(
    body,
    offset + 8,
    offset + transformLength
  );

  return {
    transform: {
      type: transformType,
      id: transformId,
      attributes: parsedAttributes.values,
      rawBytes: hex(body.slice(offset, offset + transformLength)),
      attributeRawBytes: parsedAttributes.rawBytes,
    },
    nextOffset: offset + transformLength,
  };
}

/* =========================================================
   Parse IKEv2 Proposal
========================================================= */

function parseProposal(
  body: Uint8Array,
  offset: number,
  end: number,
  packetNumber: number
): {
  proposal?: IkeProposal;
  nextOffset: number;
} {
  if (offset + 8 > end) {
    return { nextOffset: end };
  }

  const proposalLength = readU16(body, offset + 2);

  if (
    proposalLength < 8 ||
    offset + proposalLength > end
  ) {
    return {
      nextOffset: end,
    };
  }

  const proposalNumber = body[offset + 4];
  const protocolId = body[offset + 5];
  const spiSize = body[offset + 6];
  const transformCount = body[offset + 7];

  const proposalEnd = offset + proposalLength;

  let cursor = offset + 8;

  let spi = '';

  if (spiSize > 0) {
    if (cursor + spiSize > proposalEnd) {
      return {
        nextOffset: proposalEnd,
      };
    }

    spi = hex0x(body.slice(cursor, cursor + spiSize));
    cursor += spiSize;
  }

  const transforms: IkeTransform[] = [];

  /*
   * transformCount is useful as a sanity check,
   * but we also stop using the proposal boundary.
   *
   * This is important because malformed or unusual
   * captures should not make us read into the next payload.
   */
  for (
    let i = 0;
    i < transformCount && cursor + 8 <= proposalEnd;
    i++
  ) {
    const parsed = parseTransform(
      body,
      cursor,
      proposalEnd
    );

    if (!parsed.transform) {
      break;
    }

    transforms.push(parsed.transform);

    if (parsed.nextOffset <= cursor) {
      break;
    }

    cursor = parsed.nextOffset;
  }

  return {
    proposal: {
      number: proposalNumber,
      protocolId,
      spi,
      transforms,
      packetNumber,
    },
    nextOffset: proposalEnd,
  };
}

/* =========================================================
   Parse IKEv2 SA payload
========================================================= */

function parseSaPayload(
  payloadBody: Uint8Array,
  packetNumber: number
): IkeProposal[] {
  const proposals: IkeProposal[] = [];

  let offset = 0;

  while (offset + 8 <= payloadBody.length) {
    const parsed = parseProposal(
      payloadBody,
      offset,
      payloadBody.length,
      packetNumber
    );

    if (!parsed.proposal) {
      break;
    }

    proposals.push(parsed.proposal);

    if (parsed.nextOffset <= offset) {
      break;
    }

    offset = parsed.nextOffset;
  }

  return proposals;
}

/* =========================================================
   Parse complete IKE message
========================================================= */

function parseIkeMessage(
  bytes: Uint8Array,
  ikeOffset: number,
  packetNumber: number
): IkeParseResult {
  const result: IkeParseResult = {
    valid: false,
    proposals: [],
    payloads: [],
  };

  if (ikeOffset + 28 > bytes.length) {
    return result;
  }

  const initiatorSpi = readU64Hex(bytes, ikeOffset);
  const responderSpi = readU64Hex(bytes, ikeOffset + 8);

  const firstPayload = bytes[ikeOffset + 16];
  const version = bytes[ikeOffset + 17];
  const exchangeType = bytes[ikeOffset + 18];

  const majorVersion = version >> 4;

  result.valid = true;
  result.initiatorSpi = initiatorSpi;
  result.responderSpi = responderSpi;
  result.firstPayload = firstPayload;
  result.exchangeType = exchangeType;

  if (majorVersion === 1) {
    result.ikeVersion = 'IKEv1';
  } else if (majorVersion === 2) {
    result.ikeVersion = 'IKEv2';
  }

  /*
   * IKE header:
   *
   * 0-7     Initiator SPI
   * 8-15    Responder SPI
   * 16      Next Payload
   * 17      Version
   * 18      Exchange Type
   * 19      Flags
   * 20-23  Message ID
   * 24-27  Length
   */

  const messageLength = readU32(bytes, ikeOffset + 24);

  if (majorVersion !== 1 && majorVersion !== 2) return result;
  if (messageLength < 28 || ikeOffset + messageLength > bytes.length) return result;

  const availableLength = messageLength;

  const messageEnd = ikeOffset + availableLength;

  let payloadType = firstPayload;
  let payloadOffset = ikeOffset + 28;

  /*
   * IKEv2 payload header:
   *
   * Byte 0 = Next Payload
   * Byte 1 = Flags
   * Bytes 2-3 = Length
   */

  let safetyCounter = 0;

  while (
    payloadType !== IKE_PAYLOAD_NONE &&
    payloadOffset + 4 <= messageEnd &&
    safetyCounter < 100
  ) {
    safetyCounter++;

    const nextPayload = bytes[payloadOffset];
    const payloadLength = readU16(
      bytes,
      payloadOffset + 2
    );

    if (
      payloadLength < 4 ||
      payloadOffset + payloadLength > messageEnd
    ) {
      break;
    }

    result.payloads.push(payloadName(payloadType));

    const payloadBodyStart = payloadOffset + 4;
    const payloadBodyEnd =
      payloadOffset + payloadLength;

    /*
     * SA payload
     *
     * The SA payload body is:
     *     Proposal 1
     *     Proposal 2
     *     ...
     */
    if (payloadType === IKE_PAYLOAD_SA) {
      const saBody = bytes.slice(
        payloadBodyStart,
        payloadBodyEnd
      );

      const proposals = parseSaPayload(saBody, packetNumber);

      result.proposals.push(...proposals);
    }

    /*
     * IKE_AUTH and CREATE_CHILD_SA can contain
     * encrypted payloads. We deliberately do not
     * pretend to know the inner contents.
     */
    payloadOffset += payloadLength;
    payloadType = nextPayload;
  }

  return result;
}

/* =========================================================
   Extract crypto information from proposals
========================================================= */

interface DetectedCrypto {
  encryption?: string;
  encryptionBits?: number;
  keyLength?: number;

  prf?: string;

  integrity?: string;

  dhGroup?: string;
  dhNumber?: number;
  dhBits?: number;

  esn?: string;

  /*
   * Whether the proposal contains an AEAD encryption
   * transform such as AES-GCM.
   */
  aead?: boolean;
}

function extractCryptoFromProposals(
  proposals: IkeProposal[]
): DetectedCrypto {
  const result: DetectedCrypto = {};

  /*
   * Prefer the first IKE proposal.
   *
   * For a more advanced UI, all proposals can be exposed
   * separately. For the existing application's SA model,
   * we normalize the first observed proposal.
   */
  const proposal =
    proposals.find((p) => p.protocolId === 1) ||
    proposals[0];

  if (!proposal) {
    return result;
  }

  for (const transform of proposal.transforms) {
    switch (transform.type) {
      case TRANSFORM_ENCR: {
        const enc = encryptionName(transform.id);

        result.encryption = enc.name;
        result.encryptionBits = enc.bits;

        const keyLength =
          transform.attributes[ATTR_KEY_LENGTH];

        if (keyLength !== undefined) {
          result.keyLength = keyLength;
        }

        if (
          transform.id === 18 ||
          transform.id === 19 ||
          transform.id === 20 ||
          transform.id === 21 ||
          transform.id === 22 ||
          transform.id === 23 ||
          transform.id === 24 ||
          transform.id === 25 ||
          transform.id === 26 ||
          transform.id === 28
        ) {
          result.aead = true;
        }

        break;
      }

      case TRANSFORM_PRF:
        result.prf = prfName(transform.id);
        break;

      case TRANSFORM_INTEG:
        result.integrity = integrityName(
          transform.id
        );
        break;

      case TRANSFORM_DH: {
        const dh = dhName(transform.id);

        result.dhGroup = dh.name;
        result.dhNumber = transform.id;
        result.dhBits = dh.bits;

        break;
      }

      case TRANSFORM_ESN:
        result.esn = esnName(transform.id);
        break;
    }
  }

  return result;
}

/* =========================================================
   Link-layer parser
========================================================= */

function parseLinkLayer(
  packet: Uint8Array,
  linkType: number
): {
  networkOffset: number;
  etherType?: number;
} {
  /*
   * Ethernet
   */
  if (linkType === LINKTYPE_ETHERNET) {
    if (packet.length < 14) {
      return {
        networkOffset: packet.length,
      };
    }

    let offset = 14;
    let etherType =
      (packet[12] << 8) | packet[13];

    /*
     * VLAN / QinQ support
     */
    while (
      etherType === ETHERTYPE_VLAN ||
      etherType === ETHERTYPE_QINQ ||
      etherType === ETHERTYPE_QINQ2
    ) {
      if (packet.length < offset + 4) {
        return {
          networkOffset: packet.length,
        };
      }

      etherType =
        (packet[offset + 2] << 8) |
        packet[offset + 3];

      offset += 4;
    }

    return {
      networkOffset: offset,
      etherType,
    };
  }

  /*
   * Linux cooked capture v1
   */
  if (linkType === LINKTYPE_LINUX_SLL) {
    if (packet.length < 16) {
      return {
        networkOffset: packet.length,
      };
    }

    const protocol =
      (packet[14] << 8) | packet[15];

    return {
      networkOffset: 16,
      etherType: protocol,
    };
  }

  /*
   * Linux cooked capture v2
   */
  if (linkType === LINKTYPE_LINUX_SLL2) {
    if (packet.length < 20) {
      return {
        networkOffset: packet.length,
      };
    }

    const protocol =
      (packet[0] << 8) | packet[1];

    return {
      networkOffset: 20,
      etherType: protocol,
    };
  }

  /*
   * Raw IP
   */
  if (linkType === LINKTYPE_RAW) {
    if (packet.length < 1) {
      return {
        networkOffset: packet.length,
      };
    }

    const version = packet[0] >> 4;

    return {
      networkOffset: 0,
      etherType:
        version === 4
          ? ETHERTYPE_IPV4
          : version === 6
          ? ETHERTYPE_IPV6
          : undefined,
    };
  }

  return {
    networkOffset: packet.length,
  };
}

/* =========================================================
   IPv4 parser
========================================================= */

interface NetworkParseResult {
  srcIp: string;
  dstIp: string;
  protocol: number;
  transportOffset: number;
}

function parseIPv4(
  packet: Uint8Array,
  offset: number
): NetworkParseResult | null {
  if (offset + 20 > packet.length) {
    return null;
  }

  const version = packet[offset] >> 4;

  if (version !== 4) {
    return null;
  }

  const ihl = (packet[offset] & 0x0f) * 4;

  if (ihl < 20 || offset + ihl > packet.length) {
    return null;
  }

  const protocol = packet[offset + 9];

  const srcIp = ipv4ToString(
    packet,
    offset + 12
  );

  const dstIp = ipv4ToString(
    packet,
    offset + 16
  );

  return {
    srcIp,
    dstIp,
    protocol,
    transportOffset: offset + ihl,
  };
}

/* =========================================================
   IPv6 parser
========================================================= */

function parseIPv6(
  packet: Uint8Array,
  offset: number
): NetworkParseResult | null {
  if (offset + 40 > packet.length) {
    return null;
  }

  const version = packet[offset] >> 4;

  if (version !== 6) {
    return null;
  }

  let nextHeader = packet[offset + 6];
  let currentOffset = offset + 40;

  const srcIp = ipv6ToString(
    packet,
    offset + 8
  );

  const dstIp = ipv6ToString(
    packet,
    offset + 24
  );

  /*
   * Basic IPv6 extension-header walking.
   */
  let safety = 0;

  while (
    safety < 10 &&
    (
      nextHeader === 0 ||   // Hop-by-Hop
      nextHeader === 43 ||  // Routing
      nextHeader === 44 ||  // Fragment
      nextHeader === 60 ||  // Destination
      nextHeader === 51 ||  // AH
      nextHeader === 50     // ESP
    )
  ) {
    /*
     * ESP/AH are actual transport/security protocols,
     * not ordinary extension headers for our purposes.
     */
    if (
      nextHeader === 50 ||
      nextHeader === 51
    ) {
      break;
    }

    if (currentOffset + 2 > packet.length) {
      break;
    }

    const next = packet[currentOffset];

    /*
     * Fragment header has fixed 8-byte size.
     */
    if (nextHeader === 44) {
      nextHeader = next;
      currentOffset += 8;
      safety++;
      continue;
    }

    const hdrExtLen =
      (packet[currentOffset + 1] + 1) * 8;

    if (
      hdrExtLen <= 0 ||
      currentOffset + hdrExtLen > packet.length
    ) {
      break;
    }

    nextHeader = next;
    currentOffset += hdrExtLen;
    safety++;
  }

  return {
    srcIp,
    dstIp,
    protocol: nextHeader,
    transportOffset: currentOffset,
  };
}

/* =========================================================
   UDP / IKE parser
========================================================= */

function parseUdp(
  packet: Uint8Array,
  offset: number
): {
  srcPort: number;
  dstPort: number;
  payloadOffset: number;
} | null {
  if (offset + 8 > packet.length) {
    return null;
  }

  const srcPort = readU16(packet, offset);
  const dstPort = readU16(packet, offset + 2);

  return {
    srcPort,
    dstPort,
    payloadOffset: offset + 8,
  };
}

function isIkeUdpPort(port: number): boolean {
  return port === 500 || port === 4500;
}

/* =========================================================
   Main parser
========================================================= */

export async function parseUploadedFile(
  file: File
): Promise<ParsedPcapResult> {
  const arrayBuffer = await file.arrayBuffer();

  const bytes = new Uint8Array(arrayBuffer);

  if (bytes.length < 24) {
    throw new Error(
      'File is too small to be a valid classic PCAP.'
    );
  }

  /* =====================================================
     PCAP global header
  ===================================================== */

  const magicBytes = bytes.slice(0, 4);

  let littleEndian = false;
  let nanosecondTimestamp = false;

  const magicBE =
    ((magicBytes[0] << 24) |
      (magicBytes[1] << 16) |
      (magicBytes[2] << 8) |
      magicBytes[3]) >>>
    0;

  if (magicBE === PCAP_MAGIC_BE_USEC) {
    littleEndian = false;
    nanosecondTimestamp = false;
  } else if (magicBE === PCAP_MAGIC_LE_USEC) {
    littleEndian = true;
    nanosecondTimestamp = false;
  } else if (magicBE === PCAP_MAGIC_BE_NSEC) {
    littleEndian = false;
    nanosecondTimestamp = true;
  } else if (magicBE === PCAP_MAGIC_LE_NSEC) {
    littleEndian = true;
    nanosecondTimestamp = true;
  } else {
    /*
     * PCAPNG starts with:
     *
     * 0A 0D 0D 0A
     *
     * We explicitly report it rather than silently
     * treating it as a normal PCAP.
     */
    if (
      bytes[0] === 0x0a &&
      bytes[1] === 0x0d &&
      bytes[2] === 0x0d &&
      bytes[3] === 0x0a
    ) {
      throw new Error(
        'This file is PCAPNG. The current browser parser expects classic PCAP. Export it from Wireshark as "pcap" or add a PCAPNG parser/backend.'
      );
    }

    throw new Error(
      'Unsupported capture format: invalid PCAP magic number.'
    );
  }

  const versionMajor = readU16(
    bytes,
    4,
    littleEndian
  );

  const versionMinor = readU16(
    bytes,
    6,
    littleEndian
  );

  if (
    versionMajor !== 2 ||
    versionMinor !== 4
  ) {
    console.warn(
      `PCAP version ${versionMajor}.${versionMinor}`
    );
  }

  const snapLength = readU32(
    bytes,
    16,
    littleEndian
  );

  const linkType = readU32(
    bytes,
    20,
    littleEndian
  );

  if (
    linkType !== LINKTYPE_ETHERNET &&
    linkType !== LINKTYPE_RAW &&
    linkType !== LINKTYPE_LINUX_SLL &&
    linkType !== LINKTYPE_LINUX_SLL2
  ) {
    throw new Error(
      `Unsupported PCAP link type ${linkType}. Current parser supports Ethernet, Raw IP, Linux SLL and Linux SLL2.`
    );
  }

  console.log('PCAP:', {
    version: `${versionMajor}.${versionMinor}`,
    littleEndian,
    nanosecondTimestamp,
    snapLength,
    linkType,
  });

  /* =====================================================
     State
  ===================================================== */

  const packets: PacketInfo[] = [];

  const packetLengths: number[] = [];
  const timestamps: number[] = [];
  const espPacketLengths: number[] = [];
  const espTimestamps: number[] = [];
  const espPayloadBytes: number[] = [];

  let offset = 24;
  let packetIndex = 1;

  let baseTimestampMs: number | undefined;

  let uplinkBytes = 0;
  let downlinkBytes = 0;

  let firstObservedIp: string | undefined;

  let detectedIkeVersion:
    | 'IKEv1'
    | 'IKEv2'
    | undefined;

  let detectedIpVersion:
    | 'IPv4'
    | 'IPv6'
    | undefined;

  let initiatorSpi = 'Not observed in capture';

  let responderSpi = 'Not observed in capture';

  let detectedEncryption:
    | string
    | undefined;

  let detectedEncryptionBits:
    | number
    | undefined;

  let detectedKeyLength:
    | number
    | undefined;

  let detectedPrf:
    | string
    | undefined;

  let detectedIntegrity:
    | string
    | undefined;

  let detectedDhGroup:
    | string
    | undefined;

  let detectedDhNumber:
    | number
    | undefined;

  let detectedDhBits:
    | number
    | undefined;

  let detectedEsn:
    | string
    | undefined;

  let sawIkeSaInit = false;
  let sawIkeAuth = false;
  let sawCreateChildSa = false;

  let observedProposals: IkeProposal[] = [];

  /* =====================================================
     Packet loop
  ===================================================== */

  while (
    offset + 16 <= bytes.length &&
    packetIndex <= 10000
  ) {
    const tsSec = readU32(
      bytes,
      offset,
      littleEndian
    );

    const tsFraction = readU32(
      bytes,
      offset + 4,
      littleEndian
    );

    const inclLen = readU32(
      bytes,
      offset + 8,
      littleEndian
    );

    const origLen = readU32(
      bytes,
      offset + 12,
      littleEndian
    );

    const packetStart = offset + 16;
    const packetEnd = packetStart + inclLen;

    if (
      inclLen === 0 ||
      packetEnd > bytes.length
    ) {
      console.warn(
        'Stopping at malformed/truncated packet',
        packetIndex
      );

      break;
    }

    let timestampMs: number;

    if (nanosecondTimestamp) {
      timestampMs =
        tsSec * 1000 +
        Math.floor(tsFraction / 1_000_000);
    } else {
      timestampMs =
        tsSec * 1000 +
        Math.floor(tsFraction / 1000);
    }

    if (baseTimestampMs === undefined) {
      baseTimestampMs = timestampMs;
    }

    const relativeTimestamp =
      Math.max(
        0,
        timestampMs - baseTimestampMs
      );

    const packet = bytes.slice(
      packetStart,
      packetEnd
    );

    /* -----------------------------------------------
       Link layer
    ------------------------------------------------ */

    const link = parseLinkLayer(
      packet,
      linkType
    );

    let srcIp = 'Unknown';
    let dstIp = 'Unknown';

    let ipProtocol = -1;

    let transportOffset =
      link.networkOffset;

    if (
      link.etherType === ETHERTYPE_IPV4
    ) {
      detectedIpVersion = 'IPv4';

      const ipv4 = parseIPv4(
        packet,
        link.networkOffset
      );

      if (ipv4) {
        srcIp = ipv4.srcIp;
        dstIp = ipv4.dstIp;
        ipProtocol = ipv4.protocol;
        transportOffset =
          ipv4.transportOffset;
      }
    } else if (
      link.etherType === ETHERTYPE_IPV6
    ) {
      detectedIpVersion = 'IPv6';

      const ipv6 = parseIPv6(
        packet,
        link.networkOffset
      );

      if (ipv6) {
        srcIp = ipv6.srcIp;
        dstIp = ipv6.dstIp;
        ipProtocol = ipv6.protocol;
        transportOffset =
          ipv6.transportOffset;
      }
    }

    /* -----------------------------------------------
       Traffic direction
    ------------------------------------------------ */

    if (
      firstObservedIp === undefined &&
      srcIp !== 'Unknown'
    ) {
      firstObservedIp = srcIp;
    }

    if (
      firstObservedIp !== undefined
    ) {
      if (srcIp === firstObservedIp) {
        uplinkBytes += inclLen;
      } else if (
        dstIp === firstObservedIp
      ) {
        downlinkBytes += inclLen;
      }
    }

    /* -----------------------------------------------
       Packet classification
    ------------------------------------------------ */

    let protocol:
      | 'IKE'
      | 'ESP'
      | 'AH'
      | 'ICMP'
      | 'UDP'
      | 'OTHER' = 'OTHER';

    let info = `IP protocol ${ipProtocol}`;

    let spi: string | undefined;
    let seq: number | undefined;

    /* -----------------------------------------------
       UDP / IKE
    ------------------------------------------------ */

    if (
      ipProtocol === IPPROTO_UDP
    ) {
      const udp = parseUdp(
        packet,
        transportOffset
      );

      if (udp) {
        const isIke =
          isIkeUdpPort(udp.srcPort) ||
          isIkeUdpPort(udp.dstPort);

        if (isIke) {
          protocol = 'IKE';

          let ikeOffset =
            udp.payloadOffset;

          /*
           * UDP 4500:
           *
           * Non-ESP Marker:
           * 00 00 00 00
           *
           * If present, it belongs before IKE.
           */
          if (
            udp.srcPort === 4500 ||
            udp.dstPort === 4500
          ) {
            if (
              isZero4(
                packet,
                ikeOffset
              )
            ) {
              ikeOffset += 4;
            }
          }

          const ike =
            parseIkeMessage(packet, ikeOffset, packetIndex);

          if (ike.valid) {
            if (ike.ikeVersion) {
              detectedIkeVersion =
                ike.ikeVersion;
            }

            if (ike.initiatorSpi) {
              initiatorSpi =
                ike.initiatorSpi;
            }

            if (
              ike.responderSpi &&
              ike.responderSpi !== '0x0000000000000000'
            ) {
              responderSpi =
                ike.responderSpi;
            }

            const exchange =
              ike.exchangeType;

            if (
              exchange === IKE_SA_INIT
            ) {
              sawIkeSaInit = true;
            }

            if (
              exchange === IKE_AUTH
            ) {
              sawIkeAuth = true;
            }

            if (
              exchange ===
              CREATE_CHILD_SA
            ) {
              sawCreateChildSa =
                true;
            }

            /*
             * The important part:
             *
             * Parse actual SA payloads.
             */
            const isNegotiatedResponse =
              exchange === IKE_SA_INIT &&
              ike.responderSpi !== '0x0000000000000000';

            if (ike.proposals.length > 0) {
              observedProposals.push(
                ...ike.proposals
              );

              const crypto = extractCryptoFromProposals(ike.proposals);

              if (crypto.encryption && (!detectedEncryption || isNegotiatedResponse)) {
                detectedEncryption =
                  crypto.encryption;
              }

              if (crypto.encryptionBits && crypto.encryptionBits > 0 && (!detectedEncryptionBits || isNegotiatedResponse)) {
                detectedEncryptionBits =
                  crypto.encryptionBits;
              }

              if (crypto.keyLength !== undefined && (!detectedKeyLength || isNegotiatedResponse)) {
                detectedKeyLength =
                  crypto.keyLength;
              }

              if (crypto.prf && (!detectedPrf || isNegotiatedResponse)) {
                detectedPrf =
                  crypto.prf;
              }

              if (crypto.integrity && (!detectedIntegrity || isNegotiatedResponse)) {
                detectedIntegrity =
                  crypto.integrity;
              }

              if (crypto.dhGroup && (!detectedDhGroup || isNegotiatedResponse)) {
                detectedDhGroup =
                  crypto.dhGroup;

                detectedDhNumber =
                  crypto.dhNumber;

                detectedDhBits =
                  crypto.dhBits;
              }

              if (crypto.esn && (!detectedEsn || isNegotiatedResponse)) {
                detectedEsn =
                  crypto.esn;
              }
            }

            info =
              `${ike.ikeVersion || 'IKE'} ${exchangeName(exchange || 0)}`;

            if (
              ike.proposals.length > 0
            ) {
              info +=
                ` | ${ike.proposals.length} SA proposal(s)`;
            }
          } else {
            info =
              'IKE/ISAKMP UDP datagram';
          }
        } else {
          protocol = 'UDP';

          info =
            `UDP ${udp.srcPort} → ${udp.dstPort}`;
        }
      }
    }

    /* -----------------------------------------------
       ESP
    ------------------------------------------------ */

    else if (
      ipProtocol === IPPROTO_ESP
    ) {
      protocol = 'ESP';

      if (
        transportOffset + 8 <=
        packet.length
      ) {
        const spiValue =
          readU32(
            packet,
            transportOffset
          );

        const seqValue =
          readU32(
            packet,
            transportOffset + 4
          );

        spi =
          `0x${spiValue
            .toString(16)
            .padStart(8, '0')}`;

        seq = seqValue;

        info =
          `ESP Encrypted Datagram | SPI ${spi} | Seq ${seq}`;
      } else {
        info =
          'ESP packet with incomplete header';
      }
    }

    /* -----------------------------------------------
       AH
    ------------------------------------------------ */

    else if (
      ipProtocol === IPPROTO_AH
    ) {
      protocol = 'AH';

      info =
        'AH Authentication Header';
    }

    /* -----------------------------------------------
       ICMP
    ------------------------------------------------ */

    else if (
      ipProtocol === IPPROTO_ICMP
    ) {
      protocol = 'ICMP';

      info =
        'ICMP Control Message';
    }

    /* -----------------------------------------------
       Other IP protocol
    ------------------------------------------------ */

    else {
      /*
       * We don't invent IKE/ESP here.
       */
      info =
        `IP protocol ${ipProtocol}`;
    }

    /* -----------------------------------------------
       Raw preview
    ------------------------------------------------ */

    const rawPreview =
      hex(
        packet.slice(
          0,
          Math.min(32, packet.length)
        )
      );

    packets.push({
      id: packetIndex,
      timestamp: relativeTimestamp,
      sourceIp: srcIp,
      destIp: dstIp,
      protocol,
      length: origLen || inclLen,
      info,
      spi,
      seq,
      rawPreview,
    });

    packetLengths.push(
      origLen || inclLen
    );

    timestamps.push(
      relativeTimestamp
    );

    if (protocol === 'ESP') {
      espPacketLengths.push(origLen || inclLen);
      espTimestamps.push(relativeTimestamp);
      espPayloadBytes.push(...packet.slice(transportOffset));
    }

    offset = packetEnd;
    packetIndex++;
  }

  /* =====================================================
     Determine crypto values
  ===================================================== */

  /*
   * IMPORTANT:
   *
   * There are NO crypto defaults here.
   *
   * If IKE was not captured, the value remains
   * "Not observed in capture".
   */

  const encryption = detectedEncryption || 'Not observed in capture';

  const encryptionBits =
    detectedKeyLength ??
    detectedEncryptionBits ??
    0;

  const integrity = detectedIntegrity ||
    (detectedEncryption?.includes('GCM') ||
    detectedEncryption?.includes('CCM') ||
    detectedEncryption?.includes('GMAC')
      ? 'AEAD / separate integrity not negotiated'
      : 'Not observed in capture');

  const prf =
    detectedPrf ||
    'Not observed in capture';

  const dhGroup =
    detectedDhGroup ||
    'Not observed in capture';

  const dhNumber =
    detectedDhNumber ??
    0;

  const dhBits =
    detectedDhBits ??
    0;

  /*
   * PFS cannot be claimed from an IKE_SA_INIT
   * proposal alone.
   *
   * We therefore don't infer it.
   *
   * Existing type expects boolean, so false is used
   * as a compatibility value. The UI should ideally
   * display "Not determined" when no Child-SA evidence
   * exists.
   */
  const pfsEnabled = null;

  /* =====================================================
     Mode
  ===================================================== */

  /*
   * DO NOT infer tunnel/transport mode from packet size.
   *
   * Real tunnel/transport determination requires parsing
   * the Child SA / Traffic Selectors and/or inner packet
   * information.
   *
   * Existing interface requires a value, so we use:
   * "Not determined from capture"
   */

  const operationalMode = 'Not determined from capture' as const;

  /* =====================================================
     Traffic statistics
  ===================================================== */

  const count = espPacketLengths.length;

  const totalBytes =
    espPacketLengths.reduce(
      (sum, value) =>
        sum + value,
      0
    );

  const meanPacketLength =
    count > 0
      ? totalBytes / count
      : 0;

  const variance =
    count > 0
      ? espPacketLengths.reduce(
          (sum, value) =>
            sum +
            Math.pow(
              value -
                meanPacketLength,
              2
            ),
          0
        ) / count
      : 0;

  const stdPacketLength =
    Math.sqrt(variance);

  /* =====================================================
     Inter-arrival time
  ===================================================== */

  let totalIat = 0;
  let iatCount = 0;

  for (
    let i = 1;
    i < espTimestamps.length;
    i++
  ) {
    const diff =
      espTimestamps[i] -
      espTimestamps[i - 1];

    if (
      diff >= 0 &&
      diff < 5000
    ) {
      totalIat += diff;
      iatCount++;
    }
  }

  const meanIat =
    iatCount > 0
      ? totalIat / iatCount
      : 0;

  /* =====================================================
     ESP traffic
  ===================================================== */

  const espPackets =
    packets.filter(
      (packet) =>
        packet.protocol ===
        'ESP'
    );

  /*
   * Burst ratio is a traffic statistic/heuristic.
   * It is NOT a cryptographic property.
   */
  const burstRatio =
    meanIat === 0
      ? 0
      : meanIat < 10
      ? 0.9
      : meanIat < 40
      ? 0.6
      : 0.25;

  /* =====================================================
     Flow symmetry
  ===================================================== */

  const totalFlowBytes =
    uplinkBytes +
    downlinkBytes;

  const flowSymmetry =
    totalFlowBytes > 0 &&
    Math.max(
      uplinkBytes,
      downlinkBytes
    ) > 0
      ? Math.min(
          uplinkBytes,
          downlinkBytes
        ) /
        Math.max(
          uplinkBytes,
          downlinkBytes
        )
      : 0;

  /* =====================================================
     Entropy
  ===================================================== */

  const entropy =
    calculateEntropy(new Uint8Array(espPayloadBytes));

  /* =====================================================
     Security Association
  ===================================================== */

  const sa: IkeSecurityAssociation =
    {
      ikeVersion: detectedIkeVersion || 'Not observed in capture',

      operationalMode,

      ipVersion: detectedIpVersion || 'Not observed in capture',

      encryptionAlgorithm:
        encryption,

      encryptionKeyBits:
        encryptionBits,

      authIntegrityAlgorithm:
        integrity,

      dhGroup,

      dhGroupNumber:
        dhNumber,

      dhBits,

      pfsEnabled,

      keyLifetimeSeconds: null,

      replayProtection: null,

      replayWindowSize: null,

      initiatorSpi,

      responderSpi,
      proposals: observedProposals.map((proposal) => ({
        number: proposal.number,
        protocolId: proposal.protocolId,
        spi: proposal.spi,
        packetNumber: proposal.packetNumber,
        transforms: proposal.transforms.map((transform) => ({
          type: transform.type,
          id: transform.id,
          name: transformName(transform),
          attributes: transform.attributes,
          attributeRawBytes: transform.attributeRawBytes,
          rawBytes: transform.rawBytes,
          packetNumber: proposal.packetNumber,
        })),
      })),
    };

  /* =====================================================
     ESP features
  ===================================================== */

  const evidence: EvidenceRecord[] = [];

  for (const proposal of observedProposals) {
    for (const transform of proposal.transforms) {
      evidence.push({
        value: transformName(transform),
        confidence: 'exact',
        source: 'IKEv2 SA Proposal',
        packetNumber: proposal.packetNumber,
        rawBytes: transform.rawBytes,
        fieldPath: `IKE.SA.Proposal[${proposal.number}].Transform[type=${transform.type},id=${transform.id}]`,
      });

      if (transform.attributes[ATTR_KEY_LENGTH] !== undefined) {
        evidence.push({
          value: transform.attributes[ATTR_KEY_LENGTH],
          confidence: 'exact',
          source: 'IKEv2 Transform Attribute',
          packetNumber: proposal.packetNumber,
          rawBytes: transform.attributeRawBytes[ATTR_KEY_LENGTH],
          fieldPath: `IKE.SA.Proposal[${proposal.number}].Transform[type=${transform.type},id=${transform.id}].Attribute[14]`,
        });
      }
    }
  }

  if (evidence.length === 0) {
    evidence.push({
      value: null,
      confidence: 'unavailable',
      source: 'PCAP capture',
      fieldPath: 'IKE.SA',
    });
  }

  sa.evidence = evidence;

  const features: EspTrafficFeatures =
    {
      packetCount:
        count,

      totalBytes,

      meanPacketLength:
        Math.round(
          meanPacketLength
        ),

      stdPacketLength:
        Math.round(
          stdPacketLength
        ),

      minPacketLength:
          espPacketLengths.length > 0
          ? Math.min(
              ...espPacketLengths
            )
          : 0,

      maxPacketLength:
        espPacketLengths.length > 0
          ? Math.max(
              ...espPacketLengths
            )
          : 0,

      meanInterArrivalTimeMs:
        Number(
          meanIat.toFixed(1)
        ),

      burstRatio:
        Number(
          burstRatio.toFixed(2)
        ),

      flowSymmetry:
        Number(
          flowSymmetry.toFixed(2)
        ),

      calculatedEntropy:
        entropy,
    };

  /* =====================================================
     Useful debug output
  ===================================================== */

  console.group(
    `[PCAP Analyzer] ${file.name}`
  );

  console.log(
    'Packets:',
    packets.length
  );

  console.log(
    'IKE packets:',
    packets.filter(
      (p) => p.protocol === 'IKE'
    ).length
  );

  console.log(
    'ESP packets:',
    espPackets.length
  );

  console.log(
    'IKE SA_INIT:',
    sawIkeSaInit
  );

  console.log(
    'IKE_AUTH:',
    sawIkeAuth
  );

  console.log(
    'CREATE_CHILD_SA:',
    sawCreateChildSa
  );

  console.log(
    'Initiator SPI:',
    initiatorSpi
  );

  console.log(
    'Responder SPI:',
    responderSpi
  );

  console.log(
    'Proposals:',
    observedProposals
  );

  console.log(
    'Encryption:',
    encryption
  );

  console.log(
    'Key length:',
    encryptionBits
  );

  console.log(
    'PRF:',
    prf
  );

  console.log(
    'Integrity:',
    integrity
  );

  console.log(
    'DH:',
    dhGroup
  );

  console.log(
    'ESN:',
    detectedEsn ||
      'Not observed'
  );

  console.groupEnd();

  return {
    scenarioName:
      file.name.replace(
        /\.[^/.]+$/,
        ''
      ),

    packets,

    sa,

    features,

    evidence,

    fileSizeBytes:
      file.size,
  };
}

/* =========================================================
   Synthetic PCAP generator
========================================================= */

export function generateSyntheticPcapBlob(
  scenario: VpnCaptureScenario
): Blob {
  const headerBuffer =
    new ArrayBuffer(24);

  const headerView =
    new DataView(
      headerBuffer
    );

  /*
   * Big-endian PCAP header
   */
  headerView.setUint32(
    0,
    0xa1b2c3d4,
    false
  );

  headerView.setUint16(
    4,
    2,
    false
  );

  headerView.setUint16(
    6,
    4,
    false
  );

  headerView.setInt32(
    8,
    0,
    false
  );

  headerView.setUint32(
    12,
    0,
    false
  );

  headerView.setUint32(
    16,
    65535,
    false
  );

  headerView.setUint32(
    20,
    LINKTYPE_ETHERNET,
    false
  );

  const packetChunks:
    BlobPart[] = [
      new Uint8Array(
        headerBuffer
      ),
    ];

  scenario.packets.forEach(
    (p, index) => {
      const pktLen =
        Math.max(
          p.length,
          54
        );

      const pktHeader =
        new ArrayBuffer(16);

      const pktView =
        new DataView(
          pktHeader
        );

      const tsSec =
        Math.floor(
          p.timestamp / 1000
        );

      const tsUsec =
        (p.timestamp % 1000) *
        1000;

      pktView.setUint32(
        0,
        tsSec,
        false
      );

      pktView.setUint32(
        4,
        tsUsec,
        false
      );

      pktView.setUint32(
        8,
        pktLen,
        false
      );

      pktView.setUint32(
        12,
        pktLen,
        false
      );

      /*
       * NOTE:
       *
       * This function creates synthetic packets.
       * They are NOT real Ethernet/IP/ESP/IKE packets.
       *
       * Therefore the parser correctly will not magically
       * interpret them as real protocol traffic.
       */
      const payload =
        new Uint8Array(
          pktLen
        );

      for (
        let i = 0;
        i < pktLen;
        i++
      ) {
        payload[i] =
          (i * 17 +
            index * 31) %
          256;
      }

      packetChunks.push(
        new Uint8Array(
          pktHeader
        )
      );

      packetChunks.push(
        payload
      );
    }
  );


 

  return new Blob(
    packetChunks,
    {
      type:
        'application/vnd.tcpdump.pcap',
    }
  );
}
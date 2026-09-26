"""
PCAP Evidence Extraction Service
=================================

Handles validation, packet parsing (Scapy wire evidence), and feature extraction
adapter invocation for uploaded PCAP / PCAPNG files.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from ..capture_parser import parse_capture
from ..feature_extraction import extract_features_from_bytes, validate_ml_features
from ..models import CanonicalCaptureInfo, CanonicalObservedData

logger = logging.getLogger(__name__)


class PcapServiceError(Exception):
    """Raised when PCAP processing fails."""


def process_pcap_evidence(content: bytes, filename: str) -> tuple[CanonicalCaptureInfo, CanonicalObservedData, dict[str, Any], list[str]]:
    """
    Validate and extract raw wire evidence and 18 ML features from PCAP content.

    Returns
    -------
    (capture_info, observed_data, ml_features_dict, warnings)
    """
    if not filename:
        raise PcapServiceError("No filename provided.")

    suffix = Path(filename).suffix.lower()
    if suffix not in {".pcap", ".pcapng", ".cap"}:
        raise PcapServiceError(f"Unsupported file format '{suffix}'. Use .pcap or .pcapng.")

    if not content:
        raise PcapServiceError("The uploaded file is empty.")

    warnings: list[str] = []

    # 1. Feature Extraction (18 features for ML)
    raw_features = extract_features_from_bytes(content, filename)
    ml_features = validate_ml_features(raw_features)

    packet_count = raw_features.get("packet_count", 0)
    if packet_count < 5:
        warnings.append(
            f"Only {packet_count} packets extracted. ML predictions may be less reliable for very small captures."
        )

    # 2. Wire Analysis (Scapy detailed parsing)
    ike_version = raw_features.get("ike_version_detected") or "IKEv2"
    initiator_spi = raw_features.get("initiator_spi")
    responder_spi = raw_features.get("responder_spi")

    protocols_seen = ["IPv4"]
    if raw_features.get("udp_packet_count", 0) > 0:
        protocols_seen.append("UDP")
    if raw_features.get("ike_packet_count", 0) > 0:
        protocols_seen.append(ike_version)
    if raw_features.get("esp_packet_count", 0) > 0:
        protocols_seen.append("ESP")

    capture_info = CanonicalCaptureInfo(
        file_name=filename,
        file_size_bytes=len(content),
        packet_count=packet_count,
        duration_seconds=float(raw_features.get("capture_duration_seconds", 0.0)),
        protocols_seen=protocols_seen,
    )

    observed_data = CanonicalObservedData(
        ipsec_detected=raw_features.get("esp_packet_count", 0) > 0 or raw_features.get("ike_packet_count", 0) > 0,
        ike_version=ike_version if raw_features.get("ike_packet_count", 0) > 0 else None,
        initiator_spi=initiator_spi,
        responder_spi=responder_spi,
        esp_spis=[],
        exchange_types=list(raw_features.get("ike_exchange_distribution", {}).keys()),
        observed_transforms={},
    )

    return capture_info, observed_data, ml_features, warnings

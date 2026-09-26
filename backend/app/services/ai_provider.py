"""
AI Report Explanation Provider
===============================

Abstract AI provider interface allowing seamless switching between:
  - LocalDeterministicAIProvider (default fallback, structured natural language)
  - GroqAIProvider (when GROQ_API_KEY environment variable is configured)

The AI provider NEVER invents security findings or packet facts.
It strictly interprets and explains validated evidence + assessment objects.
"""

from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


class BaseAIProvider(ABC):
    """Interface for AI-assisted report narrative generation."""

    @abstractmethod
    def generate_executive_summary(self, analysis_data: dict[str, Any]) -> str:
        """Generate a clear plain-language executive summary."""
        pass

    @abstractmethod
    def generate_technical_narrative(self, analysis_data: dict[str, Any]) -> str:
        """Generate detailed technical explanation for network engineers."""
        pass


class LocalDeterministicAIProvider(BaseAIProvider):
    """Rule-based, deterministic explanation provider (runs without external API keys)."""

    def generate_executive_summary(self, analysis_data: dict[str, Any]) -> str:
        capture = analysis_data.get("capture", {})
        observed = analysis_data.get("observed", {})
        ml = analysis_data.get("ml_inference", {})
        sec = analysis_data.get("security_assessment", {})

        filename = capture.get("file_name", "uploaded capture")
        packet_count = capture.get("packet_count", 0)
        risk_level = sec.get("risk_level", "medium").upper()
        risk_score = sec.get("risk_score", 50)
        findings_count = len(sec.get("findings", []))

        enc = ml.get("encryption", {}).get("prediction", "Unknown")
        pfs = ml.get("pfs_group", {}).get("prediction", "Unknown")

        pfs_str = "enabled" if "NOPFS" not in str(pfs).upper() else "disabled or not requested"

        summary = (
            f"Network traffic analysis of '{filename}' ({packet_count} packets) evaluated the IPsec VPN posture "
            f"with an overall Risk Score of {risk_score}/100 ({risk_level} Risk). "
            f"Packet evidence confirmed {observed.get('ike_version', 'IKE')} protocol negotiation. "
            f"The ML inference pipeline predicted {enc} encryption with PFS {pfs_str}. "
            f"Security rule evaluation identified {findings_count} actionable security finding(s)."
        )
        return summary

    def generate_technical_narrative(self, analysis_data: dict[str, Any]) -> str:
        observed = analysis_data.get("observed", {})
        features = analysis_data.get("features", {})
        ml = analysis_data.get("ml_inference", {})
        sec = analysis_data.get("security_assessment", {})

        narrative = [
            "### Technical Protocol Analysis Summary",
            f"- **Observed IKE SPI (Initiator):** {observed.get('initiator_spi', 'N/A')}",
            f"- **Observed IKE SPI (Responder):** {observed.get('responder_spi', 'N/A')}",
            f"- **Observed ESP SPIs:** {', '.join(observed.get('esp_spis', ['None']))}",
            f"- **Flow Feature Vector:** {features.get('packet_count', 0)} total packets, "
            f"{features.get('esp_packet_count', 0)} ESP packets, "
            f"{features.get('ike_packet_count', 0)} IKE packets, "
            f"duration {features.get('capture_duration_seconds', 0.0):.2f}s.",
            "### Model Inference & Security Posture",
            f"- **Encryption Model Prediction:** {ml.get('encryption', {}).get('prediction')} "
            f"(Confidence: {ml.get('encryption', {}).get('confidence', 0.0)*100:.1f}%)",
            f"- **Hash Model Prediction:** {ml.get('hash', {}).get('prediction')} "
            f"(Confidence: {ml.get('hash', {}).get('confidence', 0.0)*100:.1f}%)",
            f"- **Diffie-Hellman Group Prediction:** {ml.get('dh_group', {}).get('prediction')} "
            f"(Confidence: {ml.get('dh_group', {}).get('confidence', 0.0)*100:.1f}%)",
            f"- **PFS Group Prediction:** {ml.get('pfs_group', {}).get('prediction')} "
            f"(Confidence: {ml.get('pfs_group', {}).get('confidence', 0.0)*100:.1f}%)",
            f"- **Risk Posture:** Score {sec.get('risk_score', 0)}/100, Level {sec.get('risk_level', 'medium').upper()}.",
        ]
        return "\n".join(narrative)


class GroqAIProvider(BaseAIProvider):
    """Groq API explanation provider (uses groq SDK / REST API if GROQ_API_KEY is supplied)."""

    def __init__(self, api_key: str | None = None, model: str = "llama-3.3-70b-versatile") -> None:
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        self.model = os.getenv("GROQ_MODEL", model)
        self.fallback = LocalDeterministicAIProvider()

    def generate_executive_summary(self, analysis_data: dict[str, Any]) -> str:
        if not self.api_key:
            return self.fallback.generate_executive_summary(analysis_data)
        try:
            import httpx

            prompt = (
                "You are an expert cybersecurity advisor. Explain the following IPsec VPN security analysis "
                "in a concise executive summary suitable for a non-technical stakeholder:\n"
                f"{analysis_data}"
            )
            response = httpx.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.3,
                },
                timeout=10.0,
            )
            if response.status_code == 200:
                data = response.json()
                return data["choices"][0]["message"]["content"].strip()
            logger.warning("Groq API returned status %d; using fallback.", response.status_code)
        except Exception as exc:
            logger.warning("Groq API call failed: %s; using fallback.", exc)
        return self.fallback.generate_executive_summary(analysis_data)

    def generate_technical_narrative(self, analysis_data: dict[str, Any]) -> str:
        if not self.api_key:
            return self.fallback.generate_technical_narrative(analysis_data)
        try:
            import httpx

            prompt = (
                "You are a senior network security engineer. Provide a detailed technical breakdown "
                "of the following IPsec VPN capture analysis data:\n"
                f"{analysis_data}"
            )
            response = httpx.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.3,
                },
                timeout=10.0,
            )
            if response.status_code == 200:
                data = response.json()
                return data["choices"][0]["message"]["content"].strip()
        except Exception as exc:
            logger.warning("Groq API technical call failed: %s; using fallback.", exc)
        return self.fallback.generate_technical_narrative(analysis_data)


def get_ai_provider() -> BaseAIProvider:
    """Factory returning GroqAIProvider if GROQ_API_KEY is configured, else LocalDeterministicAIProvider."""
    api_key = os.getenv("GROQ_API_KEY")
    if api_key:
        return GroqAIProvider(api_key=api_key)
    return LocalDeterministicAIProvider()

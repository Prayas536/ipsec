"""
Security Assessment Engine Service
===================================

Evaluates deterministic rules from `data/security_rules.json` against observed
evidence and ML predictions.
Produces reproducible risk score (0-100) and structured findings.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from ..models import CanonicalSecurityAssessmentData, CanonicalSecurityFinding

logger = logging.getLogger(__name__)

_RULES_FILE = Path(__file__).resolve().parents[2] / "data" / "security_rules.json"


def evaluate_security_rules(
    ml_predictions: dict[str, Any],
    raw_features: dict[str, Any],
) -> CanonicalSecurityAssessmentData:
    """
    Evaluate deterministic security policy rules.

    Returns
    -------
    CanonicalSecurityAssessmentData (risk_level, risk_score, findings, recommendations)
    """
    rules: list[dict[str, Any]] = []
    if _RULES_FILE.exists():
        try:
            with open(_RULES_FILE, "r", encoding="utf-8") as f:
                config = json.load(f)
                rules = config.get("rules", [])
        except Exception as exc:
            logger.warning("Could not read security_rules.json: %s", exc)

    findings: list[CanonicalSecurityFinding] = []
    penalty_points = 0

    # Maps field names in rules to actual extracted/predicted values
    eval_state = {
        "encryption": str(ml_predictions.get("encryption", {}).get("prediction", "")).upper(),
        "hash": str(ml_predictions.get("hash", {}).get("prediction", "")).upper(),
        "dh_group": str(ml_predictions.get("dh_group", {}).get("prediction", "")).upper(),
        "pfs_group": str(ml_predictions.get("pfs_group", {}).get("prediction", "")).upper(),
    }

    for rule in rules:
        target_field = rule.get("field")
        target_vals = [str(v).upper() for v in rule.get("target_values", [])]
        current_val = eval_state.get(target_field, "")

        if current_val in target_vals:
            sev = rule.get("severity", "info")
            points = 25 if sev == "critical" else 15 if sev == "high" else 10 if sev == "medium" else 5
            penalty_points += points

            findings.append(
                CanonicalSecurityFinding(
                    id=rule["id"],
                    severity=sev,
                    category="security_policy",
                    title=rule["title"],
                    description=rule["description"],
                    impact=rule["impact"],
                    recommendation=rule["recommendation"],
                    basis="ml_inferred" if target_field in eval_state else "observed",
                    confidence=float(ml_predictions.get(target_field, {}).get("confidence", 0.9)),
                )
            )

    # Base score 100 minus penalty points (clamped to [0, 100])
    risk_score = max(0, min(100, 100 - penalty_points))

    risk_level = (
        "critical" if risk_score < 40 else "high" if risk_score < 60 else "medium" if risk_score < 80 else "low"
    )

    recommendations = [f.recommendation for f in findings if f.recommendation]

    return CanonicalSecurityAssessmentData(
        risk_level=risk_level,
        risk_score=risk_score,
        findings=findings,
        recommendations=recommendations,
    )

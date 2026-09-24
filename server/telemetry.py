"""Authorized VPN gateway telemetry adapters.

Only read-only SA metadata is collected. PSKs, private keys, and session keys
are never requested or parsed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import importlib
from dataclasses import dataclass
from typing import Any, Sequence


@dataclass(frozen=True)
class TelemetryResult:
    source: str
    status: str
    records: list[dict[str, Any]]
    evidence: list[str]
    error: str | None = None


class GatewayAdapter:
    name = "UNKNOWN"

    def collect(self) -> TelemetryResult:
        raise NotImplementedError


class StrongSwanAdapter(GatewayAdapter):
    """Read authorized metadata using the read-only swanctl command."""

    name = "STRONGSWAN"

    def __init__(
        self,
        command: Sequence[str] = ("swanctl", "--list-sas", "--raw"),
        timeout_seconds: float = 10,
    ) -> None:
        self.command = tuple(command)
        self.timeout_seconds = timeout_seconds

    def collect(self) -> TelemetryResult:
        executable = shutil.which(self.command[0])
        if executable is None:
            return TelemetryResult(
                source="GATEWAY_TELEMETRY",
                status="NOT_DETERMINABLE",
                records=[],
                evidence=["swanctl is not installed or is not available on PATH."],
                error="STRONGSWAN_CONTROL_TOOL_UNAVAILABLE",
            )

        try:
            completed = subprocess.run(
                (executable, *self.command[1:]),
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return TelemetryResult(
                source="GATEWAY_TELEMETRY",
                status="NOT_DETERMINABLE",
                records=[],
                evidence=[f"StrongSwan telemetry command failed: {type(exc).__name__}."],
                error="STRONGSWAN_CONTROL_QUERY_FAILED",
            )

        if completed.returncode != 0:
            return TelemetryResult(
                source="GATEWAY_TELEMETRY",
                status="NOT_DETERMINABLE",
                records=[],
                evidence=["StrongSwan rejected the read-only SA query."],
                error="STRONGSWAN_CONTROL_QUERY_REJECTED",
            )

        records = parse_swanctl_records(completed.stdout)
        if not records:
            return TelemetryResult(
                source="GATEWAY_TELEMETRY",
                status="NOT_DETERMINABLE",
                records=[],
                evidence=["The gateway returned no parseable SA metadata."],
                error="STRONGSWAN_NO_PARSEABLE_SA",
            )

        return TelemetryResult(
            source="GATEWAY_TELEMETRY",
            status="CONFIRMED",
            records=records,
            evidence=["Read-only swanctl SA telemetry was parsed from the gateway."],
        )


class ViciAdapter(GatewayAdapter):
    """Optional read-only StrongSwan VICI adapter.

    The VICI Python package and socket are deployment dependencies. This
    adapter never falls back to guessed values when either is unavailable.
    """

    name = "STRONGSWAN_VICI"

    def __init__(self, client_factory: Any | None = None) -> None:
        self.client_factory = client_factory

    def collect(self) -> TelemetryResult:
        try:
            factory = self.client_factory
            if factory is None:
                module = importlib.import_module("vici")
                factory = module.Session
            session = factory()
            response = session.request("list-sas", {})
            records = parse_vici_records(response)
        except (ImportError, OSError, RuntimeError, TypeError, ValueError) as exc:
            return TelemetryResult(
                source="GATEWAY_TELEMETRY",
                status="NOT_DETERMINABLE",
                records=[],
                evidence=[f"VICI telemetry unavailable: {type(exc).__name__}."],
                error="STRONGSWAN_VICI_UNAVAILABLE",
            )

        if not records:
            return TelemetryResult(
                source="GATEWAY_TELEMETRY",
                status="NOT_DETERMINABLE",
                records=[],
                evidence=["VICI returned no parseable SA metadata."],
                error="STRONGSWAN_VICI_NO_PARSEABLE_SA",
            )
        return TelemetryResult(
            source="GATEWAY_TELEMETRY",
            status="CONFIRMED",
            records=records,
            evidence=["Read-only StrongSwan VICI SA telemetry was parsed."],
        )


def _format_spi(value: Any) -> str | None:
    if not value:
        return None
    val_str = str(value).strip()
    if val_str.startswith("0x"):
        return val_str
    try:
        int(val_str, 16)
        return f"0x{val_str}"
    except ValueError:
        return val_str


def _format_algo(alg: Any, keysize: Any = None) -> str | None:
    if not alg:
        return None
    if keysize:
        return f"{alg}_{keysize}"
    return str(alg)


def _format_ts(val: Any) -> str | None:
    if isinstance(val, list):
        return ", ".join(str(x) for x in val)
    return str(val) if val is not None else None


def _to_int_or_str(val: Any) -> Any:
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return str(val)


def _parse_swanctl_event_blocks(text: str) -> list[dict[str, Any]]:
    import re
    tokens = re.findall(r'\{|\}|\[|\]|[^\s\{\}\[\]=]+|=', text)
    if not tokens:
        return []

    idx = 0

    def parse_dict():
        nonlocal idx
        d: dict[str, Any] = {}
        while idx < len(tokens):
            tok = tokens[idx]
            if tok == '}':
                idx += 1
                return d
            key = tok
            idx += 1
            if idx >= len(tokens):
                break
            nxt = tokens[idx]
            if nxt == '=':
                idx += 1
                if idx < len(tokens) and tokens[idx] == '[':
                    idx += 1
                    items = []
                    while idx < len(tokens) and tokens[idx] != ']':
                        items.append(tokens[idx])
                        idx += 1
                    if idx < len(tokens) and tokens[idx] == ']':
                        idx += 1
                    d[key] = items
                elif idx < len(tokens) and tokens[idx] == '{':
                    idx += 1
                    d[key] = parse_dict()
                else:
                    d[key] = tokens[idx] if idx < len(tokens) else ''
                    idx += 1
            elif nxt == '{':
                idx += 1
                d[key] = parse_dict()
            elif nxt == '[':
                idx += 1
                items = []
                while idx < len(tokens) and tokens[idx] != ']':
                    items.append(tokens[idx])
                    idx += 1
                if idx < len(tokens) and tokens[idx] == ']':
                    idx += 1
                d[key] = items
        return d

    data = parse_dict()
    conns: dict[str, Any] = {}
    if "event" in data and isinstance(data["event"], dict):
        conns = data["event"]
    elif "list-sa" in data and isinstance(data["list-sa"], dict):
        conns = data["list-sa"]
    else:
        conns = data

    records: list[dict[str, Any]] = []
    for conn_name, ike_info in conns.items():
        if not isinstance(ike_info, dict):
            continue
        ike_rec = {
            "name": conn_name,
            "uniqueid": _to_int_or_str(ike_info.get("uniqueid")),
            "version": _to_int_or_str(ike_info.get("version")),
            "state": ike_info.get("state"),
            "local_host": ike_info.get("local-host") or ike_info.get("local_host"),
            "remote_host": ike_info.get("remote-host") or ike_info.get("remote_host"),
            "initiator_spi": _format_spi(ike_info.get("initiator-spi") or ike_info.get("initiator_spi")),
            "responder_spi": _format_spi(ike_info.get("responder-spi") or ike_info.get("responder_spi")),
            "encr": _format_algo(ike_info.get("encr-alg") or ike_info.get("encr"), ike_info.get("encr-keysize")),
            "prf": ike_info.get("prf-alg") or ike_info.get("prf"),
            "dh": ike_info.get("dh-group") or ike_info.get("dh"),
            "established": _to_int_or_str(ike_info.get("established")),
            "reauth_time": _to_int_or_str(ike_info.get("reauth-time")),
        }
        child_sas = ike_info.get("child-sas") or ike_info.get("child_sas") or {}
        if isinstance(child_sas, dict):
            for child_key, child_info in child_sas.items():
                if not isinstance(child_info, dict):
                    continue
                spi_in = _format_spi(child_info.get("spi-in") or child_info.get("inbound_spi") or child_info.get("spi_in"))
                spi_out = _format_spi(child_info.get("spi-out") or child_info.get("outbound_spi") or child_info.get("spi_out"))
                child_rec = {
                    "name": child_info.get("name", child_key),
                    "uniqueid": _to_int_or_str(child_info.get("uniqueid")),
                    "reqid": _to_int_or_str(child_info.get("reqid")),
                    "state": child_info.get("state"),
                    "mode": child_info.get("mode"),
                    "protocol": child_info.get("protocol", "ESP"),
                    "inbound_spi": spi_in,
                    "outbound_spi": spi_out,
                    "spi": spi_in or spi_out,
                    "child_sa_spi": spi_in or spi_out,
                    "encr": _format_algo(child_info.get("encr-alg") or child_info.get("encr"), child_info.get("encr-keysize")),
                    "bytes_in": _to_int_or_str(child_info.get("bytes-in")),
                    "bytes_out": _to_int_or_str(child_info.get("bytes-out")),
                    "packets_in": _to_int_or_str(child_info.get("packets-in")),
                    "packets_out": _to_int_or_str(child_info.get("packets-out")),
                    "local_ts": _format_ts(child_info.get("local-ts")),
                    "remote_ts": _format_ts(child_info.get("remote-ts")),
                }
                child_rec = {k: v for k, v in child_rec.items() if v is not None}
                records.append(child_rec)

        ike_rec = {k: v for k, v in ike_rec.items() if v is not None}
        records.append(ike_rec)

    return records


def parse_swanctl_records(output: str) -> list[dict[str, Any]]:
    text = output.strip()
    if not text:
        return []

    try:
        decoded = json.loads(text)
    except json.JSONDecodeError:
        decoded = None

    if decoded is not None:
        return _extract_json_records(decoded)

    if "{" in text and ("=" in text or "event" in text or "reply" in text):
        records = _parse_swanctl_event_blocks(text)
        if records:
            return records

    records: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    allowed = {
        "name", "uniqueid", "state", "version", "local_host", "remote_host",
        "local_ts", "remote_ts", "initiator_spi", "responder_spi", "inbound_spi",
        "outbound_spi", "spi", "child_sa_spi", "protocol", "reqid",
        "encr", "integ", "prf", "dh", "mode", "rekey_time",
        "reauth_time", "bytes_in", "bytes_out", "packets_in", "packets_out",
    }
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            if current:
                records.append(current)
                current = {}
            continue
        if ":" not in stripped:
            continue
        key, value = (part.strip() for part in stripped.split(":", 1))
        normalized = key.lower().replace("-", "_").replace(" ", "_")
        if normalized in allowed:
            current[normalized] = value
    if current:
        records.append(current)
    return records


VICI_ALLOWED_FIELDS = {
    "name", "uniqueid", "state", "version", "local_host", "remote_host",
    "local_ts", "remote_ts", "initiator_spi", "responder_spi", "inbound_spi",
    "outbound_spi", "encr", "integ", "prf", "dh", "mode", "rekey_time",
    "reauth_time", "bytes_in", "bytes_out", "packets_in", "packets_out",
}


def parse_vici_records(value: Any) -> list[dict[str, Any]]:
    """Flatten only recognized scalar SA metadata from a VICI response."""
    records: list[dict[str, Any]] = []

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            record: dict[str, Any] = {}
            for key, item in node.items():
                normalized = str(key).lower().replace("-", "_").replace(" ", "_")
                if normalized in VICI_ALLOWED_FIELDS and isinstance(item, (str, int, float, bool)):
                    record[normalized] = item
                else:
                    visit(item)
            if record:
                records.append(record)
        elif isinstance(node, (list, tuple)):
            for item in node:
                visit(item)

    visit(value)
    return records


def _extract_json_records(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        for key in ("sas", "child_sas", "connections", "records"):
            nested = value.get(key)
            if isinstance(nested, (list, dict)):
                records = _extract_json_records(nested)
                if records:
                    return records
        return [value]
    return []

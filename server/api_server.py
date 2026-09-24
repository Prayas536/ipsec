"""API gateway for offline PCAP analysis and gateway agent management.

This server manages gateway enrollment, authenticated telemetry ingestion,
exact SPI correlation, and agent distribution. It enforces request size limits,
sanitizes telemetry, never persists raw secrets or packet payloads, and never
exposes internal gateway interfaces or command execution to browsers.
"""

from __future__ import annotations

import io
import json
import os
import tarfile
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from correlation import correlate_spi
from sanitizer import sanitize_analysis_payload
from scapy_analyzer import analyze
from repository import AnalysisRepository

HOST = os.environ.get("VPN_ANALYZER_API_HOST", "0.0.0.0")
PORT = int(os.environ.get("VPN_ANALYZER_API_PORT", "8770"))
MAX_BODY_BYTES = 100 * 1024 * 1024
AGENT_TOKEN = os.environ.get("VPN_ANALYZER_AGENT_TOKEN")
REPOSITORY = AnalysisRepository(os.environ.get("VPN_ANALYZER_DATABASE", "data/analyzer.sqlite3"))


def json_response(
    handler: BaseHTTPRequestHandler,
    status: int,
    value: dict[str, Any] | list[Any],
) -> None:
    body = json.dumps(value).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    origin = handler.headers.get("Origin", "*")
    handler.send_header("Access-Control-Allow-Origin", origin if origin else "*")
    handler.send_header(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization, X-Filename, X-Gateway-Id",
    )
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def text_response(
    handler: BaseHTTPRequestHandler,
    status: int,
    text: str,
    content_type: str = "text/plain",
) -> None:
    body = text.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    origin = handler.headers.get("Origin", "*")
    handler.send_header("Access-Control-Allow-Origin", origin if origin else "*")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def binary_response(
    handler: BaseHTTPRequestHandler,
    status: int,
    data: bytes,
    content_type: str,
    filename: str | None = None,
) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    if filename:
        handler.send_header("Content-Disposition", f'attachment; filename="{filename}"')
    origin = handler.headers.get("Origin", "*")
    handler.send_header("Access-Control-Allow-Origin", origin if origin else "*")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def _extract_bearer_token(auth_header: str | None) -> str | None:
    if not auth_header:
        return None
    parts = auth_header.strip().split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None


class ApiHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self) -> None:
        self.send_response(204)
        origin = self.headers.get("Origin", "*")
        self.send_header("Access-Control-Allow-Origin", origin if origin else "*")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization, X-Filename, X-Gateway-Id",
        )
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length > MAX_BODY_BYTES:
            json_response(self, 413, {"error": "INVALID_CONTENT_LENGTH"})
            return

        body = self.rfile.read(content_length) if content_length > 0 else b""
        path = self.path.split("?")[0].rstrip("/")

        # 1. PCAP Analysis
        if path == "/api/analyze/pcap":
            self._analyze_pcap(body)
            return

        # 2. Gateway Registration
        if path == "/api/gateways":
            self._create_gateway(body)
            return

        # 3. Gateway Enrollment
        if path == "/api/gateways/enroll":
            self._enroll_gateway(body)
            return

        # 4. Gateway Actions
        if path.startswith("/api/gateways/"):
            parts = path[len("/api/gateways/"):].split("/")
            if len(parts) == 2:
                gateway_id, action = parts
                if action == "heartbeat":
                    self._gateway_heartbeat(gateway_id, body)
                    return
                elif action == "telemetry":
                    self._gateway_telemetry(gateway_id, body)
                    return
                elif action == "token":
                    self._gateway_regenerate_token(gateway_id)
                    return
                elif action == "revoke":
                    self._gateway_revoke(gateway_id)
                    return

        # 5. Analysis Correlation
        if path.startswith("/api/analysis/") and path.endswith("/correlate"):
            analysis_id = path[len("/api/analysis/"):-len("/correlate")].strip("/")
            self._correlate_analysis(analysis_id, body)
            return

        # 6. Legacy Telemetry Ingestion
        if path == "/api/agent/telemetry":
            self._ingest_metadata(body)
            return
        if path.startswith("/api/analysis/") and path.endswith("/telemetry"):
            analysis_id = path[len("/api/analysis/"):-len("/telemetry")]
            self._ingest_analysis_telemetry(analysis_id, body)
            return

        json_response(self, 404, {"error": "NOT_FOUND"})

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path.rstrip("/")
        query = urllib.parse.parse_qs(parsed_url.query)

        # 1. Gateway List
        if path == "/api/gateways":
            gateways = REPOSITORY.list_gateways()
            json_response(self, 200, gateways)
            return

        # 2. Gateway Details
        if path.startswith("/api/gateways/"):
            parts = path[len("/api/gateways/"):].split("/")
            if len(parts) == 1:
                gateway_id = parts[0]
                gateway = REPOSITORY.get_gateway(gateway_id, include_history=True)
                if gateway is None:
                    json_response(self, 404, {"error": "GATEWAY_NOT_FOUND"})
                    return
                json_response(self, 200, gateway)
                return
            elif len(parts) == 2 and parts[1] == "telemetry":
                gateway_id = parts[0]
                telemetry = REPOSITORY.get_latest_gateway_telemetry(gateway_id)
                json_response(self, 200, telemetry or {})
                return
            elif len(parts) == 2 and parts[1] == "report":
                self._serve_gateway_report(parts[0])
                return

        # 3. Agent Installer & Package
        if path == "/api/agent/install.sh":
            self._serve_install_script()
            return
        if path in ("/api/agent/download", "/api/agent/bundle.tar.gz"):
            self._serve_agent_bundle()
            return

        # 4. Analysis Endpoints
        if path.startswith("/api/analysis/"):
            prefix = "/api/analysis/"
            if path.endswith("/telemetry"):
                analysis_id = path[len(prefix):-len("/telemetry")]
                if not analysis_id or len(analysis_id) > 80:
                    json_response(self, 400, {"error": "INVALID_ANALYSIS_ID"})
                    return
                gateway_id = query.get("gateway_id", [None])[0]
                if gateway_id:
                    result = REPOSITORY.correlate_analysis_with_gateway(analysis_id, gateway_id)
                else:
                    result = self._build_telemetry_summary(analysis_id)
                if result is None:
                    json_response(self, 404, {"error": "ANALYSIS_NOT_FOUND"})
                    return
                json_response(self, 200, result)
                return

            analysis_id = path[len(prefix):].split("/")[0]
            if not analysis_id or len(analysis_id) > 80:
                json_response(self, 400, {"error": "INVALID_ANALYSIS_ID"})
                return
            result = REPOSITORY.get_analysis(analysis_id)
            if result is None:
                json_response(self, 404, {"error": "ANALYSIS_NOT_FOUND"})
                return
            json_response(self, 200, result)
            return

        json_response(self, 404, {"error": "NOT_FOUND"})

    def do_DELETE(self) -> None:
        path = self.path.split("?")[0].rstrip("/")
        if path.startswith("/api/gateways/"):
            gateway_id = path[len("/api/gateways/"):].strip("/")
            if not gateway_id or "/" in gateway_id:
                json_response(self, 400, {"error": "INVALID_GATEWAY_ID"})
                return
            removed = REPOSITORY.remove_gateway(gateway_id)
            if not removed:
                json_response(self, 404, {"error": "GATEWAY_NOT_FOUND"})
                return
            json_response(self, 200, {"status": "REMOVED", "gateway_id": gateway_id})
            return
        json_response(self, 404, {"error": "NOT_FOUND"})

    # ================= Helper Handlers =================

    def _analyze_pcap(self, body: bytes) -> None:
        try:
            filename = self.headers.get("X-Filename", "capture.pcap")
            result = analyze(body, filename)
        except Exception as exc:
            json_response(self, 400, {"error": "PCAP_ANALYSIS_FAILED", "detail": str(exc)})
            return
        analysis_id = REPOSITORY.save_analysis(result)
        result["analysisId"] = analysis_id

        # If gateway context was provided on upload, correlate server-side immediately
        gateway_id = self.headers.get("X-Gateway-Id")
        if gateway_id:
            summary = REPOSITORY.correlate_analysis_with_gateway(analysis_id, gateway_id)
            if summary:
                result["gatewayTelemetry"] = summary
                result["correlation"] = summary.get("correlation")

        json_response(self, 200, result)

    def _create_gateway(self, body: bytes) -> None:
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            json_response(self, 400, {"error": "INVALID_JSON"})
            return
        if not isinstance(payload, dict):
            json_response(self, 400, {"error": "JSON_OBJECT_REQUIRED"})
            return

        display_name = payload.get("display_name") or payload.get("displayName")
        if not display_name or not isinstance(display_name, str) or not display_name.strip():
            json_response(self, 400, {"error": "DISPLAY_NAME_REQUIRED"})
            return

        gateway_type = payload.get("gateway_type") or payload.get("gatewayType") or "STRONGSWAN"
        try:
            gateway, raw_token, expires_at = REPOSITORY.create_gateway(
                display_name=display_name.strip(),
                gateway_type=str(gateway_type).strip(),
            )
        except Exception as exc:
            json_response(self, 500, {"error": "GATEWAY_CREATION_FAILED", "detail": str(exc)})
            return

        host = self.headers.get("Host", f"127.0.0.1:{PORT}")
        server_url = f"http://{host}"

        json_response(
            self,
            201,
            {
                "gateway_id": gateway["gateway_id"],
                "display_name": gateway["display_name"],
                "gateway_type": gateway["gateway_type"],
                "status": gateway["status"],
                "created_at": gateway["created_at"],
                "enrollment_token": raw_token,
                "expires_at": expires_at,
                "server_url": server_url,
            },
        )

    def _enroll_gateway(self, body: bytes) -> None:
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            json_response(self, 400, {"error": "INVALID_JSON"})
            return
        if not isinstance(payload, dict):
            json_response(self, 400, {"error": "JSON_OBJECT_REQUIRED"})
            return

        token = payload.get("token") or payload.get("enrollment_token")
        if not token or not isinstance(token, str):
            json_response(self, 400, {"error": "TOKEN_REQUIRED"})
            return

        agent_version = str(payload.get("agent_version") or "1.0.0")
        adapter = str(payload.get("adapter") or "STRONGSWAN")

        result = REPOSITORY.enroll_gateway(
            enrollment_token=token.strip(),
            agent_version=agent_version,
            adapter=adapter,
        )

        if "error" in result:
            status_code = 401 if "INVALID" in result["error"] or "REVOKED" in result["error"] else 400
            json_response(self, status_code, result)
            return

        json_response(self, 200, result)

    def _gateway_heartbeat(self, gateway_id: str, body: bytes) -> None:
        token = _extract_bearer_token(self.headers.get("Authorization"))
        if not token:
            json_response(self, 401, {"error": "UNAUTHORIZED", "detail": "Bearer token required"})
            return

        gateway = REPOSITORY.authenticate_agent(gateway_id, token)
        if gateway is None:
            json_response(self, 401, {"error": "UNAUTHORIZED", "detail": "Invalid or revoked credentials"})
            return

        REPOSITORY.record_heartbeat(gateway_id)
        json_response(self, 200, {"status": "OK", "gateway_id": gateway_id})

    def _gateway_telemetry(self, gateway_id: str, body: bytes) -> None:
        token = _extract_bearer_token(self.headers.get("Authorization"))
        if not token:
            json_response(self, 401, {"error": "UNAUTHORIZED", "detail": "Bearer token required"})
            return

        gateway = REPOSITORY.authenticate_agent(gateway_id, token)
        if gateway is None:
            json_response(self, 401, {"error": "UNAUTHORIZED", "detail": "Invalid or revoked credentials"})
            return

        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            json_response(self, 400, {"error": "INVALID_JSON"})
            return
        if not isinstance(payload, dict):
            json_response(self, 400, {"error": "JSON_OBJECT_REQUIRED"})
            return

        sanitized = sanitize_analysis_payload({**payload, "gateway_id": gateway_id})
        REPOSITORY.record_gateway_telemetry(
            gateway_id=gateway_id,
            payload=sanitized,
            analysis_id=sanitized.get("analysis_id"),
        )

        json_response(self, 200, {"status": "ACCEPTED", "gateway_id": gateway_id})

    def _gateway_regenerate_token(self, gateway_id: str) -> None:
        try:
            raw_token, expires_at = REPOSITORY.create_enrollment_token(gateway_id)
            json_response(
                self,
                200,
                {
                    "gateway_id": gateway_id,
                    "enrollment_token": raw_token,
                    "expires_at": expires_at,
                },
            )
        except ValueError as exc:
            json_response(self, 404 if "NOT_FOUND" in str(exc) else 400, {"error": str(exc)})
        except Exception as exc:
            json_response(self, 500, {"error": "FAILED_TO_GENERATE_TOKEN", "detail": str(exc)})

    def _gateway_revoke(self, gateway_id: str) -> None:
        success = REPOSITORY.revoke_gateway(gateway_id)
        if not success:
            json_response(self, 404, {"error": "GATEWAY_NOT_FOUND"})
            return
        json_response(self, 200, {"status": "REVOKED", "gateway_id": gateway_id})

    def _correlate_analysis(self, analysis_id: str, body: bytes) -> None:
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            json_response(self, 400, {"error": "INVALID_JSON"})
            return
        if not isinstance(payload, dict):
            json_response(self, 400, {"error": "JSON_OBJECT_REQUIRED"})
            return

        gateway_id = payload.get("gateway_id")
        if not gateway_id or not isinstance(gateway_id, str):
            json_response(self, 400, {"error": "GATEWAY_ID_REQUIRED"})
            return

        summary = REPOSITORY.correlate_analysis_with_gateway(analysis_id, gateway_id.strip())
        if summary is None:
            json_response(self, 404, {"error": "ANALYSIS_NOT_FOUND"})
            return
        json_response(self, 200, summary)

    def _serve_install_script(self) -> None:
        host = self.headers.get("Host", f"127.0.0.1:{PORT}")
        server_url = f"http://{host}"
        script = f"""#!/usr/bin/env bash
set -e

SERVER_URL="${{SERVER_URL:-"{server_url}"}}"
INSTALL_DIR="/opt/vpn-analyzer-agent"
BIN_DIR="/usr/local/bin"

if [ "$(id -u)" -ne 0 ]; then
  INSTALL_DIR="$HOME/.vpn-analyzer-agent"
  BIN_DIR="$HOME/.local/bin"
fi

echo "[*] Installing VPN Analyzer Gateway Agent..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$BIN_DIR"

if command -v curl >/dev/null 2>&1; then
  curl -sSL "$SERVER_URL/api/agent/download" | tar -xz -C "$INSTALL_DIR"
elif command -v wget >/dev/null 2>&1; then
  wget -qO- "$SERVER_URL/api/agent/download" | tar -xz -C "$INSTALL_DIR"
else
  echo "[!] Error: curl or wget is required to install the agent."
  exit 1
fi

WRAPPER="$BIN_DIR/vpn-analyzer-agent"
cat << 'EOF' > "$WRAPPER"
#!/usr/bin/env bash
AGENT_DIR="$(dirname "$(realpath "$0")")"
if [ ! -f "$AGENT_DIR/vpn_analyzer_agent.py" ]; then
  AGENT_DIR="/opt/vpn-analyzer-agent"
  if [ ! -f "$AGENT_DIR/vpn_analyzer_agent.py" ]; then
    AGENT_DIR="$HOME/.vpn-analyzer-agent"
  fi
fi
exec python3 "$AGENT_DIR/vpn_analyzer_agent.py" "$@"
EOF

chmod +x "$WRAPPER"
chmod +x "$INSTALL_DIR/vpn_analyzer_agent.py"

echo "[✓] VPN Analyzer Gateway Agent installed successfully!"
echo "[✓] Binary location: $WRAPPER"
echo ""
echo "Next step: Enroll your gateway by running:"
echo "  vpn-analyzer-agent enroll --server $SERVER_URL --token <ONE_TIME_TOKEN>"
"""
        text_response(self, 200, script, content_type="text/x-shellscript")

    def _serve_agent_bundle(self) -> None:
        buf = io.BytesIO()
        base_dir = Path(__file__).resolve().parent
        files_to_pack = [
            ("vpn_analyzer_agent.py", base_dir / "vpn_analyzer_agent.py"),
            ("telemetry.py", base_dir / "telemetry.py"),
            ("sanitizer.py", base_dir / "sanitizer.py"),
            ("correlation.py", base_dir / "correlation.py"),
            ("agent_config.example.json", base_dir / "agent_config.example.json"),
        ]

        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for arcname, filepath in files_to_pack:
                if filepath.exists():
                    tar.add(str(filepath), arcname=arcname)

        binary_response(
            self,
            200,
            buf.getvalue(),
            content_type="application/gzip",
            filename="vpn-analyzer-agent.tar.gz",
        )

    def _serve_gateway_report(self, gateway_id: str) -> None:
        """Generate an immutable gateway-only security assessment report."""
        import time as _time
        gateway = REPOSITORY.get_gateway(gateway_id, include_history=False)
        if gateway is None:
            json_response(self, 404, {"error": "GATEWAY_NOT_FOUND"})
            return

        telemetry = REPOSITORY.get_latest_gateway_telemetry(gateway_id)
        records = telemetry.get("records", []) if telemetry else []
        evidence = telemetry.get("evidence", []) if telemetry else []
        adapter = (telemetry.get("adapter") or gateway.get("telemetry_adapter") or "STRONGSWAN") if telemetry else "STRONGSWAN"
        collected_at = telemetry.get("collectedAt") if telemetry else None
        received_at = telemetry.get("receivedAt") if telemetry else None
        telem_status = (telemetry.get("status") or "NOT_DETERMINABLE") if telemetry else "NOT_DETERMINABLE"

        ike_records = [r for r in records if isinstance(r, dict) and (r.get("version") or r.get("initiator_spi") or r.get("responder_spi") or r.get("prf"))]
        child_records = [r for r in records if isinstance(r, dict) and (r.get("protocol") == "ESP" or r.get("inbound_spi") or r.get("outbound_spi"))]

        # Gateway-only security assessment
        findings = []
        limitations = []

        if not telemetry or not records:
            limitations.append("No telemetry received from the gateway yet. Assessment is incomplete.")
        else:
            # IKE assessment
            for ike in ike_records:
                encr = ike.get("encr", "")
                if encr and any(weak in encr.upper() for weak in ["DES", "3DES", "NULL"]):
                    findings.append({"category": "IKE_ENCRYPTION", "severity": "Critical", "value": encr, "detail": "Weak or null IKE encryption algorithm detected."})
                elif encr:
                    findings.append({"category": "IKE_ENCRYPTION", "severity": "Pass", "value": encr, "detail": "IKE encryption algorithm is acceptable."})
                else:
                    limitations.append("IKE encryption algorithm could not be determined from available telemetry.")

                integ = ike.get("integ", "")
                if integ and any(weak in integ.upper() for weak in ["MD5", "SHA1", "SHA_96"]):
                    findings.append({"category": "IKE_INTEGRITY", "severity": "High", "value": integ, "detail": "Weak IKE integrity/PRF algorithm detected."})
                elif integ:
                    findings.append({"category": "IKE_INTEGRITY", "severity": "Pass", "value": integ, "detail": "IKE integrity algorithm is acceptable."})
                else:
                    limitations.append("IKE integrity algorithm could not be determined from available telemetry.")

                dh = ike.get("dh", "")
                if dh and any(weak in dh.upper() for weak in ["MODP_1024", "MODP_768", "DH_1", "DH_2", "DH_5"]):
                    findings.append({"category": "DH_GROUP", "severity": "High", "value": dh, "detail": "Weak Diffie-Hellman group; susceptible to downgrade attacks."})
                elif dh:
                    findings.append({"category": "DH_GROUP", "severity": "Pass", "value": dh, "detail": "Diffie-Hellman group is acceptable."})
                else:
                    limitations.append("Diffie-Hellman group could not be determined from available telemetry.")

            # Child SA assessment
            for child in child_records:
                c_encr = child.get("encr", "")
                if c_encr and any(weak in c_encr.upper() for weak in ["DES", "3DES", "NULL"]):
                    findings.append({"category": "CHILD_SA_ENCRYPTION", "severity": "Critical", "value": c_encr, "detail": "Weak or null Child-SA encryption detected."})
                elif c_encr:
                    findings.append({"category": "CHILD_SA_ENCRYPTION", "severity": "Pass", "value": c_encr, "detail": "Child-SA encryption algorithm is acceptable."})
                else:
                    limitations.append("Child-SA encryption could not be determined from available telemetry.")

            if not ike_records and not child_records:
                limitations.append("Gateway is connected but no active Security Associations were reported. No cryptographic assessment is possible without active SAs.")

        if not limitations:
            limitations.append("PFS state could not be independently determined from available VICI telemetry.")
        limitations.append("This report reflects the gateway state at the moment the report was generated, not at any arbitrary historical point.")
        if not telemetry:
            limitations.append("Gateway has not submitted telemetry yet. Connect the agent and allow at least one telemetry cycle before generating a report.")

        report_generated_at = _time.strftime("%Y-%m-%d %H:%M:%S", _time.gmtime())

        json_response(self, 200, {
            "reportType": "GATEWAY_SECURITY_REPORT",
            "reportGeneratedAt": report_generated_at,
            "gateway": {
                "gateway_id": gateway["gateway_id"],
                "display_name": gateway["display_name"],
                "gateway_type": gateway["gateway_type"],
                "status": gateway["status"],
                "enrolled_at": gateway.get("enrolled_at"),
                "last_seen_at": gateway.get("last_seen_at"),
                "agent_version": gateway.get("agent_version"),
                "telemetry_adapter": adapter,
                "active_ike_sa_count": gateway.get("active_ike_sa_count", 0),
                "active_child_sa_count": gateway.get("active_child_sa_count", 0),
            },
            "telemetry": {
                "status": telem_status,
                "adapter": adapter,
                "collectedAt": collected_at,
                "receivedAt": received_at,
                "ikeRecords": ike_records,
                "childRecords": child_records,
                "evidence": evidence,
            },
            "securityAssessment": {
                "findings": findings,
                "source": "GATEWAY_TELEMETRY",
                "limitations": limitations,
            },
        })

    def _build_telemetry_summary(self, analysis_id: str) -> dict[str, Any] | None:
        session = REPOSITORY.get_analysis(analysis_id)
        if session is None:
            return None

        telemetry = []
        correlation = {
            "correlation_status": "UNKNOWN",
            "matched": [],
            "unmatchedTelemetry": [],
            "unmatchedPcapSpis": [],
        }

        for item in session.get("telemetry", []):
            record = item.get("record", {}) if isinstance(item, dict) else {}
            if not isinstance(record, dict):
                continue
            telemetry.append({
                "gatewayId": record.get("gateway_id") or record.get("gatewayId"),
                "adapter": record.get("adapter") or "STRONGSWAN",
                "source": record.get("source") or "GATEWAY_TELEMETRY",
                "status": record.get("status") or "NOT_DETERMINABLE",
                "collectedAt": record.get("collected_at") or record.get("collectedAt"),
                "records": record.get("records") or [record],
                "evidence": record.get("evidence") or [],
                "error": record.get("error"),
            })
            entry_correlation = item.get("correlation") if isinstance(item, dict) else None
            if isinstance(entry_correlation, dict):
                if isinstance(entry_correlation.get("matched"), list):
                    correlation["matched"].extend(entry_correlation["matched"])
                if isinstance(entry_correlation.get("unmatchedTelemetry"), list):
                    correlation["unmatchedTelemetry"].extend(entry_correlation["unmatchedTelemetry"])
                if isinstance(entry_correlation.get("unmatchedPcapSpis"), list):
                    correlation["unmatchedPcapSpis"].extend(entry_correlation["unmatchedPcapSpis"])
                if entry_correlation.get("correlation_status") == "CONFIRMED":
                    correlation["correlation_status"] = "CONFIRMED"

        pcap_spis = []
        for packet in session.get("packets", []):
            if isinstance(packet, dict) and packet.get("spi"):
                pcap_spis.append(packet.get("spi"))

        if not correlation["matched"] and not correlation["unmatchedTelemetry"] and session.get("telemetry"):
            correlation["unmatchedPcapSpis"] = list(dict.fromkeys(pcap_spis))

        return {
            "analysisId": analysis_id,
            "gatewayId": telemetry[0].get("gatewayId") if telemetry else None,
            "telemetry": telemetry,
            "correlation": correlation,
            "pcapSpis": list(dict.fromkeys(pcap_spis)),
        }

    def _ingest_metadata(self, body: bytes) -> None:
        if not AGENT_TOKEN:
            json_response(self, 503, {"error": "AGENT_AUTH_NOT_CONFIGURED"})
            return
        authorization = self.headers.get("Authorization", "")
        if authorization != f"Bearer {AGENT_TOKEN}":
            json_response(self, 401, {"error": "UNAUTHORIZED"})
            return
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            json_response(self, 400, {"error": "INVALID_JSON"})
            return
        if not isinstance(value, dict):
            json_response(self, 400, {"error": "JSON_OBJECT_REQUIRED"})
            return
        sanitized = sanitize_analysis_payload(value)
        pcap_spis = [
            packet.get("spi") for packet in sanitized["packets"]
            if packet.get("spi")
        ]
        telemetry = sanitized["telemetry"]
        correlation = correlate_spi(pcap_spis, telemetry)
        analysis_id = sanitized.get("analysis_id")
        if isinstance(analysis_id, str) and analysis_id:
            REPOSITORY.save_telemetry(analysis_id, telemetry, correlation)
        json_response(self, 200, {
            "status": "ACCEPTED",
            "sanitized": sanitized,
            "correlation": correlation,
        })

    def _ingest_analysis_telemetry(self, analysis_id: str, body: bytes) -> None:
        if not analysis_id or len(analysis_id) > 80:
            json_response(self, 400, {"error": "INVALID_ANALYSIS_ID"})
            return
        if not AGENT_TOKEN:
            json_response(self, 503, {"error": "AGENT_AUTH_NOT_CONFIGURED"})
            return
        authorization = self.headers.get("Authorization", "")
        if authorization != f"Bearer {AGENT_TOKEN}":
            json_response(self, 401, {"error": "UNAUTHORIZED"})
            return
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            json_response(self, 400, {"error": "INVALID_JSON"})
            return
        if not isinstance(value, dict):
            json_response(self, 400, {"error": "JSON_OBJECT_REQUIRED"})
            return
        sanitized = sanitize_analysis_payload({**value, "analysis_id": analysis_id})
        pcap_spis = [
            packet.get("spi") for packet in sanitized["packets"]
            if packet.get("spi")
        ]
        telemetry = sanitized["telemetry"]
        if not telemetry and sanitized.get("records"):
            telemetry = sanitized["records"]
        correlation = correlate_spi(pcap_spis, telemetry)
        REPOSITORY.save_telemetry(analysis_id, telemetry, correlation)
        json_response(self, 200, {
            "status": "ACCEPTED",
            "analysisId": analysis_id,
            "sanitized": sanitized,
            "correlation": correlation,
        })

    def log_message(self, format: str, *args: object) -> None:
        print(f"[api] {format % args}")


if __name__ == "__main__":
    print(f"Local analyzer API listening on http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), ApiHandler).serve_forever()

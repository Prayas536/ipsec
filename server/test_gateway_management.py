"""Comprehensive unit and integration tests for Gateway Management, Onboarding, and Telemetry."""

import json
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

from correlation import correlate_spi
from repository import AnalysisRepository, compute_gateway_status


class GatewayManagementTests(unittest.TestCase):
    def setUp(self):
        # Use an in-memory or temporary database for test isolation
        self.repo = AnalysisRepository(":memory:")

    def tearDown(self):
        self.repo.close()

    def test_gateway_registration_and_token_generation(self):
        gateway, raw_token, expires_at = self.repo.create_gateway(
            display_name="Test Gateway Alpha",
            gateway_type="STRONGSWAN",
            validity_seconds=3600,
        )
        self.assertTrue(gateway["gateway_id"].startswith("gw-"))
        self.assertEqual(gateway["display_name"], "Test Gateway Alpha")
        self.assertEqual(gateway["gateway_type"], "STRONGSWAN")
        self.assertEqual(gateway["status"], "NEVER_CONNECTED")
        self.assertTrue(raw_token.startswith("gw_enroll_"))
        self.assertGreater(expires_at, time.time())

    def test_successful_enrollment_and_one_time_token_usage(self):
        gateway, raw_token, expires_at = self.repo.create_gateway("Enrollment Test GW")
        gateway_id = gateway["gateway_id"]

        # First enrollment succeeds
        result = self.repo.enroll_gateway(
            enrollment_token=raw_token,
            agent_version="1.2.0",
            adapter="STRONGSWAN",
        )
        self.assertEqual(result.get("status"), "ENROLLED")
        self.assertEqual(result.get("gateway_id"), gateway_id)
        agent_token = result.get("agent_token")
        self.assertTrue(agent_token.startswith("gw_agent_"))

        # Verify gateway is now enrolled and connected
        updated_gw = self.repo.get_gateway(gateway_id)
        self.assertIsNotNone(updated_gw)
        self.assertEqual(updated_gw["status"], "CONNECTED")
        self.assertEqual(updated_gw["agent_version"], "1.2.0")

        # Second enrollment with same token fails (one-time token requirement)
        second_attempt = self.repo.enroll_gateway(enrollment_token=raw_token)
        self.assertEqual(second_attempt.get("error"), "ENROLLMENT_TOKEN_ALREADY_USED")

    def test_invalid_enrollment_token(self):
        result = self.repo.enroll_gateway(enrollment_token="non_existent_token_12345")
        self.assertEqual(result.get("error"), "INVALID_ENROLLMENT_TOKEN")

    def test_enrollment_token_expiry(self):
        # Create token with validity of -10 seconds (already expired)
        gateway, raw_token, _ = self.repo.create_gateway("Expiry Test GW", validity_seconds=-10)
        result = self.repo.enroll_gateway(enrollment_token=raw_token)
        self.assertEqual(result.get("error"), "ENROLLMENT_TOKEN_EXPIRED")

    def test_agent_authentication(self):
        gateway, raw_token, _ = self.repo.create_gateway("Auth Test GW")
        gateway_id = gateway["gateway_id"]
        enroll_res = self.repo.enroll_gateway(raw_token)
        agent_token = enroll_res["agent_token"]

        # Valid auth
        auth_gw = self.repo.authenticate_agent(gateway_id, agent_token)
        self.assertIsNotNone(auth_gw)
        self.assertEqual(auth_gw["gateway_id"], gateway_id)

        # Invalid token
        invalid_auth = self.repo.authenticate_agent(gateway_id, "wrong_token")
        self.assertIsNone(invalid_auth)

        # Nonexistent gateway
        no_gw = self.repo.authenticate_agent("gw-nonexistent", agent_token)
        self.assertIsNone(no_gw)

    def test_agent_revocation(self):
        gateway, raw_token, _ = self.repo.create_gateway("Revoke Test GW")
        gateway_id = gateway["gateway_id"]
        enroll_res = self.repo.enroll_gateway(raw_token)
        agent_token = enroll_res["agent_token"]

        # Verify active
        self.assertIsNotNone(self.repo.authenticate_agent(gateway_id, agent_token))

        # Revoke gateway
        revoked = self.repo.revoke_gateway(gateway_id)
        self.assertTrue(revoked)

        # Check status is REVOKED
        gw = self.repo.get_gateway(gateway_id)
        self.assertEqual(gw["status"], "REVOKED")

        # Agent authentication immediately fails
        self.assertIsNone(self.repo.authenticate_agent(gateway_id, agent_token))

        # New enrollment on revoked gateway fails
        new_token_res = self.repo.enroll_gateway(raw_token)
        self.assertIn("error", new_token_res)

    def test_heartbeat_and_last_seen_update(self):
        gateway, raw_token, _ = self.repo.create_gateway("Heartbeat Test GW")
        gateway_id = gateway["gateway_id"]
        self.repo.enroll_gateway(raw_token)

        initial_gw = self.repo.get_gateway(gateway_id)
        initial_seen = initial_gw["last_seen_at"]

        time.sleep(0.05)
        self.repo.record_heartbeat(gateway_id)

        updated_gw = self.repo.get_gateway(gateway_id)
        self.assertIsNotNone(updated_gw["last_seen_at"])
        self.assertEqual(updated_gw["status"], "CONNECTED")

    def test_telemetry_submission_and_storage(self):
        gateway, raw_token, _ = self.repo.create_gateway("Telemetry Test GW")
        gateway_id = gateway["gateway_id"]
        self.repo.enroll_gateway(raw_token)

        payload = {
            "source": "GATEWAY_TELEMETRY",
            "adapter": "STRONGSWAN",
            "status": "CONFIRMED",
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "telemetry": [
                {
                    "name": "vpn-conn-1",
                    "version": 2,
                    "state": "ESTABLISHED",
                    "initiator_spi": "0xd4dcc4ccbc2ca500",
                    "responder_spi": "0xea9b13bd33e80006",
                    "encr": "AES_GCM_16_256",
                },
                {
                    "name": "vpn-child-1",
                    "protocol": "ESP",
                    "inbound_spi": "0xcbda18be",
                    "outbound_spi": "0xcceb3e66",
                    "spi": "0xcbda18be",
                    "encr": "AES_GCM_16_256",
                    "mode": "TUNNEL",
                },
            ],
            "evidence": ["Read-only swanctl SA telemetry was parsed."],
        }

        self.repo.record_gateway_telemetry(gateway_id, payload)

        gw = self.repo.get_gateway(gateway_id, include_history=True)
        self.assertEqual(gw["active_ike_sa_count"], 1)
        self.assertEqual(gw["active_child_sa_count"], 1)
        self.assertIsNotNone(gw["latest_telemetry"])
        self.assertEqual(len(gw["history"]), 1)

        latest = self.repo.get_latest_gateway_telemetry(gateway_id)
        self.assertIsNotNone(latest)
        self.assertEqual(latest["adapter"], "STRONGSWAN")
        self.assertEqual(len(latest["records"]), 2)

    def test_multiple_gateways_listing(self):
        gw1, _, _ = self.repo.create_gateway("Production Gateway Alpha")
        gw2, _, _ = self.repo.create_gateway("Branch Office Gateway Beta")
        gw3, _, _ = self.repo.create_gateway("Disaster Recovery Gateway")

        gateways = self.repo.list_gateways()
        self.assertEqual(len(gateways), 3)
        names = [g["display_name"] for g in gateways]
        self.assertIn("Production Gateway Alpha", names)
        self.assertIn("Branch Office Gateway Beta", names)
        self.assertIn("Disaster Recovery Gateway", names)

    def test_gateway_removal(self):
        gateway, _, _ = self.repo.create_gateway("To Remove GW")
        gateway_id = gateway["gateway_id"]
        self.assertIsNotNone(self.repo.get_gateway(gateway_id))

        removed = self.repo.remove_gateway(gateway_id)
        self.assertTrue(removed)
        self.assertIsNone(self.repo.get_gateway(gateway_id))

    def test_regenerate_enrollment_token(self):
        gateway, token1, _ = self.repo.create_gateway("Regen GW")
        gateway_id = gateway["gateway_id"]

        token2, expires2 = self.repo.create_enrollment_token(gateway_id)
        self.assertNotEqual(token1, token2)
        self.assertTrue(token2.startswith("gw_enroll_"))

        # Token 1 was revoked when Token 2 was generated
        res1 = self.repo.enroll_gateway(token1)
        self.assertEqual(res1.get("error"), "ENROLLMENT_TOKEN_REVOKED")

        # Token 2 succeeds
        res2 = self.repo.enroll_gateway(token2)
        self.assertEqual(res2.get("status"), "ENROLLED")

    def test_exact_spi_correlation_confirmed(self):
        # 1. Create and save analysis session with ESP packet having SPI 0xcbda18be
        analysis_data = {
            "scenarioName": "VPN Capture Test",
            "sa": {
                "observations": {"espSpis": ["0xcbda18be"]},
            },
            "packets": [
                {
                    "id": 1,
                    "timestamp": 0.001,
                    "protocol": "ESP",
                    "length": 128,
                    "spi": "0xcbda18be",
                    "seq": 1,
                }
            ],
        }
        analysis_id = self.repo.save_analysis(analysis_data)

        # 2. Register gateway and record telemetry with Child SA SPI 0xcbda18be
        gateway, raw_token, _ = self.repo.create_gateway("Correlation GW")
        gateway_id = gateway["gateway_id"]
        self.repo.enroll_gateway(raw_token)

        self.repo.record_gateway_telemetry(
            gateway_id,
            {
                "status": "CONFIRMED",
                "telemetry": [
                    {
                        "protocol": "ESP",
                        "inbound_spi": "0xcbda18be",
                        "outbound_spi": "0xcceb3e66",
                        "spi": "0xcbda18be",
                        "encr": "AES_GCM_16_256",
                    }
                ],
                "evidence": ["Read-only swanctl SA telemetry was parsed."],
            },
        )

        # 3. Perform server-side exact SPI correlation
        summary = self.repo.correlate_analysis_with_gateway(analysis_id, gateway_id)
        self.assertIsNotNone(summary)
        self.assertEqual(summary["correlationStatus"], "CONFIRMED")
        self.assertIn("0xcbda18be", summary["matchedSpis"])
        self.assertEqual(summary["gatewayId"], gateway_id)

    def test_spi_mismatch_yields_unknown(self):
        analysis_data = {
            "scenarioName": "Unmatched Test",
            "packets": [{"id": 1, "protocol": "ESP", "spi": "0x11112222", "seq": 1}],
        }
        analysis_id = self.repo.save_analysis(analysis_data)

        gateway, raw_token, _ = self.repo.create_gateway("Mismatch GW")
        gateway_id = gateway["gateway_id"]
        self.repo.enroll_gateway(raw_token)

        self.repo.record_gateway_telemetry(
            gateway_id,
            {
                "status": "CONFIRMED",
                "telemetry": [{"inbound_spi": "0x99998888", "spi": "0x99998888"}],
            },
        )

        summary = self.repo.correlate_analysis_with_gateway(analysis_id, gateway_id)
        self.assertIsNotNone(summary)
        self.assertEqual(summary["correlationStatus"], "UNKNOWN")
        self.assertEqual(summary["matchedSpis"], [])
        self.assertIn("0x11112222", summary["unmatchedPcapSpis"])

    def test_telemetry_unavailable_for_analysis(self):
        analysis_data = {
            "scenarioName": "No Telemetry Test",
            "packets": [{"id": 1, "protocol": "ESP", "spi": "0x12345678", "seq": 1}],
        }
        analysis_id = self.repo.save_analysis(analysis_data)

        gateway, _, _ = self.repo.create_gateway("Empty GW")
        gateway_id = gateway["gateway_id"]

        summary = self.repo.correlate_analysis_with_gateway(analysis_id, gateway_id)
        self.assertIsNotNone(summary)
        self.assertEqual(summary["correlationStatus"], "UNKNOWN")
        self.assertEqual(summary["gatewayStatus"], "NOT_DETERMINABLE")
        self.assertIn("No telemetry available", summary["evidence"][0])



class GatewayApiHttpIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import tempfile
        import threading
        from http.server import ThreadingHTTPServer
        import api_server

        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = Path(cls.temp_dir.name) / "test_api.sqlite3"
        cls.orig_repo = api_server.REPOSITORY
        api_server.REPOSITORY = AnalysisRepository(cls.db_path)

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), api_server.ApiHandler)
        cls.port = cls.server.server_port
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        import api_server
        cls.server.shutdown()
        cls.server.server_close()
        api_server.REPOSITORY = cls.orig_repo
        cls.temp_dir.cleanup()

    def _http_request(self, method, path, body=None, headers=None):
        import urllib.request
        url = f"{self.base_url}{path}"
        data = None
        req_headers = headers or {}
        if body is not None:
            if isinstance(body, (dict, list)):
                data = json.dumps(body).encode("utf-8")
                req_headers["Content-Type"] = "application/json"
            elif isinstance(body, bytes):
                data = body
            elif isinstance(body, str):
                data = body.encode("utf-8")

        req = urllib.request.Request(url, data=data, method=method, headers=req_headers)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp_body = resp.read()
                content_type = resp.headers.get("Content-Type", "")
                if "application/json" in content_type:
                    return resp.status, json.loads(resp_body.decode("utf-8"))
                return resp.status, resp_body
        except urllib.error.HTTPError as exc:
            err_body = exc.read()
            try:
                return exc.code, json.loads(err_body.decode("utf-8"))
            except Exception:
                return exc.code, err_body

    def test_http_gateway_full_lifecycle(self):
        # 1. POST /api/gateways -> register
        status, data = self._http_request("POST", "/api/gateways", {"display_name": "HTTP Test Gateway"})
        self.assertEqual(status, 201)
        gateway_id = data["gateway_id"]
        enroll_token = data["enrollment_token"]
        self.assertTrue(gateway_id.startswith("gw-"))
        self.assertTrue(enroll_token.startswith("gw_enroll_"))

        # 2. GET /api/gateways -> list
        status, gws = self._http_request("GET", "/api/gateways")
        self.assertEqual(status, 200)
        found = [g for g in gws if g["gateway_id"] == gateway_id]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["status"], "NEVER_CONNECTED")

        # 3. POST /api/gateways/enroll -> enroll
        status, enroll_res = self._http_request(
            "POST", "/api/gateways/enroll",
            {"token": enroll_token, "agent_version": "1.2.0", "adapter": "strongswan"}
        )
        self.assertEqual(status, 200)
        agent_token = enroll_res["agent_token"]
        self.assertTrue(agent_token.startswith("gw_agent_"))

        # 4. POST /api/gateways/<id>/heartbeat without auth -> 401
        status, _ = self._http_request("POST", f"/api/gateways/{gateway_id}/heartbeat")
        self.assertEqual(status, 401)

        # 5. POST /api/gateways/<id>/heartbeat with auth -> 200
        status, hb_res = self._http_request(
            "POST", f"/api/gateways/{gateway_id}/heartbeat",
            headers={"Authorization": f"Bearer {agent_token}"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(hb_res["status"], "OK")

        # 6. POST /api/gateways/<id>/telemetry -> 200
        status, telem_res = self._http_request(
            "POST", f"/api/gateways/{gateway_id}/telemetry",
            body={
                "status": "CONFIRMED",
                "telemetry": [
                    {"protocol": "ESP", "inbound_spi": "0x55556666", "spi": "0x55556666"}
                ]
            },
            headers={"Authorization": f"Bearer {agent_token}"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(telem_res["status"], "ACCEPTED")

        # 7. GET /api/gateways/<id> -> details
        status, gw_detail = self._http_request("GET", f"/api/gateways/{gateway_id}")
        self.assertEqual(status, 200)
        self.assertEqual(gw_detail["status"], "CONNECTED")
        self.assertEqual(gw_detail["active_child_sa_count"], 1)

        # 8. GET /api/agent/install.sh
        status, install_script = self._http_request("GET", "/api/agent/install.sh")
        self.assertEqual(status, 200)
        self.assertIn(b"vpn-analyzer-agent", install_script)

        # 9. GET /api/agent/download
        status, bundle_bytes = self._http_request("GET", "/api/agent/download")
        self.assertEqual(status, 200)
        self.assertTrue(len(bundle_bytes) > 1000)

        # 10. POST /api/gateways/<id>/revoke
        status, rev_res = self._http_request("POST", f"/api/gateways/{gateway_id}/revoke")
        self.assertEqual(status, 200)
        self.assertEqual(rev_res["status"], "REVOKED")

        # 11. Subsequent agent request rejected
        status, _ = self._http_request(
            "POST", f"/api/gateways/{gateway_id}/heartbeat",
            headers={"Authorization": f"Bearer {agent_token}"}
        )
        self.assertEqual(status, 401)

        # 12. DELETE /api/gateways/<id>
        status, del_res = self._http_request("DELETE", f"/api/gateways/{gateway_id}")
        self.assertEqual(status, 200)
        self.assertEqual(del_res["status"], "REMOVED")

    def test_agent_cli_enroll_and_run_flow(self):
        import vpn_analyzer_agent
        # 1. Register gateway
        status, data = self._http_request("POST", "/api/gateways", {"display_name": "CLI Agent Test GW"})
        self.assertEqual(status, 201)
        gateway_id = data["gateway_id"]
        enroll_token = data["enrollment_token"]

        # 2. Enroll using vpn_analyzer_agent.enroll_agent
        temp_config = self.db_path.parent / "test_agent_config.json"
        enroll_result = vpn_analyzer_agent.enroll_agent(
            server=self.base_url,
            token=enroll_token,
            adapter="none",
            config_path=temp_config,
        )
        self.assertEqual(enroll_result["status"], "ENROLLED")
        self.assertEqual(enroll_result["gateway_id"], gateway_id)
        self.assertTrue(temp_config.exists())

        # Verify gateway is CONNECTED
        status, gw = self._http_request("GET", f"/api/gateways/{gateway_id}")
        self.assertEqual(status, 200)
        self.assertEqual(gw["status"], "CONNECTED")

        # 3. Run agent once
        exit_code = vpn_analyzer_agent.run_agent(
            config_path=temp_config,
            once=True,
        )
        self.assertEqual(exit_code, 0)

        # 4. Check telemetry was recorded
        # 5. Check security report endpoint
        status, report = self._http_request("GET", f"/api/gateways/{gateway_id}/report")
        self.assertEqual(status, 200)
        self.assertEqual(report["reportType"], "GATEWAY_SECURITY_REPORT")
        self.assertEqual(report["gateway"]["gateway_id"], gateway_id)
        self.assertIn("securityAssessment", report)
        self.assertIn("findings", report["securityAssessment"])
        self.assertIn("limitations", report["securityAssessment"])


if __name__ == "__main__":
    unittest.main()



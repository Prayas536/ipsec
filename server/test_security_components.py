import unittest

from correlation import correlate_spi
from sanitizer import sanitize_analysis_payload
from telemetry import ViciAdapter, parse_swanctl_records, parse_vici_records
from scapy_analyzer import parse_ike
from live_capture import capture_from_packets
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.ipsec import ESP
from scapy.packet import Raw


class SecurityComponentTests(unittest.TestCase):
    def test_ikev2_visible_metadata(self):
        header = bytearray(28)
        header[16] = 41
        header[17] = 0x20
        header[18] = 34
        header[19] = 0x28
        notify = bytes([43, 0, 0, 8, 0, 0]) + (16388).to_bytes(2, "big")
        vendor = bytes([0, 0, 0, 8]) + b"TEST"
        message = header + notify + vendor
        message[24:28] = len(message).to_bytes(4, "big")
        result = parse_ike(bytes(message))
        self.assertEqual(result["ikeVersion"], "IKEv2")
        self.assertIn("Response", result["flags"])
        self.assertIn("Initiator", result["flags"])
        self.assertIn("NAT_DETECTION_SOURCE_IP", result["notifications"])
        self.assertIn("0x54455354", result["vendorIds"])

    def test_ikev1_payload_names_without_v2_proposal_decode(self):
        header = bytearray(28)
        header[16] = 13
        header[17] = 0x10
        header[18] = 2
        vendor = bytes([0, 0, 0, 8]) + b"V1ID"
        message = header + vendor
        message[24:28] = len(message).to_bytes(4, "big")
        result = parse_ike(bytes(message))
        self.assertEqual(result["ikeVersion"], "IKEv1")
        self.assertEqual(result["payloads"], ["VENDOR"])
        self.assertEqual(result["proposals"], [])
        self.assertEqual(result["vendorIds"], ["0x56314944"])

    def test_correlation_requires_exact_spi(self):
        result = correlate_spi(
            ["0x1234"],
            [{"outbound_spi": "0x1234", "encr": "aes256gcm16"}, {"outbound_spi": "0x9999"}],
        )
        self.assertEqual(result["correlation_status"], "CONFIRMED")
        self.assertEqual(result["matched"][0]["matched_spis"], ["0x1234"])
        self.assertEqual(result["unmatchedTelemetry"][0]["correlation_status"], "UNKNOWN")

    def test_sanitizer_drops_payload_and_secret_fields(self):
        result = sanitize_analysis_payload({
            "analysis_id": "capture-1",
            "packets": [{"protocol": "ESP", "spi": "0x1234", "payload": "secret", "session_key": "secret"}],
            "telemetry": [{"encr": "aes256gcm16", "private_key": "secret"}],
        })
        self.assertNotIn("payload", result["packets"][0])
        self.assertNotIn("session_key", result["packets"][0])
        self.assertNotIn("private_key", result["telemetry"][0])

    def test_swanctl_parser_keeps_only_recognized_metadata(self):
        records = parse_swanctl_records(
            "name: site-a\n"
            "outbound-spi: 0x1234\n"
            "encr: aes256gcm16\n"
            "private-key: must-not-be-kept\n"
        )
        self.assertEqual(records[0]["outbound_spi"], "0x1234")
        self.assertNotIn("private_key", records[0])

    def test_vici_parser_keeps_only_sa_metadata(self):
        records = parse_vici_records({
            "site-a": {
                "state": "ESTABLISHED",
                "outbound_spi": "0x1234",
                "encr": "aes256gcm16",
                "session_key": "secret",
            }
        })
        self.assertEqual(records[0]["outbound_spi"], "0x1234")
        self.assertNotIn("session_key", records[0])

    def test_vici_adapter_uses_read_only_list_sas_request(self):
        class FakeSession:
            requests = []

            def request(self, name, payload):
                self.requests.append((name, payload))
                return {"site-a": {"state": "ESTABLISHED", "mode": "tunnel"}}

        result = ViciAdapter(client_factory=FakeSession).collect()
        self.assertEqual(result.status, "CONFIRMED")
        self.assertEqual(FakeSession.requests, [("list-sas", {})])

    def test_live_metadata_extracts_native_esp_without_payload(self):
        result = capture_from_packets([
            IP(src="192.0.2.1", dst="198.51.100.1") / ESP(spi=0x1234, seq=9) / Raw(b"secret")
        ])[0]
        self.assertEqual(result["protocol"], "ESP")
        self.assertEqual(result["spi"], "0x00001234")
        self.assertEqual(result["sequence_observed"], 9)
        self.assertNotIn("payload", result)

    def test_live_metadata_detects_nat_t_esp(self):
        result = capture_from_packets([
            IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=4500, dport=4500) /
            Raw((0x12345678).to_bytes(4, "big") + (4).to_bytes(4, "big") + b"secret")
        ])[0]
        self.assertEqual(result["protocol"], "ESP")
        self.assertEqual(result["spi"], "0x12345678")
        self.assertNotIn("secret", result.values())


if __name__ == "__main__":
    unittest.main()

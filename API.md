# Current Interfaces

## Browser parser

`parseUploadedFile(file: File)` returns `ParsedPcapResult` for classic PCAP and PCAPNG.

## Local Scapy service

`POST http://127.0.0.1:8765/analyze`

Request body: raw PCAP/PCAPNG bytes.

Headers:

- `Content-Type: application/octet-stream`
- `X-Filename: original filename`

The response contains packets, SA data, features, observations, and evidence. The service is local-only by default.

## Agent

The current agent is a command-line interface rather than a network API. It supports local PCAP analysis and optional HTTPS metadata submission. A production cloud API gateway still needs authentication, request validation, rate limiting, replay protection, persistence, and deployment configuration before it can be exposed publicly.

## Local persistence endpoints

`POST /api/analyze/pcap` now persists a sanitized analysis session in SQLite and returns an `analysisId`.

`GET /api/analysis/{analysisId}` retrieves the stored SA summary, features, observations, packet metadata, and correlated telemetry. Raw packet previews, debug dumps, payloads, and source IP fields are not stored.

Set `VPN_ANALYZER_DATABASE` to choose the SQLite path. The default is `data/analyzer.sqlite3`.

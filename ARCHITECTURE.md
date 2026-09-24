# Architecture

Current implemented path:

`PCAP/PCAPNG -> Scapy service or browser parser -> normalized packet/SA/features -> evidence model -> security rules and traffic inference -> dashboard`

Optional local-agent path:

`PCAP -> Scapy analyzer + StrongSwan read-only telemetry -> exact SPI correlation -> sanitized local/cloud result`

The local API persists sanitized results through `server/repository.py` using SQLite. Analysis sessions, packet metadata, and gateway telemetry are separated into tables. Raw payloads and packet debug/preview fields are explicitly excluded from persistence.

The evidence model is shared at the TypeScript dashboard boundary. Gateway telemetry, correlation, and sanitization are implemented as isolated Python modules so they can later be placed behind an authenticated API without coupling protocol parsing to React.

Live packet capture, persistent analysis storage, and public cloud deployment remain separate integration work and are not represented as complete features.

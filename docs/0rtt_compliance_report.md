# 0-RTT (Early Data) Standards-Compliance Report

Scope: the 0-RTT implementation on this branch — TLS 1.3 (RFC 8446), DTLS 1.3
(RFC 9147) and QUIC-TLS (RFC 9001) — covering the key schedule, record layer,
handshake state machine, extension handling, anti-replay, and the public API
(`HITLS_WriteEarlyData` / `HITLS_ReadEarlyData` / `HITLS_GetEarlyDataStatus` /
`HITLS_SetMaxEarlyDataSize` / `HITLS_SESS_GetMaxEarlyData` /
`HITLS_QUIC_TLS_SetEarlyDataEnabled`).

Method: every normative requirement (MUST / MUST NOT / SHOULD) of the relevant
sections was audited against the code by seven independent review passes
(client rules, server rules, anti-replay, record & key schedule, DTLS 1.3,
QUIC, API robustness — 146 individual findings), and every claimed
non-compliance was re-verified adversarially against the source. Findings that
survived verification were fixed on this branch where feasible; the remainder
are documented below.

## Summary

| Area | Result |
| --- | --- |
| RFC 8446 §4.2.10 client rules (offer conditions, PSK/cipher/ALPN binding, HRR, EncryptedExtensions verdict) | Compliant |
| RFC 8446 §4.5 EndOfEarlyData (send/receive, transcript, key switch, stream-TLS only) | Compliant |
| RFC 8446 §4.2.10 server rules (three behaviours, accept preconditions, reject-skip) | Compliant (skip of oversize protected records fixed during audit) |
| RFC 8446 §4.6.1 NewSessionTicket `early_data` / `max_early_data_size` enforcement | Compliant |
| RFC 8446 §8 per-instance at-most-once acceptance (anti-replay MUST) | Compliant (window-bounded ClientHello recording added during audit) |
| RFC 8446 §5.1/§5.2/§5.4 record framing of 0-RTT records | Compliant on send; receiver stricter than the RFC (pre-existing, see D2) |
| RFC 8446 §7.1 key schedule (`c e traffic` derivation, transcript, PSK hash) | Compliant |
| RFC 8446 D.3 fail-on-downgrade after a 0-RTT offer | Compliant (added during audit) |
| RFC 9147 DTLS 1.3 (epoch 1, unified header, no EndOfEarlyData, `dtls13` labels, silent discard) | Compliant (late epoch-1 discard fixed during audit) |
| RFC 9001 QUIC (0xffffffff sentinel, EARLY_DATA secret delivery, no TLS-carried app data, no EndOfEarlyData) | Compliant |

## Fixes applied as a result of the audit

1. **RFC 8446 Appendix D.3** — a client that offered 0-RTT now fails the
   connection with a fatal `illegal_parameter` alert when the ServerHello
   negotiates TLS 1.2 or older (`recv_server_hello.c`). Previously the
   downgraded handshake proceeded with the early write keys still active.
2. **RFC 8446 §4.2.10 / §5.2 post-HelloRetryRequest skip** — protected
   early-data records with ciphertext bodies in the 16385..16640-byte range
   (legal per §5.2) are now skipped within the allowance while the server
   awaits the second ClientHello in plaintext, instead of aborting with
   `record_overflow` (`rec_read.c`).
3. **RFC 8446 §8 anti-replay (MUST)** — per-server-instance at-most-once
   acceptance of a 0-RTT handshake is now enforced by recording the PSK binder
   (unique per ClientHello) of every accepted 0-RTT handshake in a bounded
   ring shared through the configuration's session manager, held for three
   times the ticket-age freshness window; a duplicate binder falls back to
   1-RTT (`session_mgr.c`, `recv_client_hello.c`). Combined with the
   pre-existing `obfuscated_ticket_age` freshness window (10 s) this
   implements the §8.2 ClientHello-recording mechanism with bounded memory.
4. **RFC 9147 silent-discard posture** — a late or reordered epoch-1 record
   arriving after a DTLS 1.3 server rejected 0-RTT (or after the early phase
   ended) is now discarded silently instead of terminating the connection
   with `unexpected_message` (`rec_read.c`).
5. **Server-side buffering bound** — early data buffered while the handshake
   is driven with `HITLS_Accept` (rather than `HITLS_ReadEarlyData`) is now
   counted and capped at the advertised `max_early_data_size`; excess
   terminates the connection with `unexpected_message` instead of growing the
   heap without bound (`rec_read.c`).
6. **Early-phase read boundary** — once the early phase is over,
   `HITLS_ReadEarlyData` only drains records buffered during the phase and
   never reads fresh records, so pipelined 1-RTT application data can neither
   be delivered through the early-data API nor be miscounted against the
   early-data limit (`conn_early_data.c`).
7. **Busy-transport write bookkeeping** — an early-data record retained by
   the record layer after a busy transport (out-buffer or flight buffer) is
   now uniformly staged: the bytes are accounted once when staged, a retry
   completes flush-only (never re-encrypting, so the same plaintext cannot be
   sent twice even if `HITLS_Flush` or the handshake flushed it in between),
   and a handshake message can no longer be swallowed by the record layer's
   flush-retry path (`conn_early_data.c`, `send_common.c`, `record.c`,
   including sequence-number ownership across write-state switches in
   `rec_write.c`).

## Documented limitations and deviations

* **D1 — Global (cross-instance) at-most-once is not provided.** RFC 8446 §8
  makes infrastructure-wide replay prevention a SHOULD. The binder-recording
  store is per session manager (per `HITLS_Config`); deployments with several
  server processes sharing a ticket key need an external mechanism if they
  require global at-most-once. The ring holds 256 entries; beyond ~256
  accepted 0-RTT handshakes per 30 s window the guarantee degrades gracefully
  (oldest entries are evicted). Fresh-start overlap (§8.2 SHOULD: reject 0-RTT
  while the recording window overlaps the startup time) is not implemented;
  the 10 s freshness window bounds the exposure.
* **D2 — `legacy_record_version` is checked, not ignored (pre-existing).**
  RFC 8446 §5.1 says the field "MUST be ignored for all purposes"; the
  openHiTLS record layer has always required `0x0303` on protected TLS 1.3
  records and this branch keeps that behaviour (the 0-RTT sender was made
  compliant: the compat CCS and all 0-RTT records now carry `0x0303`).
  Interop against conforming peers is unaffected.
* **D3 — `early_exporter_master_secret` is not derived.** The "e exp master"
  derivation, an early-exporter API, and the `EARLY_EXPORTER_SECRET`
  SSLKEYLOGFILE line are not implemented (exporters over 0-RTT data are an
  optional feature; the regular exporter is unaffected).
* **D4 — Single-use tickets (§8.1) are not implemented.** Tickets are
  stateless (self-encrypted); at-most-once acceptance is provided by the
  §8.2-style recording above instead, which the RFC allows.
* **D5 — Status reporting is conservative.** While the offer is still
  undecided, `HITLS_GetEarlyDataStatus` reports `HITLS_EARLY_DATA_NOT_SENT`;
  it reports `ACCEPTED`/`REJECTED` as soon as the verdict is known. An
  application that abandons an interrupted `HITLS_WriteEarlyData` retry and
  finishes the handshake instead should treat bytes staged by a busy write as
  sent (a later retry with the same buffer reports them as written; the
  connection's early-data status says whether the peer processed them).
* **D6 — Application profile.** RFC 8446 §2.3/E.5 requires an application
  profile before using 0-RTT (replay-safe request selection). That obligation
  binds the application protocol; the library keeps 0-RTT off until the
  application both configures `maxEarlyDataSize > 0` and calls
  `HITLS_WriteEarlyData` (or enables it explicitly for QUIC).

## Protocol-behaviour highlights (verified)

* Client offers 0-RTT only with a ticket that permits it, from the first PSK,
  with the ticket's cipher suite and a still-offered ALPN protocol, never
  after HelloRetryRequest, and only with explicit application intent; the
  second ClientHello after an HRR carries no `early_data` extension and is
  sent unprotected.
* EndOfEarlyData is sent exactly when the server accepted (stream TLS 1.3
  only — never in DTLS 1.3, never in QUIC), is included in the transcript,
  and is followed by the switch to the handshake write keys; the server
  requires it on the accept path and treats it as fatal `unexpected_message`
  otherwise.
* The server accepts only with the first PSK selected via a ticket, matching
  cipher suite and ALPN, a fresh `obfuscated_ticket_age` (±10 s), and an
  unseen binder; otherwise it falls back to 1-RTT and skips undecryptable
  early records within a bounded allowance derived from
  `max_early_data_size`.
* 0-RTT records are TLS 1.3 records in every aspect before version
  negotiation completes: `0x0301` appears only on the record holding the
  initial ClientHello; the compat CCS and all early records carry `0x0303`,
  AEAD AAD/nonce and inner-plaintext framing follow §5.2/§5.4, and
  `client_early_traffic_secret = Derive-Secret(Early Secret, "c e traffic",
  ClientHello)` is computed over the exact ClientHello with the ticket
  suite's hash.
* DTLS 1.3 early data uses epoch 1 with the unified header and the `dtls13`
  HKDF label prefix; the server keeps the epoch-1 read state as the outdated
  state while at epoch 2, reconstructs the epoch from the 2-bit field, and
  silently discards epoch-1 records it cannot (or may no longer) process.
* QUIC tickets permitting 0-RTT always advertise `0xffffffff`; a client
  treats any other value as a protocol violation. EARLY_DATA-level secrets
  are delivered through the secret callbacks (client write / server read
  only) without advancing the CRYPTO stream levels, and the TLS layer never
  carries application data (`HITLS_WriteEarlyData`/`HITLS_ReadEarlyData` are
  rejected in QUIC mode).

## Test coverage

`testcode/sdv/testcase/tls/feature/tls13_0rtt/` (13 cases): accept end-to-end
with 1-RTT continuation, ClientHello extension presence/absence, reject with
record skip, tickets without permission, client-side limit enforcement, API
misuse, HelloRetryRequest implicit rejection, stale ticket age, ALPN change,
version-downgrade abort (D.3), ClientHello replay rejection (§8), and
DTLS 1.3 epoch-1 accept/reject. QUIC 0-RTT resumption (EARLY_DATA secrets,
sentinel enforcement, level invariance) is covered in
`testcode/sdv/testcase/tls/feature/quic_tls/test_suite_sdv_quic_tls_interaction.c`.

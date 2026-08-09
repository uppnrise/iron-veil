# Security Policy

IronVeil sits in the data path of databases holding personal data. A masking
bypass, a control-plane weakness, or silent data corruption in this proxy has
direct consequences for its users, so security reports are welcome and taken
seriously.

## Reporting a vulnerability

Please report privately rather than in a public issue. Use GitHub's private
vulnerability reporting on this repository ("Security" → "Report a
vulnerability"). If that is unavailable to you, open an issue containing only
a request for a private contact channel — no details.

Include, as far as you can:

- what the issue is and which component it affects (proxy data path,
  management API, dashboard, build/release tooling),
- a reproduction: a query, packet capture, config, or request that shows it,
- the version or commit you tested,
- the impact you believe it has.

## What to expect

- Acknowledgement within **3 business days**.
- An assessment (accepted / not-a-vulnerability / needs-more-info) within
  **10 business days**.
- For accepted reports, a fix or a documented mitigation, and credit in the
  release notes unless you prefer otherwise.

This is a small project without a paid bounty program.

## In scope

- Masking bypasses: any way to retrieve values from a column an explicit rule
  covers, through either protocol.
- Silent data corruption: values the proxy rewrites or truncates when no rule
  asked it to.
- Control-plane issues: authentication bypass on the management API,
  disabling masking without credentials, CORS/CSRF, credential exposure.
- Retention or re-serving of pre-masking values through logs, metrics, the
  audit trail or the dashboard.
- Protocol-level memory-safety issues: panics, unbounded allocation or
  desynchronization reachable from an unauthenticated socket.

## Known limitations (not vulnerabilities)

These are documented design boundaries, not defects. See the "Security
Posture" section of `README.md`.

- Masking is **best effort against a legitimate query author**. Provenance is
  not recoverable for computed columns, so `SELECT CONCAT(email, '')` and
  similar expressions are matched by result-set label only. IronVeil is a
  compliance and convenience control, not an adversarial boundary.
- IronVeil masks the **text protocol only**. MySQL server-side prepared
  statements are rejected with `ER_UNSUPPORTED_PS` (1295) rather than
  forwarded unmasked; PostgreSQL `COPY ... TO STDOUT` is forwarded unmasked
  with a warning and a metric.
- Read-only access is enforced by database privileges (`GRANT SELECT`), not by
  the proxy. IronVeil does not parse or filter SQL, and write transparency is
  intended behaviour.
- Heuristic detection is shape-based. With the opt-in detectors enabled it
  will rewrite non-PII values that share a shape (order numbers, host
  addresses, dates). Use explicit rules where correctness matters.

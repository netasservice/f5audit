# f5audit

Read-only audit tool for **F5 BIG-IP LTM**. It collects configuration and
statistics via iControl REST (GET only), correlates object references, and
produces a multi-sheet **Excel report** identifying unused objects (nodes,
pools, virtual servers, monitors) as input for a human-driven, change-
controlled cleanup.

**This tool never modifies the device.** The "suggested command" columns in
the report are informational text only; nothing is ever executed.

## Safety design

- The HTTP client (`F5ReadOnlyClient`) exposes a single `get()` method.
  There are no `post`/`patch`/`put`/`delete` methods. The only internal
  write is the token login, hardcoded to `/mgmt/shared/authn/login`.
  This is enforced by structural tests.
- No `tmsh`/bash execution endpoints are used or referenced anywhere.
- No explicit logout (deleting the token would be a write); tokens expire
  on their own (~20 minutes).
- Passwords are read from an interactive prompt (`getpass`) or the
  `F5_PASS` environment variable — never from a CLI argument, and never
  written to disk or logs.
- Management-plane friendly: sequential requests only, `$top`/`$skip`
  pagination, per-request delay (`--delay`, default 0.1 s), 30 s timeout,
  max 2 retries with exponential backoff.

## Requirements

- Python >= 3.9, `requests`, `openpyxl`
- An account with a **read-only role** (Auditor/Guest) and iControl REST
  access on the BIG-IP
- Network access to the management interface (TCP 443)

## Installation

```
pip install .
```

Or without installing, from the project directory: `python -m f5audit ...`

## Usage

### 1. Validate access first

```
f5audit validate --host 192.0.2.1 --user auditor --insecure
```

Probes login plus the key GET endpoints and prints a diagnosis per
response code (bad credentials, missing REST access, denied endpoints,
old BIG-IP versions, network timeouts).

### 2. Collect once, analyze offline N times

```
f5audit collect --host 192.0.2.1 --user auditor --insecure --save-raw ./raw/
f5audit analyze --from-raw ./raw/ --out report.xlsx
```

`collect` saves every raw JSON response (with timestamps) to disk;
`analyze --from-raw` re-analyzes from that cache **without touching the
F5 again**. This is the recommended workflow: one collection per session,
all further analysis offline.

### One-step alternative

```
f5audit analyze --host 192.0.2.1 --user auditor --insecure --save-raw ./raw/ --out report.xlsx
```

### Options

| Flag | Meaning |
|---|---|
| `--user` / `F5_USER` | Username (password via prompt or `F5_PASS`) |
| `--login-provider` | Token auth provider (default `tmos`; set for TACACS+/RADIUS) |
| `--insecure` | Skip TLS verification (self-signed mgmt certs); prints a warning |
| `--delay` | Seconds between requests (default 0.1) |
| `--top` | Pagination page size (default 100) |
| `--format xlsx\|csv` | Excel workbook or one CSV per sheet |
| `--allow-standby` | On a standby unit, emit traffic verdicts marked `UNRELIABLE (standby)` instead of skipping them |

Exit codes: `0` OK · `1` connection/auth error · `2` analysis completed
with warnings (standby device, denied partitions, missing endpoints).

## Verdicts

| Verdict | Meaning |
|---|---|
| `ORPHAN` | Not referenced by anything (node: no pool membership; pool: no VS/iRule/policy reference; monitor: no user). Only issued when the inventory is complete and no dynamic iRules are active. |
| `MANUAL REVIEW` | A dynamic iRule (`pool $var`, `pool [...]`, datagroups) or a missing `ltm/rule` endpoint means the object *could* be referenced at runtime. Never auto-cleanup these. |
| `INACTIVE` | Configured and referenced, but disabled or zero total connections since the last counter reset. |
| `UNRELIABLE (standby)` | Traffic-based verdict computed on a standby unit (only with `--allow-standby`). |
| `UNRELIABLE (incomplete inventory)` | Some partitions were not readable; a reference could exist in an invisible partition. |
| `IN USE` | Everything else. |

## Operational warning

- **Collect on the ACTIVE unit** of the HA pair. On a standby unit traffic
  counters are zeros and the tool will skip traffic analysis (or mark it
  `UNRELIABLE` with `--allow-standby`).
- Traffic counters reset on reboot / stats reset. Ideally collect after
  **several weeks of uptime**; the report includes the failover-state age
  as context.
- `INACTIVE` means "no traffic since the counters started", not "safe to
  delete". Use the planned `compare` workflow (v2) — two collections some
  weeks apart — to distinguish real zero traffic from a recent reset.
  The raw cache already stores per-file timestamps to enable this.

## Report sheets

1. **Summary** — hostname, version, HA state, uptime context, partitions,
   verdict counts, active warnings.
2. **Inventory** — one row per pool member (plus rows for pool-less
   nodes), fully correlated: node ↔ pool ↔ virtual server ↔ monitor ↔
   iRule/policy references, statuses, traffic and verdict.
3. **Orphan Nodes** · 4. **Orphan-Inactive Pools** · 5. **Inactive
   Virtual Servers** · 6. **Orphan Monitors** — filtered views with
   informational `tmsh` commands for the change request.
7. **Manual Review** — objects touched by dynamic logic, with the
   iRule/policy that causes the doubt.

Color coding: red = ORPHAN · yellow = MANUAL REVIEW / UNRELIABLE ·
orange = INACTIVE · green = IN USE.

## Development

```
pip install -e ".[dev]"
pytest
```

No test touches the network; everything runs from anonymized JSON
fixtures and mocked HTTP sessions. Structural tests assert the client
exposes no write verbs and that no forbidden endpoint appears in the
source.

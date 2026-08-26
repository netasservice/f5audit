"""Command line interface: collect / analyze / validate."""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from . import __version__
from .analyzer import Analyzer
from .client import F5APIError, F5AuthError, F5ClientError, F5ReadOnlyClient
from .collector import CollectionData, Collector, RawStore, load_from_raw
from .correlator import correlate
from .parsing import parse_collection
from .report import build_tables, default_report_name, write_csv, write_xlsx

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_WARNINGS = 2

logger = logging.getLogger("f5audit")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _add_connection_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", help="BIG-IP management address")
    parser.add_argument(
        "--user",
        help="Username (or set the F5_USER environment variable)",
    )
    parser.add_argument(
        "--login-provider",
        default="tmos",
        help="Auth provider for token login (default: tmos; use the remote "
        "provider name for TACACS+/RADIUS setups)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Skip TLS certificate verification (self-signed mgmt certs)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.1,
        help="Delay in seconds between requests (default: 0.1)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=100,
        help="Page size for collection pagination (default: 100)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="f5audit",
        description="Read-only audit of an F5 BIG-IP LTM configuration. Never modifies the device.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument(
        "--verbose", action="store_true", help="Debug logging (never prints passwords/tokens)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    collect_parser = subparsers.add_parser(
        "collect", help="Collect configuration and stats, save raw JSON"
    )
    _add_connection_args(collect_parser)
    collect_parser.add_argument(
        "--save-raw",
        metavar="DIR",
        help="Directory for raw JSON cache (default: ./f5audit_raw_<host>_<ts>)",
    )

    analyze_parser = subparsers.add_parser(
        "analyze", help="Analyze (from a live device or a raw cache) and report"
    )
    _add_connection_args(analyze_parser)
    analyze_parser.add_argument(
        "--from-raw", metavar="DIR", help="Analyze a previously saved raw cache"
    )
    analyze_parser.add_argument(
        "--save-raw", metavar="DIR", help="Also save raw JSON while collecting"
    )
    analyze_parser.add_argument("--out", help="Output report path")
    analyze_parser.add_argument("--format", choices=["xlsx", "csv"], default="xlsx")
    analyze_parser.add_argument(
        "--allow-standby",
        action="store_true",
        help="On a standby unit, emit traffic verdicts marked UNRELIABLE "
        "instead of skipping traffic analysis",
    )

    validate_parser = subparsers.add_parser(
        "validate", help="Probe access: login plus key GET endpoints"
    )
    _add_connection_args(validate_parser)

    return parser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_credentials(args) -> tuple:
    username = args.user or os.environ.get("F5_USER")
    if not username:
        print(
            "Error: provide a username with --user or the F5_USER environment variable.",
            file=sys.stderr,
        )
        sys.exit(EXIT_ERROR)
    # Password never travels as a CLI argument (visible in process lists).
    password = os.environ.get("F5_PASS")
    if not password:
        password = getpass.getpass(f"Password for {username}@{args.host}: ")
    return username, password


def _build_client(args) -> F5ReadOnlyClient:
    if not args.host:
        print("Error: --host is required for this command.", file=sys.stderr)
        sys.exit(EXIT_ERROR)
    username, password = _resolve_credentials(args)
    if args.insecure:
        print(
            "WARNING: TLS certificate verification is DISABLED "
            "(--insecure). Only use this on a trusted management network.",
            file=sys.stderr,
        )
        try:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except ImportError:
            pass
    return F5ReadOnlyClient(
        args.host,
        username,
        password,
        verify_tls=not args.insecure,
        login_provider=args.login_provider,
        delay=args.delay,
        page_size=args.top,
    )


def _load_resume_data(save_raw_dir: str | None) -> CollectionData | None:
    """Reuse an existing raw cache so only the missing datasets are
    fetched (top up an old cache, resume an aborted run). A fresh or
    empty directory means a full collection."""
    if not save_raw_dir:
        return None
    directory = Path(save_raw_dir)
    if not directory.is_dir() or not any(directory.glob("*.json")):
        return None
    try:
        resume_data = load_from_raw(save_raw_dir)
    except F5ClientError as exc:
        print(f"Warning: could not reuse raw cache in {save_raw_dir}: {exc}", file=sys.stderr)
        return None
    print(
        f"Resuming collection: reusing {len(resume_data.datasets)} existing "
        f"datasets from {save_raw_dir} (use a new --save-raw directory for a "
        "full, time-consistent collection)."
    )
    return resume_data


def _collect(args, save_raw_dir: str | None) -> CollectionData:
    client = _build_client(args)
    resume_data = _load_resume_data(save_raw_dir)
    raw_store = RawStore(save_raw_dir) if save_raw_dir else None
    collector = Collector(client, raw_store=raw_store, resume_data=resume_data)
    data = collector.collect()
    if save_raw_dir:
        print(f"Raw JSON saved to: {save_raw_dir}")
    if data.meta.get("aborted"):
        print(f"Collection aborted early: {data.meta['aborted']}", file=sys.stderr)
        print(f"Partial data ({len(data.datasets)} datasets) was kept.", file=sys.stderr)
    return data


def _default_raw_dir(host: str) -> str:
    stamp = datetime.now().strftime("%Y%m%d-%H%M")
    return f"./f5audit_raw_{host}_{stamp}"


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def cmd_collect(args) -> int:
    save_raw_dir = args.save_raw or _default_raw_dir(args.host or "unknown")
    data = _collect(args, save_raw_dir)
    if data.meta.get("aborted"):
        return EXIT_ERROR
    print(
        f"Collected {len(data.datasets)} datasets. "
        f"Analyze offline with: f5audit analyze --from-raw {save_raw_dir}"
    )
    return EXIT_OK


def cmd_analyze(args) -> int:
    if args.from_raw:
        data = load_from_raw(args.from_raw)
        print(
            f"Loaded raw cache from {args.from_raw} "
            f"(collected at {data.meta.get('collected_at', 'unknown')})."
        )
    else:
        data = _collect(args, args.save_raw)
        if data.meta.get("aborted"):
            return EXIT_ERROR

    parsed = parse_collection(data)
    correlation = correlate(parsed)
    analysis = Analyzer(parsed, correlation, allow_standby=args.allow_standby).run()

    # Prominent standby warning happens before writing anything.
    for warning in analysis.warnings:
        print(f"\nWARNING: {warning}", file=sys.stderr)

    tables = build_tables(parsed, correlation, analysis)
    out = args.out or default_report_name(parsed.system.hostname, args.format)
    if args.format == "csv":
        written = write_csv(tables, out)
        print(f"\nCSV report written: {len(written)} files in {out}/")
    else:
        write_xlsx(tables, out)
        print(f"\nExcel report written: {out}")

    counts = analysis.verdict_counts()
    print(
        "Verdict counts: "
        + ", ".join(f"{verdict}={count}" for verdict, count in sorted(counts.items()))
    )
    return EXIT_WARNINGS if analysis.warnings else EXIT_OK


VALIDATE_PROBES = [
    ("sys/version", "/mgmt/tm/sys/version", None),
    ("auth/partition", "/mgmt/tm/auth/partition", {"$top": 1}),
    ("ltm/pool", "/mgmt/tm/ltm/pool", {"$top": 1}),
    ("ltm/virtual", "/mgmt/tm/ltm/virtual", {"$top": 1}),
    ("ltm/node", "/mgmt/tm/ltm/node", {"$top": 1}),
    ("ltm/rule", "/mgmt/tm/ltm/rule", {"$top": 1}),
    ("ltm/virtual/stats", "/mgmt/tm/ltm/virtual/stats", None),
    ("sys/failover", "/mgmt/tm/sys/failover", None),
    ("net/self", "/mgmt/tm/net/self", {"$top": 1}),
    ("net/arp/stats", "/mgmt/tm/net/arp/stats", None),
]


def _diagnose(endpoint: str, status: object) -> str:
    if status == 200:
        return "OK"
    if status == 401:
        return "Unauthorized: check credentials / REST access for this account"
    if status == 403:
        if endpoint == "ltm/rule":
            return "Forbidden: pool orphan verdicts will be capped at MANUAL REVIEW"
        return "Forbidden: this account cannot read this endpoint"
    if status == 404:
        return "Not found: endpoint missing on this BIG-IP version"
    if status == "timeout":
        return "Timeout: check network/firewall path to the management interface"
    return f"Unexpected response ({status})"


def cmd_validate(args) -> int:
    client = _build_client(args)
    print(f"Validating read access to {args.host}...\n")
    try:
        client.login()
    except F5AuthError as exc:
        print(f"LOGIN FAILED: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except F5ClientError as exc:
        print(f"CONNECTION FAILED: {exc}", file=sys.stderr)
        return EXIT_ERROR
    auth_mode = getattr(client, "_auth_mode", "token")
    print(
        f"Login: OK (auth mode: {auth_mode}"
        + (", old BIG-IP without token auth" if auth_mode == "basic" else "")
        + ")\n"
    )

    print(f"{'Endpoint':<22} {'Status':<8} Diagnosis")
    print("-" * 78)
    failures = 0
    for endpoint, path, params in VALIDATE_PROBES:
        try:
            client.get(path, params=params)
            status: object = 200
        except F5APIError as exc:
            status = exc.status_code
        except F5ClientError:
            status = "timeout"
        if status != 200:
            failures += 1
        print(f"{endpoint:<22} {str(status):<8} {_diagnose(endpoint, status)}")

    if failures:
        print(f"\n{failures} probe(s) failed. Collection may be degraded.")
        return EXIT_WARNINGS
    print("\nAll probes passed. The account is ready for 'f5audit collect'.")
    return EXIT_OK


# ---------------------------------------------------------------------------


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    handlers = {
        "collect": cmd_collect,
        "analyze": cmd_analyze,
        "validate": cmd_validate,
    }
    try:
        return handlers[args.command](args)
    except F5AuthError as exc:
        print(f"Authentication error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except F5ClientError as exc:
        if args.verbose:
            logger.exception("Client error")
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 - no raw tracebacks for end users
        if args.verbose:
            logger.exception("Unexpected error")
        print(
            f"Unexpected error: {exc.__class__.__name__}: {exc}. "
            "Re-run with --verbose for details.",
            file=sys.stderr,
        )
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())

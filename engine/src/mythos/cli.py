"""Mythos engine CLI.

    mythos engage URL [--workdir DIR] [--scope FILE] ...   full pipeline
    mythos recon  URL ...                                  recon only
    mythos scan   URL ...                                  scan only (needs scope)
    mythos fingerprint URL                                 one-shot fingerprint
    mythos tools                                           show available OSS tools
    mythos init-scope URL [--out FILE]                     write a scope.yaml template

All commands print JSON to stdout unless noted, so agents can consume them.
Every command enforces the engagement scope.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, external
from .http_client import HttpClient
from .orchestrator import run_engagement
from .recon.fingerprint import fingerprint
from .scope import Scope, default_scope_yaml


def _client(args) -> HttpClient:
    if getattr(args, "scope", None):
        scope = Scope.load(args.scope)
    else:
        scope = Scope.from_dict({"target": args.url, "in_scope": [_host(args.url)]})
        if getattr(args, "rps", None):
            scope.rules.rate_limit_rps = args.rps
        if getattr(args, "allow_exploit", False):
            scope.rules.allow_exploit = True
    headers = {}
    for h in getattr(args, "header", None) or []:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return HttpClient(scope=scope, proxy=getattr(args, "proxy", None),
                      extra_headers=headers)


def _host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).hostname or url


def cmd_engage(args) -> int:
    client = _client(args)
    workdir = Path(args.workdir) if args.workdir else None
    if workdir:
        workdir.mkdir(parents=True, exist_ok=True)
    log = (lambda *a: print(*a, file=sys.stderr)) if not args.quiet else (lambda *a: None)
    res = run_engagement(client, args.url, workdir=workdir,
                         do_recon=not args.no_recon, do_scan=not args.no_scan,
                         max_pages=args.max_pages, wordlist=args.wordlist,
                         mode=getattr(args, "mode", "standard"), log=log)
    out = res.to_dict()
    if args.workdir:
        print(json.dumps({"workdir": str(workdir), "summary": out["summary"],
                          "findings": len(out["findings"])}, indent=2))
    else:
        print(json.dumps(out, indent=2))
    return 0


def cmd_recon(args) -> int:
    args.no_scan = True
    args.no_recon = False
    return cmd_engage(args)


def cmd_scan(args) -> int:
    args.no_scan = False
    args.no_recon = True
    return cmd_engage(args)


def cmd_fingerprint(args) -> int:
    client = _client(args)
    print(json.dumps(fingerprint(client, args.url).to_dict(), indent=2))
    return 0


def cmd_tools(args) -> int:
    print(json.dumps(external.available_tools(), indent=2))
    return 0


def cmd_init_scope(args) -> int:
    content = default_scope_yaml(args.url)
    if args.out:
        Path(args.out).write_text(content, encoding="utf-8")
        print(f"wrote scope template to {args.out}")
    else:
        print(content)
    return 0


def _add_common(p: argparse.ArgumentParser, with_url: bool = True) -> None:
    if with_url:
        p.add_argument("url")
    p.add_argument("--scope", help="path to scope.yaml (overrides single-host default)")
    p.add_argument("--proxy", help="upstream proxy, e.g. http://127.0.0.1:8080 (Burp)")
    p.add_argument("--header", action="append", help="extra header 'Name: value' (repeatable)")
    p.add_argument("--rps", type=float, help="requests per second ceiling")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="mythos", description="Mythos web red-team engine")
    ap.add_argument("--version", action="version", version=f"mythos-engine {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name, fn in (("engage", cmd_engage), ("recon", cmd_recon), ("scan", cmd_scan)):
        p = sub.add_parser(name)
        _add_common(p)
        p.add_argument("--workdir", help="engagement dir to write artifacts into")
        p.add_argument("--max-pages", type=int, default=150, dest="max_pages")
        p.add_argument("--mode", choices=["quick", "standard", "deep"],
                       default="standard", help="scan depth (deep adds time-based oracles)")
        p.add_argument("--wordlist", help="content-discovery wordlist for ffuf")
        p.add_argument("--allow-exploit", action="store_true", dest="allow_exploit")
        p.add_argument("--no-recon", action="store_true")
        p.add_argument("--no-scan", action="store_true")
        p.add_argument("--quiet", action="store_true")
        p.set_defaults(func=fn)

    p = sub.add_parser("fingerprint")
    _add_common(p)
    p.set_defaults(func=cmd_fingerprint)

    p = sub.add_parser("tools")
    p.set_defaults(func=cmd_tools)

    p = sub.add_parser("init-scope")
    p.add_argument("url")
    p.add_argument("--out")
    p.set_defaults(func=cmd_init_scope)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

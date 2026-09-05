#!/usr/bin/env python
"""run.py — CLI for the R Package Validation Gateway.

Usage:
  python run.py --pkg abind [--version 1.4-8] [--tier gxp-support]
  python run.py --github https://github.com/owner/repo [--ref v1.0] [--tier exploratory]
  python run.py --tarball path/to/pkg_1.0.tar.gz [--tier gxp-critical]
  python run.py --publish --pkg glue --version 1.7.0 [--binary]
  python run.py --repo-list
  python run.py --repo-export <dir>

Exit code: 0 on GO / GO-WITH-CONDITIONS / repo success, 2 on NO-GO or a
refused publish, 1 on pipeline error.
stdlib only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gateway import pipeline  # noqa: E402
from gateway import repo as repo_mod  # noqa: E402

TIER_CHOICES = ("exploratory", "gxp-support", "gxp-critical")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="R Package Validation Gateway CLI")
    ap.add_argument("--publish", action="store_true",
                    help="publish --pkg/--version into the approved repository "
                         "(requires a passing assessment on record + an "
                         "electronic signature)")
    ap.add_argument("--signer", metavar="USER", action="append",
                    help="with --publish: electronic-signature signer id "
                         "(21 CFR Part 11). Repeatable: publishing a "
                         "gxp-critical assessment requires two DISTINCT "
                         "signers (dual approval). Passwords are read from "
                         "ESIGN_PASSWORD (single signer only) or prompted "
                         "securely per signer")
    ap.add_argument("--binary", action="store_true",
                    help="with --publish: prefer the P3M noble Linux binary")
    ap.add_argument("--repo-list", action="store_true",
                    help="list the approved-package repository manifest")
    ap.add_argument("--repo-export", metavar="DIR",
                    help="export a static snapshot of the repository to DIR "
                         "(for air-gapped image builds)")
    ap.add_argument("--snapshot", default=None,
                    help="P3M snapshot date for --binary "
                         "(default: platform build arg)")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--pkg", help="CRAN package name")
    src.add_argument("--github", help="GitHub repo URL (https://github.com/owner/repo)")
    src.add_argument("--tarball", help="local package source tarball path")
    ap.add_argument("--version", help="package version (CRAN; default: current)")
    ap.add_argument("--ref", help="git ref for --github (default: HEAD)")
    ap.add_argument("--tier", default="exploratory", choices=TIER_CHOICES)
    ap.add_argument("--config", help="decision rules config path")
    ap.add_argument("--data-dir", help="data directory (default: ./data)")
    ap.add_argument("--skip-score", action="store_true",
                    help="skip R scoring (debugging; forces NO-GO)")
    ap.add_argument("--actor", default="cli",
                    help="actor id recorded on the audit record "
                         "(default: cli)")
    args = ap.parse_args(argv)

    data_dir = Path(args.data_dir) if args.data_dir else pipeline.DEFAULT_DATA_DIR

    # ---- repository subcommands (no assessment) ----
    if args.repo_list:
        m = repo_mod.list_repo(data_dir)
        arts = m.get("artifacts", [])
        if not arts:
            print(f"[repo] repository is EMPTY ({m['repo_dir']}) — publish a "
                  "passing assessment first")
            return 0
        print(f"[repo] {len(arts)} artifact(s) in {m['repo_dir']}:")
        for a in arts:
            missing = a.get("dependency_gaps", {}).get("missing", [])
            print(f"[repo]   {a['package']} {a['version']} ({a['flavor']}) "
                  f"sha256 {a['sha256'][:12]}… decision "
                  f"{a.get('assessment_decision')}"
                  + (f" | missing deps: {', '.join(missing)}" if missing else ""))
        return 0

    if args.repo_export:
        try:
            res = repo_mod.export_repo(args.repo_export, data_dir)
        except repo_mod.RepoError as e:
            print(f"[repo] ERROR: {e}", file=sys.stderr)
            return 1
        print(f"[repo] exported {res['exported_files']} files -> {res['dest']}")
        return 0

    if args.publish:
        if not args.pkg or not args.version:
            print("[repo] ERROR: --publish requires --pkg and --version",
                  file=sys.stderr)
            return 1
        if not args.signer:
            print("[repo] ERROR: --publish requires --signer "
                  "(electronic signature, 21 CFR Part 11); gxp-critical "
                  "publishes require --signer twice with two distinct "
                  "signers (dual approval)", file=sys.stderr)
            return 1
        import getpass
        import os
        env_pw = os.environ.get("ESIGN_PASSWORD")
        signers = []
        for s in args.signer:
            if len(args.signer) == 1 and env_pw:
                pw = env_pw
            else:
                pw = getpass.getpass(f"esign password for {s}: ")
            signers.append((s, pw))
        try:
            res = repo_mod.publish(
                args.pkg, args.version, binary=args.binary,
                data_dir=data_dir,
                snapshot=args.snapshot or repo_mod.DEFAULT_P3M_SNAPSHOT,
                signers=signers)
        except repo_mod.RepoError as e:
            print(f"[repo] PUBLISH REFUSED: {e}", file=sys.stderr)
            return 2
        print(f"[repo] published {res['package']} {res['version']} "
              f"({res['flavor']}) sha256 {res['sha256'][:16]}…")
        if res.get("binary_fallback"):
            print(f"[repo] note: {res['binary_fallback']}")
        gaps = res["dependency_gaps"]
        print(f"[repo] deps covered: {len(gaps['covered'])}; missing: "
              f"{len(gaps['missing'])}")
        for dname in gaps["missing"]:
            print(f"[repo]   MISSING dep {dname} — needs its own "
                  "assessment + publish (chain gating)")
        sig_txt = "; ".join(f"{s['signer_id']} ({s['record_hash'][:16]}…)"
                            for s in res["esign_signatures"])
        print(f"[repo] audit record {res['audit_record_hash'][:16]}…; "
              f"signature(s): {sig_txt}; "
              f"index stanzas: {res['index_stanzas']}")
        return 0

    if not (args.pkg or args.github or args.tarball):
        ap.error("one of --pkg / --github / --tarball is required for an "
                 "assessment (or use --publish / --repo-list / --repo-export)")

    spec = {}
    if args.pkg:
        spec = {"package": args.pkg, "version": args.version}
    elif args.github:
        spec = {"github_url": args.github, "ref": args.ref}
    else:
        spec = {"upload_path": args.tarball}
    spec = {k: v for k, v in spec.items() if v is not None}

    try:
        a = pipeline.run_assessment(
            spec, args.tier, data_dir=data_dir, config_path=args.config,
            skip_score=args.skip_score, actor=args.actor)
    except Exception as e:  # noqa: BLE001
        print(f"[run] ERROR: {type(e).__name__}: {e}", file=sys.stderr)
        return 1

    d = a["decision"]
    print(f"[run] package      : {a['ingest']['package']} {a['ingest']['version']}"
          f" ({a['ingest']['origin']}, {a['ingest']['collection_mode']})")
    print(f"[run] tarball sha256: {a['ingest']['sha256']}")
    if a.get("score"):
        print(f"[run] scored by    : {a['score']['r_version']}, "
              f"riskmetric {a['score']['riskmetric_version']}")
    if d.get("score_error"):
        print(f"[run] score error  : {d['score_error']}")
    print(f"[run] overall score: {d['overall_score']}")
    print(f"[run] DECISION     : {d['decision']}  (tier={d['tier']}, "
          f"config v{d['config_version']} sha256 {d['config_sha256'][:12]}…)")
    print(f"[run] fired rules  : {', '.join(d['fired_rules']) or '(none)'}")
    for c in d["conditions"]:
        print(f"[run]   condition  : {c}")
    print(f"[run] rules evaluated (id | input | op threshold | fired):")
    for r in d["rules_evaluated"]:
        inp = r.get("input")
        cond = (f"<{r['low_threshold']}/<{r['high_threshold']}"
                if "low_threshold" in r else f"{r.get('op')} {r.get('threshold')}")
        print(f"[run]   {r['id']:<26} | {str(inp):>10} | {cond:<12} | "
              f"{'FIRED' if r.get('fired') else 'no'}")
    print(f"[run] evidence     : {a['evidence_path']} "
          f"({len(a['evidence']['entries'])} entries, "
          f"mode={a['evidence']['collection_mode']})")
    print(f"[run] report html  : {a['report']['html']}")
    if a["report"]["pdf"]:
        print(f"[run] report pdf   : {a['report']['pdf']}")
    else:
        print(f"[run] report pdf   : NOT GENERATED — {a['report']['pdf_note']}")
    print(f"[run] audit record : {a['audit_log']} "
          f"(record_hash {a['audit_record']['record_hash'][:12]}…)")
    return 0 if d["decision"] in ("GO", "GO-WITH-CONDITIONS") else 2


if __name__ == "__main__":
    sys.exit(main())

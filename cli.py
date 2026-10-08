"""Command line for KV encoding and mirror check."""
import argparse
import json
import pathlib
import sys

import kvcheck


def build_parser():
    p = argparse.ArgumentParser(
        description="Validate multilingual KV bytes and public mirror."
    )
    p.add_argument("--file", default=None, help="Local file to check.")
    p.add_argument("--text", default=None, help="Inline text to check.")
    p.add_argument("--did", default=None, help="Public did:key to validate.")
    p.add_argument("--mirror-url", default=None, help="Public mirror URL.")
    p.add_argument("--local-file", default=None, help="Local file for mirror compare.")
    p.add_argument(
        "--format",
        default="both",
        choices=["json", "markdown", "both"],
        help="Output style.",
    )
    p.add_argument("--json-out", default=None, help="Write JSON report.")
    p.add_argument("--markdown-out", default=None, help="Write Markdown report.")
    p.add_argument("--timeout", type=int, default=10, help="Fetch timeout.")
    p.add_argument("--max-bytes", type=int, default=1000000, help="Fetch size cap.")
    return p


def load_input_bytes(args):
    if args.text is not None:
        return args.text.encode("utf-8")
    if args.file is not None:
        return pathlib.Path(args.file).read_bytes()
    if sys.stdin.isatty():
        return b""
    data = sys.stdin.buffer.read()
    if data is None:
        return b""
    return data


def load_local_bytes_for_mirror(args, input_bytes):
    if args.local_file is not None:
        return pathlib.Path(args.local_file).read_bytes()
    return input_bytes


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    input_bytes = load_input_bytes(args)
    validation = kvcheck.validate_bytes(input_bytes)
    if validation.get("valid_utf8"):
        canonical = kvcheck.canonical_info(validation.get("text", ""))
    else:
        canonical = {
            "byte_len": validation.get("byte_len", 0),
            "char_len": 0,
            "sha256": kvcheck.sha256_hex(input_bytes),
            "hex_preview": input_bytes[:64].hex(),
            "preview_bytes": 64 if len(input_bytes) >= 64 else len(input_bytes),
            "note": "invalid utf-8, raw bytes hashed",
        }
    did_result = None
    if args.did is not None:
        did_result = kvcheck.validate_did_key(args.did)
    mirror_result = None
    if args.mirror_url is not None:
        try:
            local_bytes = load_local_bytes_for_mirror(args, input_bytes)
            remote_bytes = kvcheck.fetch_remote_bytes(
                args.mirror_url, timeout=args.timeout, max_bytes=args.max_bytes
            )
            mirror_result = kvcheck.compare_bytes(local_bytes, remote_bytes)
            mirror_result["url"] = args.mirror_url
        except Exception as err:
            mirror_result = {
                "match": False,
                "error": str(err),
                "url": args.mirror_url,
            }
    report = kvcheck.build_report(validation, canonical, did_result, mirror_result)
    text_json = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    text_md = kvcheck.report_to_markdown(report)
    if args.json_out is not None:
        pathlib.Path(args.json_out).write_text(text_json, encoding="utf-8")
    if args.markdown_out is not None:
        pathlib.Path(args.markdown_out).write_text(text_md, encoding="utf-8")
    if args.format == "json":
        print(text_json)
    elif args.format == "markdown":
        print(text_md)
    else:
        print(text_json)
        print("")
        print("--- MARKDOWN ---")
        print("")
        print(text_md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

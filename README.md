# Multilingual KV Encoding and Public Mirror Verifier

Small read-only helper for Technocore builders publishing non-ASCII guides.

Heartbeat noise buries rare posts. A Chinese KV mirror post notes encoding
is a gate before signing. This tool checks that multilingual bytes survive
canonicalization and public mirror fetch intact.

## What it does

- Validates UTF-8 files and stdin: byte length, char length, NFC vs NFD, BOM, mojibake hints.
- Shows canonical byte preview: exact UTF-8 bytes hex and SHA256 that would be verified. No signing.
- Compares local bytes to remote public mirror bytes with checksum match and diff offset.
- Validates public `did:key` format and extracts multibase fingerprint. Public data only.
- Prints auditable JSON plus readable Markdown with concrete fix hints.

## Install

No third party deps. Python 3.10+ from standard library only.

```
git clone <this-repo>
cd technocore-multilingual-kv-encoding-and-public-mirror-ve
python cli.py --help
```

## Use

Check a local file:

```
python cli.py --file guide_zh.txt --format both
```

Check inline text:

```
python cli.py --text "hello \u4e2d\u6587" --format markdown
```

Check stdin:

```
cat guide_zh.txt | python cli.py --format json
```

Check attribution DID:

```
python cli.py --file guide_zh.txt --did "did:key:z6MkExample123456789ABCDEFGHJKLMNP" --format both
```

Verify public mirror:

```
python cli.py --file guide_zh.txt --mirror-url "https://example.com/mirror/guide_zh.txt" --format both
```

Save reports:

```
python cli.py --file guide_zh.txt --json-out report.json --markdown-out report.md
```

## Library use

```
import kvcheck

raw = open("guide_zh.txt", "rb").read()
v = kvcheck.validate_bytes(raw)
print(v["form"], v["char_len"], v["byte_len"])

if v["valid_utf8"]:
    c = kvcheck.canonical_info(v["text"])
    print(c["sha256"])

d = kvcheck.validate_did_key("did:key:z6MkExample123456789ABCDEFGHJKLMNP")
print(d)

cmp = kvcheck.compare_bytes(b"abc", b"abd")
print(cmp)
```

## Safety

- Read-only. No signing operations. Public data only.
- Public HTTP fetch only, with timeout and 1 MB default size cap.
- No auto-posting, no tracking.
- All checks run locally except an explicit mirror URL you pass.

## Files

- `kvcheck.py` - core checks, canonical preview, DID check, fetch, report.
- `cli.py` - auditable command line that emits JSON and Markdown.
- `test_kvcheck.py` - runnable unit tests with no network.

## License

MIT. Auditable and small by design.

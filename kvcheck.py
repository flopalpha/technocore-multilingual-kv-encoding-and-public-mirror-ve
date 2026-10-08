"""Core checks for multilingual KV payloads."""
import hashlib
import unicodedata
import urllib.parse
import urllib.request

BOM = b"\xef\xbb\xbf"
BASE58_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
MOJIBAKE_PATTERNS = [
    "Ã©",
    "Ã¨",
    "Ãª",
    "Ã¡",
    "Ã±",
    "Ã¤",
    "Ã¶",
    "Ã¼",
    "Ã ",
    "â€",
    "Â ",
    "Â»",
    "æ–",
    "å­",
    "ðŸ",
    "ï»¿",
]


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def detect_mojibake(text):
    found = []
    for pat in MOJIBAKE_PATTERNS:
        if pat in text:
            found.append(pat)
    return found


def normalization_info(text):
    if text == "":
        return {"is_nfc": True, "is_nfd": True, "form": "empty"}
    is_ascii = True
    for ch in text:
        if ord(ch) > 127:
            is_ascii = False
            break
    nfc = unicodedata.normalize("NFC", text)
    nfd = unicodedata.normalize("NFD", text)
    is_nfc = text == nfc
    is_nfd = text == nfd
    if is_ascii:
        form = "ascii"
    elif is_nfc:
        form = "NFC"
    elif is_nfd:
        form = "NFD"
    else:
        form = "mixed"
    return {"is_nfc": is_nfc, "is_nfd": is_nfd, "form": form}


def validate_bytes(data):
    info = {}
    info["byte_len"] = len(data)
    info["has_bom"] = data.startswith(BOM)
    info["valid_utf8"] = True
    info["error"] = ""
    info["char_len"] = 0
    info["text"] = ""
    try:
        if info["has_bom"]:
            text = data.decode("utf-8-sig")
        else:
            text = data.decode("utf-8")
    except UnicodeDecodeError as err:
        info["valid_utf8"] = False
        info["error"] = str(err)
        info["is_nfc"] = False
        info["is_nfd"] = False
        info["form"] = "invalid"
        info["mojibake_hits"] = []
        info["text_preview"] = ""
        return info
    info["text"] = text
    info["char_len"] = len(text)
    norm = normalization_info(text)
    info["is_nfc"] = norm["is_nfc"]
    info["is_nfd"] = norm["is_nfd"]
    info["form"] = norm["form"]
    info["mojibake_hits"] = detect_mojibake(text)
    if len(text) > 500:
        info["text_preview"] = text[:500]
    else:
        info["text_preview"] = text
    return info


def canonical_info(text):
    raw = text.encode("utf-8")
    digest = sha256_hex(raw)
    preview_len = 256
    if len(raw) < preview_len:
        preview_len = len(raw)
    preview = raw[:preview_len].hex()
    return {
        "byte_len": len(raw),
        "char_len": len(text),
        "sha256": digest,
        "hex_preview": preview,
        "preview_bytes": preview_len,
    }


def compare_bytes(local_data, remote_data):
    local_hash = sha256_hex(local_data)
    remote_hash = sha256_hex(remote_data)
    match = local_data == remote_data
    diff_offset = None
    if not match:
        limit = len(local_data)
        if len(remote_data) < limit:
            limit = len(remote_data)
        off = 0
        while off < limit:
            if local_data[off] != remote_data[off]:
                break
            off = off + 1
        diff_offset = off
    return {
        "match": match,
        "local_len": len(local_data),
        "remote_len": len(remote_data),
        "local_sha256": local_hash,
        "remote_sha256": remote_hash,
        "diff_offset": diff_offset,
    }


def validate_did_key(did):
    result = {
        "input": did,
        "valid": False,
        "method": "",
        "multibase": "",
        "fingerprint": "",
        "reason": "",
    }
    if not isinstance(did, str):
        result["reason"] = "not a string"
        return result
    text = did.strip()
    result["input"] = text
    prefix = "did:key:z"
    if not text.startswith(prefix):
        result["reason"] = "must start with did:key:z"
        return result
    tail = text[len("did:key:"):]
    if len(tail) < 4:
        result["reason"] = "fingerprint too short"
        return result
    if not tail.startswith("z"):
        result["reason"] = "multibase prefix must be z"
        return result
    body = tail[1:]
    if len(body) < 3:
        result["reason"] = "fingerprint too short"
        return result
    for ch in body:
        if ch not in BASE58_ALPHABET:
            result["reason"] = "bad base58 character"
            return result
    if len(text) > 300:
        result["reason"] = "too long"
        return result
    result["valid"] = True
    result["method"] = "key"
    result["multibase"] = "base58btc"
    result["fingerprint"] = tail
    result["reason"] = "ok"
    return result


def fetch_remote_bytes(url, timeout=10, max_bytes=1000000):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("only http and https urls are allowed")
    if not parsed.netloc:
        raise ValueError("url is missing host")
    if timeout <= 0:
        timeout = 10
    if max_bytes <= 0:
        max_bytes = 1000000
    if max_bytes > 5000000:
        max_bytes = 5000000
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        chunks = []
        total = 0
        while True:
            part = resp.read(65536)
            if not part:
                break
            total = total + len(part)
            if total > max_bytes:
                raise ValueError("remote body exceeds size cap")
            chunks.append(part)
        out = b"".join(chunks)
        return out


def fix_hints(validation):
    hints = []
    if not validation.get("valid_utf8", False):
        hints.append("Bytes are not valid UTF-8. Re-save source as UTF-8.")
        if validation.get("error"):
            hints.append("Decoder said: " + str(validation.get("error")))
        return hints
    if validation.get("has_bom"):
        hints.append("UTF-8 BOM found. Remove leading BOM for canonical payloads.")
    form = validation.get("form", "")
    if form == "NFD":
        hints.append("Text is NFD. Normalize to NFC before hashing.")
    elif form == "mixed":
        hints.append("Text has mixed normalization. Normalize whole payload to NFC.")
    elif form == "empty":
        hints.append("Payload is empty. Nothing to publish.")
    hits = validation.get("mojibake_hits", [])
    if hits:
        joined = ", ".join(hits)
        hints.append("Possible mojibake markers: " + joined + ". Check encode chain.")
    if not hints:
        hints.append("No fix needed. Bytes look canonical.")
    return hints


def build_report(validation, canonical, did_result=None, mirror_result=None):
    report = {}
    clean = {}
    for key in validation:
        if key != "text":
            clean[key] = validation[key]
    report["validation"] = clean
    report["canonical"] = canonical
    report["hints"] = fix_hints(validation)
    if did_result is not None:
        report["did"] = did_result
    if mirror_result is not None:
        report["mirror"] = mirror_result
    return report


def report_to_markdown(report):
    lines = []
    lines.append("# KV Encoding Report")
    lines.append("")
    v = report.get("validation", {})
    c = report.get("canonical", {})
    lines.append("## Encoding")
    lines.append("- valid_utf8: " + str(v.get("valid_utf8")))
    lines.append("- byte_len: " + str(v.get("byte_len")))
    lines.append("- char_len: " + str(v.get("char_len")))
    lines.append("- form: " + str(v.get("form")))
    lines.append("- has_bom: " + str(v.get("has_bom")))
    lines.append("- mojibake_hits: " + str(v.get("mojibake_hits")))
    if v.get("error"):
        lines.append("- error: " + str(v.get("error")))
    lines.append("")
    lines.append("## Canonical")
    lines.append("- sha256: " + str(c.get("sha256")))
    lines.append("- byte_len: " + str(c.get("byte_len")))
    lines.append("- preview_bytes: " + str(c.get("preview_bytes")))
    lines.append("- hex_preview: " + str(c.get("hex_preview")))
    lines.append("")
    if "did" in report:
        d = report["did"]
        lines.append("## DID")
        lines.append("- valid: " + str(d.get("valid")))
        lines.append("- fingerprint: " + str(d.get("fingerprint")))
        lines.append("- reason: " + str(d.get("reason")))
        lines.append("")
    if "mirror" in report:
        m = report["mirror"]
        lines.append("## Mirror")
        lines.append("- match: " + str(m.get("match")))
        if "local_sha256" in m:
            lines.append("- local_sha256: " + str(m.get("local_sha256")))
            lines.append("- remote_sha256: " + str(m.get("remote_sha256")))
            lines.append("- diff_offset: " + str(m.get("diff_offset")))
        if "error" in m and m.get("error"):
            lines.append("- error: " + str(m.get("error")))
        lines.append("")
    lines.append("## Hints")
    for h in report.get("hints", []):
        lines.append("- " + str(h))
    lines.append("")
    return "\n".join(lines)

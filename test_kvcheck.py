"""Tests for kvcheck with no network."""
import hashlib
import pathlib
import tempfile
import unittest
import unicodedata

import kvcheck
import cli


class KvCheckTest(unittest.TestCase):
    def test_chinese_valid(self):
        text = "hello \u4e2d\u6587\u6d4b\u8bd5"
        data = text.encode("utf-8")
        v = kvcheck.validate_bytes(data)
        self.assertTrue(v["valid_utf8"])
        self.assertEqual(v["byte_len"], len(data))
        self.assertEqual(v["char_len"], len(text))
        self.assertEqual(v["form"], "NFC")
        self.assertTrue(v["is_nfc"])

    def test_invalid_utf8(self):
        data = b"\xff\xfe\xfd"
        v = kvcheck.validate_bytes(data)
        self.assertFalse(v["valid_utf8"])
        self.assertEqual(v["form"], "invalid")
        hints = kvcheck.fix_hints(v)
        self.assertTrue(len(hints) >= 1)

    def test_nfd_hint(self):
        base = "\u00e9"
        nfd = unicodedata.normalize("NFD", base)
        self.assertNotEqual(base, nfd)
        v = kvcheck.validate_bytes(nfd.encode("utf-8"))
        self.assertEqual(v["form"], "NFD")
        hints = kvcheck.fix_hints(v)
        joined = " ".join(hints)
        self.assertIn("NFC", joined)

    def test_mojibake_detection(self):
        text = "caf\u00c3\u00a9 broken"
        hits = kvcheck.detect_mojibake(text)
        self.assertIn("\u00c3\u00a9", hits)
        v = kvcheck.validate_bytes(text.encode("utf-8"))
        self.assertTrue(len(v["mojibake_hits"]) >= 1)

    def test_canonical_sha256(self):
        text = "\u4e2d\u6587"
        c = kvcheck.canonical_info(text)
        expect = hashlib.sha256(text.encode("utf-8")).hexdigest()
        self.assertEqual(c["sha256"], expect)
        self.assertEqual(c["byte_len"], len(text.encode("utf-8")))
        self.assertTrue(len(c["hex_preview"]) > 0)

    def test_compare_match(self):
        a = "data \u4e2d\u6587".encode("utf-8")
        r = kvcheck.compare_bytes(a, a)
        self.assertTrue(r["match"])
        self.assertIsNone(r["diff_offset"])
        self.assertEqual(r["local_sha256"], r["remote_sha256"])

    def test_compare_mismatch_offset(self):
        r = kvcheck.compare_bytes(b"abc", b"abd")
        self.assertFalse(r["match"])
        self.assertEqual(r["diff_offset"], 2)
        r2 = kvcheck.compare_bytes(b"abc", b"abcX")
        self.assertEqual(r2["diff_offset"], 3)

    def test_did_valid(self):
        did = "did:key:z6MkExample123456789ABCDEFGHJKLMNP"
        d = kvcheck.validate_did_key(did)
        self.assertTrue(d["valid"])
        self.assertEqual(d["fingerprint"], "z6MkExample123456789ABCDEFGHJKLMNP")
        self.assertEqual(d["multibase"], "base58btc")

    def test_did_invalid(self):
        d = kvcheck.validate_did_key("did:web:example.com")
        self.assertFalse(d["valid"])
        d2 = kvcheck.validate_did_key("did:key:z!!!")
        self.assertFalse(d2["valid"])

    def test_fetch_rejects_bad_scheme(self):
        with self.assertRaises(ValueError):
            kvcheck.fetch_remote_bytes("ftp://example.com/file.txt")
        with self.assertRaises(ValueError):
            kvcheck.fetch_remote_bytes("not-a-url")

    def test_bom_detection(self):
        data = b"\xef\xbb\xbfhello"
        v = kvcheck.validate_bytes(data)
        self.assertTrue(v["valid_utf8"])
        self.assertTrue(v["has_bom"])
        hints = kvcheck.fix_hints(v)
        joined = " ".join(hints)
        self.assertIn("BOM", joined)

    def test_file_roundtrip_tempfile(self):
        text = "temp \u4e2d\u6587 check"
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp) / "guide.txt"
            p.write_bytes(text.encode("utf-8"))
            raw = p.read_bytes()
            v = kvcheck.validate_bytes(raw)
            self.assertTrue(v["valid_utf8"])
            c = kvcheck.canonical_info(v["text"])
            self.assertEqual(c["char_len"], len(text))

    def test_report_markdown(self):
        v = kvcheck.validate_bytes("hi \u4e2d\u6587".encode("utf-8"))
        c = kvcheck.canonical_info(v["text"])
        rep = kvcheck.build_report(v, c)
        md = kvcheck.report_to_markdown(rep)
        self.assertIn("KV Encoding Report", md)
        self.assertIn("sha256", md)

    def test_cli_parser(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--text", "hi", "--format", "json"])
        self.assertEqual(args.text, "hi")
        self.assertEqual(args.format, "json")


if __name__ == "__main__":
    unittest.main()

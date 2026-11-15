"""Offline tests using synthetic responses built from the SPC/SBC/SPL layouts.

Run:  python -m unittest discover -s tests -v
"""
import json
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sastool import inquiry as inq, logpages, modepages, vendor  # noqa: E402
from sastool.fields import Field, parse_hex_bytes  # noqa: E402
from sastool.sense import parse_sense, sense_summary  # noqa: E402
from sastool.transport import SPTD, SPTDWB, normalize_path  # noqa: E402


def param(code, value, ctl=0x03):
    return struct.pack(">HBB", code, ctl, len(value)) + value


def logpage(page, params, sub=None):
    body = b"".join(params)
    b0 = page | (0x40 if sub is not None else 0)
    return bytes([b0, sub or 0]) + struct.pack(">H", len(body)) + body


def text(lines):
    return "\n".join(lines)


class Fields(unittest.TestCase):
    def test_get_set_roundtrip(self):
        buf = bytearray(8)
        f = Field("x", 1, 5, 3)
        f.set(buf, 5)
        self.assertEqual(buf[1], 0b00101000)
        self.assertEqual(f.get(buf), 5)
        g = Field("y", 2, 3, 12)       # crosses a byte boundary
        g.set(buf, 0xABC)
        self.assertEqual(g.get(buf), 0xABC)
        self.assertEqual(buf[2:4], bytes([0x0A, 0xBC]))
        self.assertEqual(f.get(buf), 5)
        with self.assertRaises(ValueError):
            f.set(buf, 8)
        self.assertIsNone(Field("z", 7, 7, 16).get(buf))

    def test_signed_and_hex(self):
        self.assertEqual(Field("t", 0, fmt="signed").get(b"\xfe"), -2)
        self.assertEqual(parse_hex_bytes("12 00 0x60"), b"\x12\x00\x60")
        self.assertEqual(parse_hex_bytes("120060"), b"\x12\x00\x60")


class Sense(unittest.TestCase):
    def test_fixed(self):
        s = bytearray(18)
        s[0], s[2], s[7], s[12], s[13] = 0x70, 0x05, 10, 0x24, 0x00
        s[15], s[17] = 0xC0, 2
        d = parse_sense(s)
        self.assertEqual((d["key"], d["asc"], d["ascq"]), (5, 0x24, 0))
        self.assertIn("Invalid field in CDB", sense_summary(s))

    def test_descriptor(self):
        s = bytes([0x72, 0x03, 0x11, 0x00, 0, 0, 0, 12,
                   0x00, 0x0A, 0x80, 0x00]) + (0x1234).to_bytes(8, "big")
        d = parse_sense(s)
        self.assertEqual(d["key"], 3)
        self.assertEqual(d["information"], 0x1234)


class Logs(unittest.TestCase):
    def test_error_counters(self):
        d = logpage(0x03, [param(0, bytes(4)), param(3, (77).to_bytes(4, "big")),
                           param(5, (10 ** 12).to_bytes(8, "big")), param(6, (2).to_bytes(4, "big"))])
        t = text(logpages.render_log_page(d))
        self.assertIn("Read error counters", t)
        self.assertRegex(t, r"Total errors corrected\s+: 77")
        self.assertRegex(t, r"Total uncorrected errors\s+: 2")
        self.assertIn(str(10 ** 12), t)

    def test_supported(self):
        d = logpage(0x00, [bytes([0x00, 0x00, 0x03, 0x00, 0x18, 0x00, 0x30, 0x00])], sub=0xFF)
        self.assertEqual(logpages.supported_pages(d), [(0, 0), (3, 0), (0x18, 0), (0x30, 0)])

    def test_temperature_and_wear(self):
        t = text(logpages.render_log_page(logpage(0x0D, [param(0, b"\0\x23"), param(1, b"\0\x46")])))
        self.assertIn("Current temperature : 35 C", t)
        self.assertIn("Reference temperature : 70 C", t)
        t = text(logpages.render_log_page(logpage(0x11, [param(1, b"\0\0\0\x07")])))
        self.assertIn("7%", t)

    def test_selftest(self):
        v = bytearray(16)
        v[0] = (2 << 5) | 3
        v[2:4] = (1234).to_bytes(2, "big")
        v[4:12] = b"\xff" * 8
        t = text(logpages.render_log_page(logpage(0x10, [param(1, bytes(v)), param(2, bytes(16))])))
        self.assertIn("background extended", t)
        self.assertIn("POH=1234", t)
        self.assertNotIn("#2 ", t)

    def test_background_scan(self):
        st = struct.pack(">IBBHHH", 600000, 0, 1, 12, 0x8000, 3)
        ev = struct.pack(">IBBB", 500, (2 << 4) | 3, 0x11, 0x00) + bytes(5) + (0xABCDEF).to_bytes(8, "big")
        t = text(logpages.render_log_page(logpage(0x15, [param(0, st), param(1, ev)])))
        self.assertIn("600000 min", t)
        self.assertIn("50.00%", t)
        self.assertIn("0xabcdef", t)
        self.assertIn("MEDIUM ERROR", t)

    def test_sas_phy(self):
        phy = bytearray(48)
        phy[1], phy[3] = 0, 0x30
        phy[4], phy[5], phy[6] = 0x20, 0x0B, 0x08
        phy[8:16] = bytes.fromhex("5000cca012345601")
        phy[32:36] = (9).to_bytes(4, "big")
        phy[44:48] = (1).to_bytes(4, "big")
        ev = bytes([0, 0, 0, 0x01]) + (9).to_bytes(4, "big") + bytes(4)
        desc = bytearray(bytes(phy[:48]) + bytes([0, 0, 12, 1]) + ev)
        desc[3] = len(desc) - 4
        v = bytes([0x06, 0, 1, 1]) + bytes(desc)
        t = text(logpages.render_log_page(logpage(0x18, [param(1, v)])))
        self.assertIn("12 Gbps", t)
        self.assertIn("expander", t)
        self.assertIn("5000cca012345601", t)
        self.assertRegex(t, r"Invalid dword count\s+: 9")
        self.assertIn("Phy event 0x01", t)

    def test_truncated_does_not_crash(self):
        d = logpage(0x03, [param(0, bytes(4)), param(6, bytes(4))])
        for n in range(4, len(d)):
            logpages.render_log_page(d[:n])


class Modes(unittest.TestCase):
    def caching(self):
        pg = bytearray(20)
        pg[0], pg[1], pg[2] = 0x88, 0x12, 0x04   # PS=1, WCE=1
        return bytes(pg)

    def sense10(self, pages):
        bd = struct.pack(">I", 1000) + b"\0" + (512).to_bytes(3, "big")
        body = bytes([0, 0x10, 0, 0, 0, 8]) + bd + b"".join(pages)
        return struct.pack(">H", len(body)) + body

    def test_parse(self):
        sub = bytes([0x5C, 0x01, 0x00, 0x0C]) + bytes([0x01, 0x01]) + (168).to_bytes(2, "big") + bytes(8)
        md = modepages.ModeData(self.sense10([self.caching(), sub]))
        self.assertTrue(md.dpofua)
        self.assertEqual([(c, s) for c, s, _ in md.pages], [(8, 0), (0x1C, 1)])
        self.assertIn("block length=512", md.block_descriptor_text())
        t = text(modepages.render_page(md.find(0x1C, 1)))
        self.assertRegex(t, r"EN_BMS\s+: 1")
        self.assertRegex(t, r"BACKGROUND_MEDIUM_SCAN_INTERVAL_TIME\s+: 168 h")

    def test_edit(self):
        cur = self.caching()
        _, fields = modepages.page_def(8, 0)
        new, changes = modepages.apply_assignments(cur, ["wce=0", "RCD=1", "@13=0x20"], fields)
        self.assertEqual(new[2], 0x01)
        self.assertEqual(new[13], 0x20)
        self.assertEqual(changes[0], ("WCE", 1, 0))
        mask = bytearray(20)
        mask[2] = 0x04                            # only WCE changeable
        self.assertEqual(modepages.unchangeable_bits(cur, new, mask), [2, 13])
        sel = modepages.build_select10(new)
        self.assertEqual(sel[:8], bytes(8))
        self.assertEqual(sel[8], 0x08)            # PS cleared
        with self.assertRaises(ValueError):
            modepages.apply_assignments(cur, ["NOPE=1"], fields)
        with self.assertRaises(ValueError):
            modepages.apply_assignments(cur, ["@1=5"], fields)


class Inquiry(unittest.TestCase):
    def test_std_and_vpd(self):
        d = bytearray(96)
        d[2], d[3], d[4], d[7] = 6, 0x12, 91, 0x02
        d[8:16] = b"HGST    "
        d[16:32] = b"H4STR767CLAR7680"
        d[32:36] = b"C4C2"
        d[58:60] = (0x0C68).to_bytes(2, "big")
        self.assertEqual(inq.inq_strings(d), ("HGST", "H4STR767CLAR7680", "C4C2"))
        self.assertIn("SAS-3", text(inq.render_std_inquiry(d)))
        naa = bytes.fromhex("5000cca0aabbccdd")
        vpd = bytes([0, 0x83, 0, 12, 0x01, 0x03, 0, 8]) + naa
        self.assertIn("5000cca0aabbccdd", text(inq.render_vpd(vpd)))
        b1 = bytearray(64)
        b1[1], b1[3], b1[5], b1[7] = 0xB1, 60, 1, 3
        t = text(inq.render_vpd(bytes(b1)))
        self.assertIn("non-rotating", t)
        self.assertIn('2.5"', t)

    def test_readcap16(self):
        d = struct.pack(">QI", 999, 520) + bytes([0x01, 0x03, 0x80, 0]) + bytes(16)
        t = text(inq.render_readcap16(d))
        self.assertIn("1000 blocks x 520", t)
        self.assertIn("type 1", t)


class Vendor(unittest.TestCase):
    def test_definitions(self):
        doc = {"match": {"vendor": "^ACME"},
               "log_pages": {"0x30": {"name": "Acme wear", "params": {
                   "0x0001": {"name": "NAND writes", "unit": "GB"},
                   "0x0002": {"name": "Detail", "fields": [
                       {"name": "Flag", "byte": 0, "bit": 7, "bits": 1},
                       {"name": "Spare", "byte": 2, "bits": 16, "unit": "%"}]}}}},
               "mode_pages": {"0x20": {"name": "Acme tuning", "fields": [
                   {"name": "TURBO", "byte": 2, "bit": 0, "bits": 1}]}}}
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "acme.json"), "w") as fh:
                json.dump(doc, fh)
            self.assertEqual(vendor.load("OTHER", "x", extra_dirs=[td]).logs, {})
            defs = vendor.load("ACME", "SSD1", extra_dirs=[td])
        d = logpage(0x30, [param(1, (4242).to_bytes(8, "big")), param(2, bytes([0x80, 0, 0, 95]))])
        t = text(logpages.render_log_page(d, defs))
        self.assertIn("Acme wear", t)
        self.assertIn("NAND writes : 4242 GB", t)
        self.assertRegex(t, r"Flag\s+: 1")
        self.assertRegex(t, r"Spare\s+: 95 %")
        pg = bytes([0x20, 2, 0x01, 0])
        self.assertRegex(text(modepages.render_page(pg, defs)), r"TURBO : 1")
        new, _ = modepages.apply_assignments(pg, ["TURBO=0"], modepages.page_def(0x20, 0, defs)[1])
        self.assertEqual(new[2], 0)

    def test_template_is_valid(self):
        path = os.path.join(vendor.BUILTIN_DIR, "_template.json")
        vendor.load(force_files=[path])


class Transport(unittest.TestCase):
    def test_struct_layout(self):
        import ctypes
        if ctypes.sizeof(ctypes.c_void_p) == 8:
            self.assertEqual(ctypes.sizeof(SPTD), 56)
            self.assertEqual(SPTD.DataBuffer.offset, 24)
            self.assertEqual(SPTD.Cdb.offset, 36)
        self.assertGreaterEqual(SPTDWB.Sense.offset, ctypes.sizeof(SPTD))

    def test_opcode_timeouts(self):
        from sastool.scsi import parse_timeouts
        std = bytes([0, 0x0A, 0, 0]) + (5).to_bytes(4, "big") + (30).to_bytes(4, "big")
        self.assertEqual(parse_timeouts(std), (5, 30, False))
        hgst = bytes.fromhex("00000000" "05000000" "1e000000")   # captured from an HGST SAS SSD
        self.assertEqual(parse_timeouts(hgst), (5, 30, True))

    def test_paths(self):
        self.assertEqual(normalize_path("7"), r"\\.\PhysicalDrive7")
        self.assertEqual(normalize_path("pd10"), r"\\.\PhysicalDrive10")
        self.assertEqual(normalize_path(r"\\.\PhysicalDrive3"), r"\\.\PhysicalDrive3")


if __name__ == "__main__":
    unittest.main()

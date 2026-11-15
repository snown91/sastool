"""CDB builders and thin command wrappers (SPC / SBC)."""
import struct

from .transport import DIR_IN, DIR_NONE, DIR_OUT, ScsiError

DESTRUCTIVE_OPCODES = {
    0x04: "FORMAT UNIT", 0x07: "REASSIGN BLOCKS", 0x0A: "WRITE(6)", 0x15: "MODE SELECT(6)",
    0x2A: "WRITE(10)", 0x2E: "WRITE AND VERIFY(10)", 0x3B: "WRITE BUFFER", 0x3F: "WRITE LONG(10)",
    0x41: "WRITE SAME(10)", 0x42: "UNMAP", 0x48: "SANITIZE", 0x4C: "LOG SELECT",
    0x55: "MODE SELECT(10)", 0x5F: "PERSISTENT RESERVE OUT", 0x89: "COMPARE AND WRITE",
    0x8A: "WRITE(16)", 0x8E: "WRITE AND VERIFY(16)", 0x93: "WRITE SAME(16)", 0xAA: "WRITE(12)",
    0xAE: "WRITE AND VERIFY(12)", 0xB5: "SECURITY PROTOCOL OUT",
}

OPCODE_NAMES = {
    0x00: "TEST UNIT READY", 0x01: "REZERO UNIT", 0x03: "REQUEST SENSE", 0x04: "FORMAT UNIT",
    0x07: "REASSIGN BLOCKS", 0x08: "READ(6)", 0x0A: "WRITE(6)", 0x0B: "SEEK(6)", 0x12: "INQUIRY",
    0x15: "MODE SELECT(6)", 0x16: "RESERVE(6)", 0x17: "RELEASE(6)", 0x1A: "MODE SENSE(6)",
    0x1B: "START STOP UNIT", 0x1C: "RECEIVE DIAGNOSTIC RESULTS", 0x1D: "SEND DIAGNOSTIC",
    0x25: "READ CAPACITY(10)", 0x28: "READ(10)", 0x2A: "WRITE(10)", 0x2B: "SEEK(10)",
    0x2E: "WRITE AND VERIFY(10)", 0x2F: "VERIFY(10)", 0x34: "PRE-FETCH(10)",
    0x35: "SYNCHRONIZE CACHE(10)", 0x37: "READ DEFECT DATA(10)", 0x3B: "WRITE BUFFER",
    0x3C: "READ BUFFER", 0x3E: "READ LONG(10)", 0x3F: "WRITE LONG(10)", 0x41: "WRITE SAME(10)",
    0x42: "UNMAP", 0x48: "SANITIZE", 0x4C: "LOG SELECT", 0x4D: "LOG SENSE",
    0x55: "MODE SELECT(10)", 0x56: "RESERVE(10)", 0x57: "RELEASE(10)", 0x5A: "MODE SENSE(10)",
    0x5E: "PERSISTENT RESERVE IN", 0x5F: "PERSISTENT RESERVE OUT", 0x7F: "VARIABLE LENGTH CDB",
    0x85: "ATA PASS-THROUGH(16)", 0x88: "READ(16)", 0x89: "COMPARE AND WRITE", 0x8A: "WRITE(16)",
    0x8E: "WRITE AND VERIFY(16)", 0x8F: "VERIFY(16)", 0x90: "PRE-FETCH(16)",
    0x91: "SYNCHRONIZE CACHE(16)", 0x93: "WRITE SAME(16)", 0x9B: "READ BUFFER(16)",
    0x9E: "SERVICE ACTION IN(16)", 0x9F: "SERVICE ACTION OUT(16)", 0xA0: "REPORT LUNS",
    0xA1: "ATA PASS-THROUGH(12)", 0xA2: "SECURITY PROTOCOL IN", 0xA3: "MAINTENANCE IN",
    0xA4: "MAINTENANCE OUT", 0xA8: "READ(12)", 0xAA: "WRITE(12)", 0xAE: "WRITE AND VERIFY(12)",
    0xAF: "VERIFY(12)", 0xB5: "SECURITY PROTOCOL OUT", 0xB7: "READ DEFECT DATA(12)",
}
SERVICE_ACTION_NAMES = {
    (0x9E, 0x10): "READ CAPACITY(16)", (0x9E, 0x11): "READ LONG(16)", (0x9E, 0x12): "GET LBA STATUS",
    (0x9E, 0x13): "REPORT REFERRALS", (0x9F, 0x11): "WRITE LONG(16)",
    (0xA3, 0x05): "REPORT IDENTIFYING INFORMATION", (0xA3, 0x0A): "REPORT TARGET PORT GROUPS",
    (0xA3, 0x0C): "REPORT SUPPORTED OPERATION CODES",
    (0xA3, 0x0D): "REPORT SUPPORTED TASK MANAGEMENT FUNCTIONS", (0xA3, 0x0F): "REPORT TIMESTAMP",
    (0xA4, 0x06): "SET IDENTIFYING INFORMATION", (0xA4, 0x0A): "SET TARGET PORT GROUPS",
    (0xA4, 0x0F): "SET TIMESTAMP",
}


def opcode_name(op, sa=None):
    if sa is not None and (op, sa) in SERVICE_ACTION_NAMES:
        return SERVICE_ACTION_NAMES[(op, sa)]
    return OPCODE_NAMES.get(op, "vendor specific" if op >= 0xC0 else "unknown")


def parse_timeouts(desc):
    """Command timeouts descriptor -> (nominal_s, recommended_s, quirk).

    The standard is big-endian with a length field of 0x000A. Some firmware (seen on HGST
    SAS SSDs) leaves the length zero and stores the values little-endian; detect that.
    """
    nom, rec = int.from_bytes(desc[4:8], "big"), int.from_bytes(desc[8:12], "big")
    if int.from_bytes(desc[0:2], "big") != 0x0A and (nom >= 0x10000 or rec >= 0x10000):
        return int.from_bytes(desc[4:8], "little"), int.from_bytes(desc[8:12], "little"), True
    return nom, rec, False


# ---- identification -------------------------------------------------------
def inquiry(dev, alloc=255):
    d = dev.cmd_in(struct.pack(">BBBHB", 0x12, 0, 0, alloc, 0), alloc)
    need = d[4] + 5 if len(d) > 4 else 0
    if need > alloc:
        d = dev.cmd_in(struct.pack(">BBBHB", 0x12, 0, 0, need, 0), need)
    return d


def inquiry_vpd(dev, page):
    hdr = dev.cmd_in(struct.pack(">BBBHB", 0x12, 1, page, 4, 0), 4)
    n = 4 + (int.from_bytes(hdr[2:4], "big") if len(hdr) >= 4 else 252)
    n = max(n, 4)
    return dev.cmd_in(struct.pack(">BBBHB", 0x12, 1, page, n, 0), n)


def test_unit_ready(dev):
    return dev.execute(bytes(6))


def request_sense(dev, desc=False, alloc=252):
    return dev.cmd_in(bytes([0x03, 1 if desc else 0, 0, 0, alloc, 0]), alloc)


def read_capacity10(dev):
    d = dev.cmd_in(bytes([0x25] + [0] * 9), 8)
    return int.from_bytes(d[0:4], "big"), int.from_bytes(d[4:8], "big")


def read_capacity16(dev):
    cdb = struct.pack(">BBQIBB", 0x9E, 0x10, 0, 32, 0, 0)
    return dev.cmd_in(cdb, 32)


def report_luns(dev, select=0):
    def cdb(n):
        return struct.pack(">BBBBBBIBB", 0xA0, 0, select, 0, 0, 0, n, 0, 0)
    d = dev.cmd_in(cdb(16), 16)
    n = 8 + int.from_bytes(d[0:4], "big")
    return dev.cmd_in(cdb(n), n) if n > 16 else d


def report_opcodes(dev, alloc=16384):
    cdb = struct.pack(">BBBBBBIBB", 0xA3, 0x0C, 0x80, 0, 0, 0, alloc, 0, 0)  # RCTD=1, all commands
    try:
        return dev.cmd_in(cdb, alloc), True
    except ScsiError:
        cdb = struct.pack(">BBBBBBIBB", 0xA3, 0x0C, 0x00, 0, 0, 0, alloc, 0, 0)
        return dev.cmd_in(cdb, alloc), False


# ---- log pages -------------------------------------------------------------
def log_sense(dev, page, subpage=0, pc=1, param_ptr=0, alloc=None, sp=False):
    def cdb(n):
        return struct.pack(">BBBBBHHB", 0x4D, 1 if sp else 0, (pc << 6) | (page & 0x3F), subpage, 0,
                           param_ptr, n, 0)
    if alloc is None:
        hdr = dev.cmd_in(cdb(4), 4)
        alloc = 4 + int.from_bytes(hdr[2:4], "big") if len(hdr) >= 4 else 4
        if alloc <= 4:
            return hdr
    return dev.cmd_in(cdb(alloc), alloc)


def log_select(dev, page=0, subpage=0, pc=1, pcr=False, sp=False, data=b""):
    cdb = struct.pack(">BBBBBBBHB", 0x4C, (2 if pcr else 0) | (1 if sp else 0),
                      (pc << 6) | (page & 0x3F), subpage, 0, 0, 0, len(data), 0)
    if data:
        return dev.cmd_out(cdb, data)
    return dev.cmd(cdb)


# ---- mode pages ------------------------------------------------------------
def mode_sense10(dev, page, subpage=0, pc=0, dbd=False, alloc=None):
    def cdb(n):
        return struct.pack(">BBBBBBBHB", 0x5A, 0x08 if dbd else 0, (pc << 6) | (page & 0x3F),
                           subpage, 0, 0, 0, n, 0)
    if alloc is None:
        hdr = dev.cmd_in(cdb(8), 8)
        alloc = 2 + int.from_bytes(hdr[0:2], "big") if len(hdr) >= 2 else 8
        if alloc <= 8:
            return hdr
    return dev.cmd_in(cdb(alloc), alloc)


def mode_sense6(dev, page, subpage=0, pc=0, dbd=False, alloc=255):
    cdb = bytes([0x1A, 0x08 if dbd else 0, (pc << 6) | (page & 0x3F), subpage, alloc, 0])
    return dev.cmd_in(cdb, alloc)


def mode_select10(dev, data, sp=False, pf=True):
    cdb = struct.pack(">BBBBBBBHB", 0x55, (0x10 if pf else 0) | (1 if sp else 0), 0, 0, 0, 0, 0,
                      len(data), 0)
    return dev.cmd_out(cdb, data)


def mode_select6(dev, data, sp=False, pf=True):
    cdb = bytes([0x15, (0x10 if pf else 0) | (1 if sp else 0), 0, 0, len(data), 0])
    return dev.cmd_out(cdb, data)


# ---- unit control / diagnostics --------------------------------------------
def start_stop(dev, start=True, immed=False, power_condition=0, timeout=120):
    cdb = bytes([0x1B, 1 if immed else 0, 0, 0, (power_condition << 4) | (1 if start else 0), 0])
    return dev.cmd(cdb, timeout=timeout)


SELF_TEST_CODES = {"short": 1, "extended": 2, "abort": 4, "fg-short": 5, "fg-extended": 6}


def send_diagnostic_selftest(dev, code, timeout=60):
    cdb = bytes([0x1D, (code << 5), 0, 0, 0, 0])
    return dev.cmd(cdb, timeout=timeout)


def read_defect_header(dev, plist, glist, fmt=5):
    cdb = struct.pack(">BBIIBB", 0xB7, (0x10 if plist else 0) | (0x08 if glist else 0) | fmt,
                      0, 8, 0, 0)
    r = dev.execute(cdb, DIR_IN, 8)
    # RECOVERED ERROR / "defect list not found in requested format" still returns a header
    if not r.ok and len(r.data) < 8:
        raise ScsiError(cdb, r.status, r.sense)
    return r.data


def read16(dev, lba, blocks, block_size, timeout=60):
    cdb = struct.pack(">BBQIBB", 0x88, 0, lba, blocks, 0, 0)
    return dev.cmd_in(cdb, blocks * block_size, timeout=timeout)


def sanitize(dev, service_action, immed=True, ause=False, timeout=120):
    cdb = struct.pack(">BBBBBBBHB", 0x48, (0x80 if immed else 0) | (0x20 if ause else 0) |
                      service_action, 0, 0, 0, 0, 0, 0, 0)
    return dev.cmd(cdb, timeout=timeout)


def format_unit(dev, fmtpinfo=0, immed=True, timeout=120):
    # FMTDATA=1 with a short parameter list header so IMMED can be requested.
    cdb = bytes([0x04, (fmtpinfo << 6) | 0x10, 0, 0, 0, 0])
    hdr = bytes([0, 0x02 if immed else 0, 0, 0])
    return dev.cmd_out(cdb, hdr, timeout=timeout)


def set_block_descriptor(dev, block_size):
    """MODE SELECT(10) carrying only a short block descriptor (new logical block length)."""
    hdr = bytearray(8)
    hdr[7] = 8
    bd = struct.pack(">I", 0xFFFFFFFF) + b"\0" + block_size.to_bytes(3, "big")
    return mode_select10(dev, bytes(hdr) + bd, sp=False, pf=True)


def raw(dev, cdb, direction=DIR_NONE, alloc=0, data_out=None, timeout=30):
    return dev.execute(cdb, direction, alloc, data_out, timeout)


__all__ = [n for n in dir() if not n.startswith("_")] + ["DIR_IN", "DIR_OUT", "DIR_NONE"]

"""LOG SENSE page parsing and decoding (SPC / SBC / SPL)."""
from .fields import hexdump, render_fields
from .sense import SENSE_KEYS, asc_text

LOG_PAGE_NAMES = {
    (0x00, 0x00): "Supported log pages", (0x00, 0xFF): "Supported log pages and subpages",
    (0x01, 0): "Buffer over-run/under-run", (0x02, 0): "Write error counters",
    (0x03, 0): "Read error counters", (0x04, 0): "Read reverse error counters",
    (0x05, 0): "Verify error counters", (0x06, 0): "Non-medium error",
    (0x07, 0): "Last n error events", (0x08, 0): "Format status",
    (0x0B, 0): "Last n deferred errors or asynchronous events",
    (0x0C, 0): "Logical block provisioning", (0x0D, 0): "Temperature",
    (0x0D, 1): "Environmental reporting", (0x0D, 2): "Environmental limits",
    (0x0E, 0): "Start-stop cycle counter", (0x0E, 1): "Utilization",
    (0x0F, 0): "Application client", (0x10, 0): "Self-test results",
    (0x11, 0): "Solid state media", (0x14, 0): "Zoned block device statistics",
    (0x15, 0): "Background scan results", (0x15, 1): "Pending defects",
    (0x15, 2): "Background operation", (0x15, 3): "LPS misalignment",
    (0x16, 0): "ATA pass-through results", (0x17, 0): "Non-volatile cache",
    (0x18, 0): "Protocol specific port", (0x19, 0): "General statistics and performance",
    (0x1A, 0): "Power condition transitions", (0x1A, 1): "Command duration limits statistics",
    (0x2F, 0): "Informational exceptions",
}

ERR_COUNTERS = {
    0: "Errors corrected without substantial delay", 1: "Errors corrected with possible delays",
    2: "Total rewrites/rereads/reverifies", 3: "Total errors corrected",
    4: "Total times correction algorithm processed", 5: "Total bytes processed",
    6: "Total uncorrected errors",
}
COUNTER_TABLES = {
    (0x02, 0): ERR_COUNTERS, (0x03, 0): ERR_COUNTERS, (0x04, 0): ERR_COUNTERS, (0x05, 0): ERR_COUNTERS,
    (0x06, 0): {0: "Non-medium error count"},
    (0x08, 0): {1: "Grown defects during certification", 2: "Total blocks reassigned during format",
                3: "Total new blocks reassigned", 4: "Power on minutes since format"},
    (0x0E, 0): {3: "Specified cycle count over device lifetime", 4: "Accumulated start-stop cycles",
                5: "Specified load-unload count over device lifetime",
                6: "Accumulated load-unload cycles"},
    (0x1A, 0): {1: "Accumulated transitions to active", 2: "Accumulated transitions to idle_a",
                3: "Accumulated transitions to idle_b", 4: "Accumulated transitions to idle_c",
                8: "Accumulated transitions to standby_z", 9: "Accumulated transitions to standby_y"},
    (0x15, 1): {0: "Pending defect count"},
}

SELF_TEST_CODE = {0: "default", 1: "background short", 2: "background extended", 4: "abort background",
                  5: "foreground short", 6: "foreground extended"}
SELF_TEST_RESULT = {0: "completed without error", 1: "aborted by SEND DIAGNOSTIC",
                    2: "aborted (other than SEND DIAGNOSTIC)", 3: "unknown error, unable to complete",
                    4: "completed, failed segment unknown", 5: "FAILED - first segment",
                    6: "FAILED - second segment", 7: "FAILED - segment in self-test number",
                    0xF: "IN PROGRESS"}
BMS_STATUS = {0: "no scans active", 1: "background medium scan active", 2: "pre-scan active",
              3: "halted - fatal error", 4: "halted - vendor specific pattern of errors",
              5: "halted - medium formatted without P-list", 6: "halted - vendor specific cause",
              7: "halted - temperature out of range", 8: "suspended until BMS interval timer expires"}
REASSIGN = {1: "reassign pending (will reassign on write)", 2: "reassigned by drive, data valid",
            4: "reassign by drive failed", 5: "recovered via rewrite in place",
            6: "reassigned by application, data valid", 7: "reassigned by application, data invalid",
            8: "reassign by application failed"}
LINK_RATES = {0: "unknown", 1: "disabled", 2: "phy reset problem", 3: "spinup hold", 4: "port selector",
              5: "reset in progress", 6: "unsupported phy attached", 8: "1.5 Gbps", 9: "3 Gbps",
              0xA: "6 Gbps", 0xB: "12 Gbps", 0xC: "22.5 Gbps"}
SAS_DEV_TYPES = {0: "no device attached", 1: "end device", 2: "expander", 3: "fanout expander (legacy)"}
PHY_EVENTS = {0x01: "Invalid dword count", 0x02: "Running disparity error count",
              0x03: "Loss of dword synchronization count", 0x04: "Phy reset problem count",
              0x05: "Elasticity buffer overflow count", 0x06: "Received ERROR count",
              0x20: "Received address frame error count", 0x21: "Transmitted abandon-class OPEN_REJECT",
              0x22: "Received abandon-class OPEN_REJECT", 0x23: "Transmitted retry-class OPEN_REJECT",
              0x24: "Received retry-class OPEN_REJECT", 0x25: "Received AIP (WAITING ON PARTIAL)",
              0x26: "Received AIP (WAITING ON CONNECTION)", 0x27: "Transmitted BREAK count",
              0x28: "Received BREAK count", 0x29: "Break timeout count", 0x2A: "Connection count",
              0x2B: "Peak transmitted pathway blocked count", 0x2C: "Peak transmitted arbitration wait time",
              0x2D: "Peak arbitration time", 0x2E: "Peak connection time",
              0x40: "Transmitted SSP frame count", 0x41: "Received SSP frame count",
              0x42: "Transmitted SSP frame error count", 0x43: "Received SSP frame error count",
              0x44: "Transmitted CREDIT_BLOCKED count", 0x45: "Received CREDIT_BLOCKED count"}


class LogPage:
    def __init__(self, data):
        if len(data) < 4:
            raise ValueError("log page shorter than its 4-byte header")
        self.raw = bytes(data)
        self.page = data[0] & 0x3F
        self.spf = bool(data[0] & 0x40)
        self.ds = bool(data[0] & 0x80)
        self.subpage = data[1] if self.spf else 0
        self.length = int.from_bytes(data[2:4], "big")
        self.truncated = len(data) < 4 + self.length
        self.body = bytes(data[4:4 + self.length])

    @property
    def key(self):
        return (self.page, self.subpage)

    @property
    def name(self):
        if self.key in LOG_PAGE_NAMES:
            return LOG_PAGE_NAMES[self.key]
        return "Vendor specific" if self.page >= 0x30 else "Unknown"

    def params(self):
        """Yield (code, control_byte, value_bytes, offset_in_page)."""
        b, i = self.body, 0
        while i + 4 <= len(b):
            ln = b[i + 3]
            yield int.from_bytes(b[i:i + 2], "big"), b[i + 2], b[i + 4:i + 4 + ln], 4 + i
            i += 4 + ln


def page_name(page, sub=0):
    if sub == 0xFF and page:
        return "(supported subpages of this page)"
    return LOG_PAGE_NAMES.get((page, sub)) or ("Vendor specific" if page >= 0x30 else "")


def supported_pages(data):
    lp = LogPage(data)
    if lp.subpage == 0xFF:
        return [(lp.body[i] & 0x3F, lp.body[i + 1]) for i in range(0, len(lp.body) - 1, 2)]
    return [(b & 0x3F, 0) for b in lp.body]


def _u(v):
    return int.from_bytes(v, "big")


def _counter(v):
    if not v:
        return "(empty)"
    n = _u(v)
    if len(v) <= 8 and n == (1 << (8 * len(v))) - 1 and len(v) >= 2:
        return f"{n} (all FFh - saturated or not available)"
    return str(n)


def _ctl(c):
    flags = [n for bit, n in ((0x80, "DU"), (0x20, "TSD"), (0x10, "ETC")) if c & bit]
    fl = {0: "bounded counter", 1: "ASCII list", 2: "bounded/unbounded counter", 3: "binary list"}[c & 3]
    return fl + (" " + ",".join(flags) if flags else "")


# ---- structured decoders: each returns list of lines for one parameter -------
def _temp(code, v):
    if code in (0, 1) and len(v) >= 2:
        nm = "Current temperature" if code == 0 else "Reference temperature"
        return [f"  {nm} : " + ("not available" if v[1] == 0xFF else f"{v[1]} C")]


def _startstop(code, v):
    if code in (1, 2) and len(v) >= 6:
        nm = "Date of manufacture" if code == 1 else "Accounting date"
        y, w = v[0:4].decode("ascii", "replace"), v[4:6].decode("ascii", "replace")
        return [f"  {nm} : year {y.strip() or '?'}, week {w.strip() or '?'}"]
    nm = COUNTER_TABLES[(0x0E, 0)].get(code)
    if nm:
        return [f"  {nm} : {_counter(v)}"]


def _selftest(code, v):
    if len(v) < 16:
        return None
    res, stc = v[0] & 0xF, v[0] >> 5
    if not any(v):
        return []
    lba = _u(v[4:12])
    line = (f"  #{code:<2} {SELF_TEST_CODE.get(stc, stc):<20} {SELF_TEST_RESULT.get(res, res)}"
            f"  POH={_u(v[2:4])}  test#={v[1]}")
    if lba != 0xFFFFFFFFFFFFFFFF:
        line += f"  first failing LBA={lba:#x}"
    if v[12] & 0xF or v[13]:
        line += f"  [{SENSE_KEYS[v[12] & 0xF]} {v[13]:02x}/{v[14]:02x} {asc_text(v[13], v[14])}]"
    return [line]


def _ssmedia(code, v):
    if code == 1 and len(v) >= 4:
        return [f"  Percentage used endurance indicator : {v[3]}%"]


def _bgscan(code, v):
    if code == 0 and len(v) >= 12:
        pom = _u(v[0:4])
        return [f"  Accumulated power on time      : {pom} min ({pom / 60:.1f} h, {pom / 1440:.1f} days)",
                f"  Background scan status         : {v[5]} ({BMS_STATUS.get(v[5], 'reserved')})",
                f"  Background scans performed     : {_u(v[6:8])}",
                f"  Background scan progress       : {_u(v[8:10]) * 100 / 65536:.2f}%",
                f"  Background medium scans done   : {_u(v[10:12])}"]
    if 1 <= code <= 0x800 and len(v) >= 20:
        rs = v[4] >> 4
        return [f"  Event {code}: at {_u(v[0:4])} power-on min, LBA {_u(v[12:20]):#x}, "
                f"{SENSE_KEYS[v[4] & 0xF]} {v[5]:02x}/{v[6]:02x} ({asc_text(v[5], v[6])}), "
                f"reassign status {rs} ({REASSIGN.get(rs, 'reserved')})"]


def _sasport(code, v):
    if len(v) < 4:
        return None
    out = [f"  Relative target port {code}: protocol {v[0] & 0xF} "
           f"({'SAS' if v[0] & 0xF == 6 else 'other'}), generation {v[2]}, {v[3]} phy(s)"]
    if v[0] & 0xF != 6:
        return out + hexdump(v, "    ")
    i = 4
    for _ in range(v[3]):
        if i + 48 > len(v):
            break
        d = v[i:]
        dlen = d[3] + 4 if d[3] else 48
        out += [f"    Phy {d[1]}:",
                f"      Attached device type       : {SAS_DEV_TYPES.get((d[4] >> 4) & 7, '?')}",
                f"      Negotiated link rate       : {LINK_RATES.get(d[5] & 0xF, hex(d[5] & 0xF))}",
                f"      Reason / attached reason   : {d[5] >> 4:#x} / {d[4] & 0xF:#x}",
                f"      Attached initiator (SSP/STP/SMP) : {(d[6] >> 3) & 1}/{(d[6] >> 2) & 1}/{(d[6] >> 1) & 1}",
                f"      Attached target (SSP/STP/SMP)    : {(d[7] >> 3) & 1}/{(d[7] >> 2) & 1}/{(d[7] >> 1) & 1}",
                f"      SAS address                : {d[8:16].hex()}",
                f"      Attached SAS address       : {d[16:24].hex()}",
                f"      Attached phy identifier    : {d[24]}",
                f"      Invalid dword count        : {_u(d[32:36])}",
                f"      Running disparity errors   : {_u(d[36:40])}",
                f"      Loss of dword sync         : {_u(d[40:44])}",
                f"      Phy reset problems         : {_u(d[44:48])}"]
        if dlen > 52:
            pel, n = d[50], d[51]
            for j in range(n):
                e = d[52 + j * pel: 52 + (j + 1) * pel]
                if len(e) < 12:
                    break
                out.append(f"      Phy event {e[3]:#04x} {PHY_EVENTS.get(e[3], 'unknown'):<40}: "
                           f"{_u(e[4:8])} (peak threshold {_u(e[8:12])})")
        i += dlen
    return out


def _genstats(code, v):
    if code == 1 and len(v) >= 64:
        names = ["Read commands", "Write commands", "Logical blocks received (written)",
                 "Logical blocks transmitted (read)", "Read command processing intervals",
                 "Write command processing intervals", "Weighted read+write commands",
                 "Weighted read+write processing intervals"]
        return [f"  {n:<42}: {_u(v[i * 8:i * 8 + 8])}" for i, n in enumerate(names)]
    if code == 2 and len(v) >= 8:
        return [f"  {'Idle time intervals':<42}: {_u(v[0:8])}"]
    if code == 3 and len(v) >= 8:
        exp, integer = _u(v[0:4]), _u(v[4:8])
        return [f"  {'Time interval':<42}: {integer} x 10^-{exp} s ({integer * 10.0 ** -exp:g} s)"]


def _ie(code, v):
    if code == 0 and len(v) >= 3:
        out = [f"  Informational exception ASC/ASCQ : {v[0]:02x}/{v[1]:02x} "
               + ("(no exception)" if not v[0] and not v[1] else asc_text(v[0], v[1])),
               f"  Most recent temperature reading  : " + ("n/a" if v[2] == 0xFF else f"{v[2]} C")]
        if len(v) > 3:
            out.append(f"  Vendor specific bytes            : {v[3:].hex(' ')}")
        return out


def _lbp(code, v):
    names = {1: "Available LBA mapping resource count", 2: "Used LBA mapping resource count",
             3: "Available provisioning resource percentage", 0x100: "De-duplicated LBA resource count",
             0x101: "Compressed LBA resource count", 0x102: "Total efficiency LBA resource count"}
    if code in names and len(v) >= 4:
        return [f"  {names[code]} : {_u(v[0:4])}" + (f" (scope {v[4] & 3})" if len(v) > 4 else "")]


def _format_status(code, v):
    if code == 0:
        return [f"  Format data out : {v.hex(' ') if any(b != 0xFF for b in v) else '(not available)'}"]
    nm = COUNTER_TABLES[(0x08, 0)].get(code)
    if nm:
        return [f"  {nm} : {_counter(v)}"]


DECODERS = {(0x0D, 0): _temp, (0x0E, 0): _startstop, (0x10, 0): _selftest, (0x11, 0): _ssmedia,
            (0x15, 0): _bgscan, (0x18, 0): _sasport, (0x19, 0): _genstats, (0x2F, 0): _ie,
            (0x0C, 0): _lbp, (0x08, 0): _format_status}


def render_log_page(data, vendor_defs=None, show_hex=False):
    lp = LogPage(data)
    vd = vendor_defs.log_page(lp.page, lp.subpage) if vendor_defs else None
    name = (vd or {}).get("name") or lp.name
    sub = f"/{lp.subpage:#04x}" if lp.spf else ""
    out = [f"Log page {lp.page:#04x}{sub}: {name}  (length {lp.length}"
           + (", TRUNCATED" if lp.truncated else "") + ")"]
    if show_hex:
        return out + hexdump(lp.raw)
    if lp.page == 0 and lp.subpage in (0, 0xFF):
        for p, s in supported_pages(data):
            out.append(f"  {p:#04x}" + (f"/{s:#04x}" if lp.subpage == 0xFF else "") + f"  {page_name(p, s)}")
        return out
    if vd and vd.get("layout") == "flat":
        return out + render_fields(vd["fields"], lp.raw)
    table = COUNTER_TABLES.get(lp.key, {})
    dec = DECODERS.get(lp.key)
    if lp.key == (0x10, 0):
        out.append("  (most recent first; POH = accumulated power-on hours at test time)")
    n = zero = 0
    for code, ctl, val, off in lp.params():
        n += 1
        vparam = (vd or {}).get("params", {}).get(code) if vd else None
        if vparam is None and vd and vd.get("default_param"):
            vparam = vd["default_param"]
        if vparam:
            nm = vparam.get("name", f"Parameter {code:#06x}")
            if vparam.get("fields"):
                out.append(f"  [{code:#06x}] {nm}")
                out += render_fields(vparam["fields"], val, indent="      ")
            elif vparam.get("format") == "ascii":
                out.append(f"  [{code:#06x}] {nm} : '{val.decode('ascii', 'replace').strip()}'")
            elif vparam.get("format") == "hex":
                out.append(f"  [{code:#06x}] {nm} : {val.hex(' ')}")
            else:
                out.append(f"  [{code:#06x}] {nm} : {_counter(val)}"
                           + (f" {vparam['unit']}" if vparam.get("unit") else ""))
            continue
        lines = dec(code, val) if dec else None
        if lines is not None:
            out += lines
            continue
        if code in table:
            out.append(f"  {table[code]:<46}: {_counter(val)}")
        elif len(val) <= 8 and (ctl & 3) != 1 and lp.page < 0x30 and lp.key in COUNTER_TABLES:
            out.append(f"  Parameter {code:#06x}{'':<30}: {_counter(val)}")
        else:
            out.append(f"  Parameter {code:#06x} ({_ctl(ctl)}, {len(val)} bytes)")
            if len(val) <= 8 and val:
                out[-1] += f" = {val.hex(' ')} ({_u(val)})"
            elif not any(val):
                if lp.key == (0x0F, 0):
                    out.pop()
                    zero += 1
                else:
                    out[-1] += " = all zero"
            else:
                out += hexdump(val, "      ")
    if zero:
        out.append(f"  ({zero} of {n} parameters are all zero and not shown)")
    if lp.key == (0x10, 0) and len(out) == 2:
        out.append("  (no self-tests have been logged)")
    if n == 0 and lp.body:
        out.append("  (no parameter structure found - raw page follows)")
        out += hexdump(lp.raw)
    return out

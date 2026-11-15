"""MODE SENSE / MODE SELECT page parsing, field tables and editing."""
from .fields import Field as F, hexdump, parse_int

MRIE = {0: "no reporting", 1: "async event (obsolete)", 2: "unit attention", 3: "conditional recovered error",
        4: "unconditional recovered error", 5: "no sense", 6: "only on request"}

# Field offsets are relative to byte 0 of the mode page (the page code byte).
MODE_PAGES = {
    (0x01, 0): ("Read-write error recovery", [
        F("AWRE", 2, 7, 1), F("ARRE", 2, 6, 1), F("TB", 2, 5, 1), F("RC", 2, 4, 1), F("EER", 2, 3, 1),
        F("PER", 2, 2, 1), F("DTE", 2, 1, 1), F("DCR", 2, 0, 1), F("READ_RETRY_COUNT", 3),
        F("LBPERE", 7, 7, 1), F("WRITE_RETRY_COUNT", 8), F("RECOVERY_TIME_LIMIT", 10, 7, 16, unit="ms")]),
    (0x02, 0): ("Disconnect-reconnect (SAS)", [
        F("BUS_INACTIVITY_TIME_LIMIT", 4, 7, 16, unit="x100us"),
        F("MAXIMUM_CONNECT_TIME_LIMIT", 8, 7, 16, unit="x100us"),
        F("MAXIMUM_BURST_SIZE", 10, 7, 16, unit="x512 bytes"),
        F("FIRST_BURST_SIZE", 14, 7, 16, unit="x512 bytes")]),
    (0x03, 0): ("Format device (obsolete)", []),
    (0x04, 0): ("Rigid disk geometry (obsolete)", []),
    (0x0A, 2): ("Application tag", []),
    (0x1A, 1): ("Power consumption", [F("ACTIVE_LEVEL", 6, 1, 2), F("POWER_CONSUMPTION_IDENTIFIER", 7)]),
    (0x07, 0): ("Verify error recovery", [
        F("EER", 2, 3, 1), F("PER", 2, 2, 1), F("DTE", 2, 1, 1), F("DCR", 2, 0, 1),
        F("VERIFY_RETRY_COUNT", 3), F("VERIFY_RECOVERY_TIME_LIMIT", 10, 7, 16, unit="ms")]),
    (0x08, 0): ("Caching", [
        F("IC", 2, 7, 1), F("ABPF", 2, 6, 1), F("CAP", 2, 5, 1), F("DISC", 2, 4, 1), F("SIZE", 2, 3, 1),
        F("WCE", 2, 2, 1, desc="write cache enable"), F("MF", 2, 1, 1),
        F("RCD", 2, 0, 1, desc="read cache disable"),
        F("DEMAND_READ_RETENTION_PRIORITY", 3, 7, 4), F("WRITE_RETENTION_PRIORITY", 3, 3, 4),
        F("DISABLE_PREFETCH_TRANSFER_LENGTH", 4, 7, 16), F("MINIMUM_PREFETCH", 6, 7, 16),
        F("MAXIMUM_PREFETCH", 8, 7, 16), F("MAXIMUM_PREFETCH_CEILING", 10, 7, 16),
        F("FSW", 12, 7, 1), F("LBCSS", 12, 6, 1), F("DRA", 12, 5, 1), F("SYNC_PROG", 12, 2, 2),
        F("NV_DIS", 12, 0, 1), F("NUMBER_OF_CACHE_SEGMENTS", 13), F("CACHE_SEGMENT_SIZE", 14, 7, 16)]),
    (0x0A, 0): ("Control", [
        F("TST", 2, 7, 3), F("TMF_ONLY", 2, 4, 1), F("DPICZ", 2, 3, 1),
        F("D_SENSE", 2, 2, 1, desc="descriptor format sense"), F("GLTSD", 2, 1, 1), F("RLEC", 2, 0, 1),
        F("QUEUE_ALGORITHM_MODIFIER", 3, 7, 4), F("NUAR", 3, 3, 1), F("QERR", 3, 2, 2),
        F("RAC", 4, 6, 1), F("UA_INTLCK_CTRL", 4, 5, 2), F("SWP", 4, 3, 1, desc="software write protect"),
        F("ATO", 5, 7, 1), F("TAS", 5, 6, 1), F("ATMPE", 5, 5, 1), F("RWWP", 5, 4, 1),
        F("AUTOLOAD_MODE", 5, 2, 3), F("BUSY_TIMEOUT_PERIOD", 8, 7, 16, unit="x100ms"),
        F("EXTENDED_SELF_TEST_COMPLETION_TIME", 10, 7, 16, unit="s")]),
    (0x0A, 1): ("Control extension", [
        F("TCMOS", 4, 2, 1), F("SCSIP", 4, 1, 1), F("IALUAE", 4, 0, 1),
        F("INITIAL_COMMAND_PRIORITY", 5, 3, 4), F("MAXIMUM_SENSE_DATA_LENGTH", 6)]),
    (0x18, 0): ("Protocol-specific logical unit (SAS)", [
        F("TRANSPORT_LAYER_RETRIES", 2, 4, 1), F("PROTOCOL_IDENTIFIER", 2, 3, 4, enum={6: "SAS"})]),
    (0x19, 0): ("Protocol-specific port (SAS)", [
        F("CONTINUE_AWT", 2, 6, 1), F("BROADCAST_ASYNCHRONOUS_EVENT", 2, 5, 1),
        F("READY_LED_MEANING", 2, 4, 1), F("PROTOCOL_IDENTIFIER", 2, 3, 4, enum={6: "SAS"}),
        F("I_T_NEXUS_LOSS_TIME", 4, 7, 16, unit="ms"),
        F("INITIATOR_RESPONSE_TIMEOUT", 6, 7, 16, unit="ms"),
        F("REJECT_TO_OPEN_LIMIT", 8, 7, 16, unit="x10us")]),
    (0x19, 1): ("Phy control and discover (SAS)", []),
    (0x19, 2): ("Shared port control (SAS)", [F("POWER_LOSS_TIMEOUT", 6, 7, 16, unit="ms")]),
    (0x19, 3): ("Enhanced phy control (SAS)", []),
    (0x1A, 0): ("Power condition", [
        F("PM_BG_PRECEDENCE", 2, 7, 2), F("STANDBY_Y", 2, 0, 1), F("IDLE_C", 3, 3, 1),
        F("IDLE_B", 3, 2, 1), F("IDLE_A", 3, 1, 1), F("STANDBY_Z", 3, 0, 1),
        F("IDLE_A_TIMER", 4, 7, 32, unit="x100ms"), F("STANDBY_Z_TIMER", 8, 7, 32, unit="x100ms"),
        F("IDLE_B_TIMER", 12, 7, 32, unit="x100ms"), F("IDLE_C_TIMER", 16, 7, 32, unit="x100ms"),
        F("STANDBY_Y_TIMER", 20, 7, 32, unit="x100ms"),
        F("CCF_IDLE", 39, 7, 2), F("CCF_STANDBY", 39, 5, 2), F("CCF_STOPPED", 39, 3, 2)]),
    (0x1C, 0): ("Informational exceptions control", [
        F("PERF", 2, 7, 1), F("EBF", 2, 5, 1), F("EWASC", 2, 4, 1), F("DEXCPT", 2, 3, 1),
        F("TEST", 2, 2, 1), F("EBACKERR", 2, 1, 1), F("LOGERR", 2, 0, 1), F("MRIE", 3, 3, 4, enum=MRIE),
        F("INTERVAL_TIMER", 4, 7, 32, unit="x100ms"), F("REPORT_COUNT", 8, 7, 32)]),
    (0x1C, 1): ("Background control", [
        F("S_L_FULL", 4, 2, 1), F("LOWIR", 4, 1, 1), F("EN_BMS", 4, 0, 1), F("EN_PS", 5, 0, 1),
        F("BACKGROUND_MEDIUM_SCAN_INTERVAL_TIME", 6, 7, 16, unit="h"),
        F("BACKGROUND_PRE_SCAN_TIME_LIMIT", 8, 7, 16, unit="h"),
        F("MINIMUM_IDLE_TIME_BEFORE_BACKGROUND_SCAN", 10, 7, 16, unit="ms"),
        F("MAXIMUM_TIME_TO_SUSPEND_BACKGROUND_SCAN", 12, 7, 16, unit="ms")]),
    (0x1C, 2): ("Logical block provisioning", []),
}


def page_def(code, sub, vendor_defs=None):
    """Return (name, fields) using vendor definitions first, then the standard table."""
    vd = vendor_defs.mode_page(code, sub) if vendor_defs else None
    if vd:
        return vd.get("name", "Vendor specific"), vd.get("fields", [])
    if (code, sub) in MODE_PAGES:
        return MODE_PAGES[(code, sub)]
    return ("Vendor specific" if code == 0 or code >= 0x20 else "Unknown"), []


class ModeData:
    """Parsed MODE SENSE response (10-byte header by default)."""

    def __init__(self, data, ten=True):
        self.raw = bytes(data)
        if ten:
            if len(data) < 8:
                raise ValueError("MODE SENSE(10) response shorter than its header")
            self.length = int.from_bytes(data[0:2], "big") + 2
            self.medium_type, self.dev_param = data[2], data[3]
            self.longlba = bool(data[4] & 1)
            bdl, hdr = int.from_bytes(data[6:8], "big"), 8
        else:
            if len(data) < 4:
                raise ValueError("MODE SENSE(6) response shorter than its header")
            self.length = data[0] + 1
            self.medium_type, self.dev_param, self.longlba = data[1], data[2], False
            bdl, hdr = data[3], 4
        self.wp = bool(self.dev_param & 0x80)
        self.dpofua = bool(self.dev_param & 0x10)
        self.block_descriptors = bytes(data[hdr:hdr + bdl])
        self.pages = []
        end = min(len(data), self.length)
        i = hdr + bdl
        while i + 2 <= end:
            code = data[i] & 0x3F
            if data[i] & 0x40:
                if i + 4 > end:
                    break
                sub, ln = data[i + 1], 4 + int.from_bytes(data[i + 2:i + 4], "big")
            else:
                sub, ln = 0, 2 + data[i + 1]
            self.pages.append((code, sub, bytes(data[i:i + ln])))
            i += ln

    def find(self, code, sub=0):
        for c, s, b in self.pages:
            if (c, s) == (code, sub):
                return b
        return None

    def block_descriptor_text(self):
        b = self.block_descriptors
        if self.longlba and len(b) >= 16:
            return f"blocks={int.from_bytes(b[0:8], 'big')} block length={int.from_bytes(b[12:16], 'big')}"
        if len(b) >= 8:
            return f"blocks={int.from_bytes(b[0:4], 'big')} block length={int.from_bytes(b[5:8], 'big')}"
        return "none"


def render_page(page, vendor_defs=None, changeable=None, default=None, saved=None, show_hex=False):
    code, spf = page[0] & 0x3F, bool(page[0] & 0x40)
    sub = page[1] if spf else 0
    name, fields = page_def(code, sub, vendor_defs)
    ps = " [saveable]" if page[0] & 0x80 else ""
    out = [f"Mode page {code:#04x}" + (f"/{sub:#04x}" if spf else "") + f": {name}  ({len(page)} bytes){ps}"]
    if show_hex or not fields:
        out += hexdump(page)
        if not show_hex and changeable:
            out.append("  changeable mask:")
            out += hexdump(changeable)
        return out
    w = max(len(f.name) for f in fields)
    extra = changeable is not None or default is not None or saved is not None
    if extra:
        out.append(f"  {'field':<{w}}   {'current':<22} {'chg':<4} {'default':<12} saved")
    for f in fields:
        v = f.get(page)
        line = f"  {f.name:<{w}} : {f.render(v):<22}"
        if extra:
            chg = "-"
            if changeable is not None:
                m = f.mask_bits(changeable)
                chg = "yes" if m == (1 << f.bits) - 1 else ("part" if m else "no")

            def col(img):
                if img is None:
                    return "-"
                x = f.get(img)
                return "-" if x is None or isinstance(x, bytes) else str(x)
            line += f" {chg:<4} {col(default):<12} {col(saved)}"
        out.append(line.rstrip())
    return out


def apply_assignments(page, assignments, fields):
    """Apply ['NAME=value', '@offset=value', ...] to a copy of page. Returns (new_page, changes)."""
    buf = bytearray(page)
    by_name = {f.name.upper(): f for f in fields}
    changes = []
    for a in assignments:
        if "=" not in a:
            raise ValueError(f"expected NAME=value or @offset=value, got '{a}'")
        k, v = a.split("=", 1)
        k = k.strip()
        if k.startswith("@"):
            off, val = parse_int(k[1:]), parse_int(v)
            if not 0 <= val <= 0xFF or off >= len(buf):
                raise ValueError(f"bad byte assignment '{a}' (page is {len(buf)} bytes)")
            if off < (4 if buf[0] & 0x40 else 2):
                raise ValueError("refusing to modify the mode page header bytes")
            changes.append((f"byte {off}", buf[off], val))
            buf[off] = val
        else:
            f = by_name.get(k.upper())
            if not f:
                raise ValueError(f"unknown field '{k}' for this page; known: "
                                 + (", ".join(by_name) or "(none - use @offset=value)"))
            old = f.get(buf)
            f.set(buf, parse_int(v))
            changes.append((f.name, old, f.get(buf)))
    return bytes(buf), changes


def unchangeable_bits(old, new, mask):
    """Offsets where a modified bit is not marked changeable by the drive."""
    bad = []
    for i, (a, b) in enumerate(zip(old, new)):
        m = mask[i] if i < len(mask) else 0
        if (a ^ b) & ~m & 0xFF:
            bad.append(i)
    return bad


def build_select10(page):
    """Parameter list for MODE SELECT(10): zeroed header, no block descriptor, one page."""
    p = bytearray(page)
    p[0] &= 0x7F  # PS is reserved in MODE SELECT
    return bytes(8) + bytes(p)

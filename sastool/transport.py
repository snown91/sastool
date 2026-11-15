"""Windows SCSI pass-through transport (IOCTL_SCSI_PASS_THROUGH_DIRECT) via ctypes."""
import ctypes
import struct
import sys
from ctypes import wintypes

from .sense import STATUS_NAMES, sense_summary

IOCTL_SCSI_PASS_THROUGH_DIRECT = 0x4D014
IOCTL_SCSI_GET_ADDRESS = 0x41018
IOCTL_STORAGE_QUERY_PROPERTY = 0x2D1400

GENERIC_READ, GENERIC_WRITE = 0x80000000, 0x40000000
FILE_SHARE_READ, FILE_SHARE_WRITE = 1, 2
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

DIR_OUT, DIR_IN, DIR_NONE = 0, 1, 2
SENSE_LEN = 252
ALIGN = 4096

BUS_TYPES = {1: "SCSI", 2: "ATAPI", 3: "ATA", 4: "1394", 5: "SSA", 6: "FC", 7: "USB", 8: "RAID",
             9: "iSCSI", 10: "SAS", 11: "SATA", 12: "SD", 13: "MMC", 14: "Virtual",
             15: "FileBackedVirtual", 16: "Spaces", 17: "NVMe", 18: "SCM", 19: "UFS"}


class SPTD(ctypes.Structure):
    _fields_ = [("Length", ctypes.c_ushort), ("ScsiStatus", ctypes.c_ubyte),
                ("PathId", ctypes.c_ubyte), ("TargetId", ctypes.c_ubyte), ("Lun", ctypes.c_ubyte),
                ("CdbLength", ctypes.c_ubyte), ("SenseInfoLength", ctypes.c_ubyte),
                ("DataIn", ctypes.c_ubyte), ("DataTransferLength", ctypes.c_ulong),
                ("TimeOutValue", ctypes.c_ulong), ("DataBuffer", ctypes.c_void_p),
                ("SenseInfoOffset", ctypes.c_ulong), ("Cdb", ctypes.c_ubyte * 16)]


class SPTDWB(ctypes.Structure):
    _fields_ = [("sptd", SPTD), ("Filler", ctypes.c_ulong), ("Sense", ctypes.c_ubyte * SENSE_LEN)]


class TransportError(Exception):
    """The command never reached the drive or the OS rejected it."""


class ScsiError(Exception):
    """The drive returned a non-GOOD status."""

    def __init__(self, cdb, status, sense):
        self.cdb, self.status, self.sense = bytes(cdb), status, bytes(sense)
        st = STATUS_NAMES.get(status, f"status {status:#04x}")
        msg = f"{st} for CDB [{self.cdb.hex(' ')}]"
        if status == 0x02:
            msg += f": {sense_summary(self.sense)}"
        super().__init__(msg)

    @property
    def key_asc(self):
        from .sense import parse_sense
        d = parse_sense(self.sense)
        return (d["key"], d["asc"], d["ascq"]) if d else (None, None, None)


class ScsiResult:
    def __init__(self, cdb, status, data, sense):
        self.cdb, self.status, self.data, self.sense = bytes(cdb), status, data, sense

    @property
    def ok(self):
        return self.status == 0


def _k32():
    if sys.platform != "win32":
        raise TransportError("live drive access requires Windows (offline 'decode' works anywhere)")
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                              wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    k.CreateFileW.restype = wintypes.HANDLE
    k.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                  ctypes.c_void_p]
    k.DeviceIoControl.restype = wintypes.BOOL
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    return k


def normalize_path(spec):
    s = str(spec).strip()
    low = s.lower()
    if low.isdigit():
        return rf"\\.\PhysicalDrive{int(low)}"
    for p in ("pd", "physicaldrive", "disk"):
        if low.startswith(p) and low[len(p):].isdigit():
            return rf"\\.\PhysicalDrive{int(low[len(p):])}"
    if not s.startswith("\\\\"):
        return "\\\\.\\" + s
    return s


def _open(k, path, access):
    h = k.CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None)
    if h is None or h == INVALID_HANDLE_VALUE:
        err = ctypes.get_last_error()
        return None, err
    return h, 0


class Device:
    """An open handle to a physical drive that can execute arbitrary CDBs."""

    def __init__(self, spec, trace=False):
        self.k = _k32()
        self.path = normalize_path(spec)
        self.trace = trace
        self.handle, err = _open(self.k, self.path, GENERIC_READ | GENERIC_WRITE)
        if self.handle is None:
            if err == 5:
                raise TransportError(f"access denied opening {self.path} - SCSI pass-through needs "
                                     "an elevated (Run as administrator) prompt")
            if err == 2:
                raise TransportError(f"{self.path} does not exist (try 'list')")
            raise TransportError(f"cannot open {self.path}: {ctypes.FormatError(err).strip()} ({err})")

    def close(self):
        if self.handle is not None:
            self.k.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def execute(self, cdb, direction=DIR_NONE, alloc=0, data_out=None, timeout=30):
        """Send one CDB.  Returns ScsiResult (never raises on CHECK CONDITION)."""
        cdb = bytes(cdb)
        if not 6 <= len(cdb) <= 16:
            raise TransportError(f"CDB length {len(cdb)} unsupported (6..16 bytes)")
        if direction == DIR_OUT:
            payload = bytes(data_out or b"")
            n = len(payload)
        elif direction == DIR_IN:
            payload, n = None, int(alloc)
        else:
            payload, n = None, 0
        raw = view = None
        if n:
            raw = (ctypes.c_ubyte * (n + ALIGN))()
            off = (-ctypes.addressof(raw)) % ALIGN
            view = (ctypes.c_ubyte * n).from_buffer(raw, off)
            if payload:
                ctypes.memmove(view, payload, n)
        req = SPTDWB()
        s = req.sptd
        s.Length = ctypes.sizeof(SPTD)
        s.CdbLength = len(cdb)
        s.SenseInfoLength = SENSE_LEN
        s.DataIn = direction if n else DIR_NONE
        s.DataTransferLength = n
        s.TimeOutValue = int(timeout)
        s.DataBuffer = ctypes.addressof(view) if n else None
        s.SenseInfoOffset = SPTDWB.Sense.offset
        ctypes.memmove(s.Cdb, cdb, len(cdb))
        ret = wintypes.DWORD(0)
        ok = self.k.DeviceIoControl(self.handle, IOCTL_SCSI_PASS_THROUGH_DIRECT, ctypes.byref(req),
                                    ctypes.sizeof(req), ctypes.byref(req), ctypes.sizeof(req),
                                    ctypes.byref(ret), None)
        if not ok:
            err = ctypes.get_last_error()
            raise TransportError(f"pass-through IOCTL failed for CDB [{cdb.hex(' ')}]: "
                                 f"{ctypes.FormatError(err).strip()} ({err})")
        data = b""
        if direction == DIR_IN and n:
            data = bytes(view[:min(n, s.DataTransferLength)])
        sense = bytes(req.Sense[:s.SenseInfoLength]) if s.ScsiStatus else b""
        if self.trace:
            print(f"  [trace] cdb={cdb.hex(' ')} status={s.ScsiStatus:#04x} "
                  f"xfer={s.DataTransferLength}" + (f" sense={sense_summary(sense)}" if sense else ""),
                  file=sys.stderr)
        return ScsiResult(cdb, s.ScsiStatus, data, sense)

    def cmd(self, cdb, direction=DIR_NONE, alloc=0, data_out=None, timeout=30):
        """Like execute() but raises ScsiError on any non-GOOD status."""
        r = self.execute(cdb, direction, alloc, data_out, timeout)
        if not r.ok:
            raise ScsiError(cdb, r.status, r.sense)
        return r.data

    def cmd_in(self, cdb, alloc, timeout=30):
        return self.cmd(cdb, DIR_IN, alloc, timeout=timeout)

    def cmd_out(self, cdb, data, timeout=30):
        return self.cmd(cdb, DIR_OUT, data_out=data, timeout=timeout)


def _zstr(buf, off):
    if not off or off >= len(buf):
        return ""
    end = buf.find(b"\0", off)
    return buf[off:end if end >= 0 else len(buf)].decode("ascii", "replace").strip()


def query_descriptor(path):
    """Vendor/product/serial/bus type without admin rights. Returns dict or None."""
    k = _k32()
    h, err = _open(k, path, 0)
    if h is None:
        return None
    try:
        q = struct.pack("<III", 0, 0, 0)
        out = ctypes.create_string_buffer(1024)
        ret = wintypes.DWORD(0)
        if not k.DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, q, len(q), out, len(out),
                                 ctypes.byref(ret), None):
            return {"path": path, "vendor": "", "product": "?", "revision": "", "serial": "", "bus": "?"}
        b = out.raw[:ret.value]
        (_, _, _, _, _, _, voff, poff, roff, soff, bus, _) = struct.unpack_from("<IIBBBBIIIIII", b)
        d = {"path": path, "vendor": _zstr(b, voff), "product": _zstr(b, poff),
             "revision": _zstr(b, roff), "serial": _zstr(b, soff),
             "bus": BUS_TYPES.get(bus, str(bus))}
        addr = ctypes.create_string_buffer(8)
        if k.DeviceIoControl(h, IOCTL_SCSI_GET_ADDRESS, None, 0, addr, 8, ctypes.byref(ret), None):
            _, port, pathid, target, lun = struct.unpack("<IBBBB", addr.raw)
            d["address"] = f"{port}:{pathid}:{target}:{lun}"
        return d
    finally:
        k.CloseHandle(h)


def enumerate_drives(limit=128):
    out = []
    misses = 0
    for i in range(limit):
        d = query_descriptor(rf"\\.\PhysicalDrive{i}")
        if d is None:
            misses += 1
            if misses > 16:
                break
            continue
        misses = 0
        d["index"] = i
        out.append(d)
    return out

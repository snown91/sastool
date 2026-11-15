"""Declarative bit-field definitions shared by standard and vendor-unique pages.

A Field addresses bits the way the SCSI standards draw them: `byte` is the byte
offset, `bit` is the most significant bit of the field inside that byte (7..0),
and `bits` is the total width.  Multi-byte fields are big-endian.
"""


def parse_int(v):
    if isinstance(v, int):
        return v
    return int(str(v).strip(), 0)


class Field:
    __slots__ = ("name", "byte", "bit", "bits", "fmt", "enum", "unit", "desc")

    def __init__(self, name, byte, bit=7, bits=8, fmt="dec", enum=None, unit="", desc=""):
        self.name, self.byte, self.bit, self.bits = name, byte, bit, bits
        self.fmt, self.enum, self.unit, self.desc = fmt, enum or {}, unit, desc
        if not 0 <= bit <= 7 or bits < 1:
            raise ValueError(f"bad field geometry for {name}")
        if fmt in ("ascii", "bytes") and (bit != 7 or bits % 8):
            raise ValueError(f"{name}: ascii/bytes fields must be whole bytes")

    @classmethod
    def from_json(cls, d):
        enum = {parse_int(k): v for k, v in (d.get("enum") or {}).items()}
        return cls(d["name"], parse_int(d["byte"]), parse_int(d.get("bit", 7)),
                   parse_int(d.get("bits", 8)), d.get("format", "dec"), enum,
                   d.get("unit", ""), d.get("desc", ""))

    def _span(self, base):
        start = (base + self.byte) * 8 + (7 - self.bit)
        end = start + self.bits
        return start, end, start // 8, (end + 7) // 8

    def get(self, data, base=0):
        """Return int (or bytes for ascii/bytes formats); None if out of range."""
        start, end, first, last = self._span(base)
        if last > len(data):
            return None
        if self.fmt in ("ascii", "bytes"):
            return bytes(data[first:last])
        chunk = int.from_bytes(data[first:last], "big")
        v = (chunk >> (last * 8 - end)) & ((1 << self.bits) - 1)
        if self.fmt == "signed" and v >> (self.bits - 1):
            v -= 1 << self.bits
        return v

    def set(self, buf, value, base=0):
        start, end, first, last = self._span(base)
        if last > len(buf):
            raise ValueError(f"field {self.name} lies beyond the end of the page")
        if self.fmt in ("ascii", "bytes"):
            raise ValueError(f"field {self.name} is a byte string; use @offset=value")
        if value < 0:
            value += 1 << self.bits
        if value >> self.bits:
            raise ValueError(f"value {value:#x} does not fit in {self.bits}-bit field {self.name}")
        shift = last * 8 - end
        chunk = int.from_bytes(buf[first:last], "big")
        mask = ((1 << self.bits) - 1) << shift
        chunk = (chunk & ~mask) | (value << shift)
        buf[first:last] = chunk.to_bytes(last - first, "big")

    def mask_bits(self, mask, base=0):
        """Extract this field's bits from a changeable-mask image."""
        start, end, first, last = self._span(base)
        if last > len(mask):
            return 0
        chunk = int.from_bytes(mask[first:last], "big")
        return (chunk >> (last * 8 - end)) & ((1 << self.bits) - 1)

    def render(self, v):
        if v is None:
            return "(beyond returned data)"
        if isinstance(v, bytes):
            if self.fmt == "ascii":
                return "'" + "".join(chr(b) if 32 <= b < 127 else "." for b in v).strip() + "'"
            return v.hex(" ")
        if self.fmt == "hex":
            s = f"0x{v:0{(self.bits + 3) // 4}x}"
        else:
            s = str(v)
        if v in self.enum:
            s += f" ({self.enum[v]})"
        if self.unit:
            s += f" {self.unit}"
        return s


def decode_fields(fields, data, base=0):
    return [(f, f.get(data, base)) for f in fields]


def render_fields(fields, data, base=0, indent="  ", width=None):
    width = width or max((len(f.name) for f in fields), default=0)
    return [f"{indent}{f.name:<{width}} : {f.render(v)}" for f, v in decode_fields(fields, data, base)]


def hexdump(data, indent="  ", base=0):
    out = []
    for i in range(0, len(data), 16):
        row = data[i:i + 16]
        hx = " ".join(f"{b:02x}" for b in row[:8]) + "  " + " ".join(f"{b:02x}" for b in row[8:])
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        out.append(f"{indent}{base + i:04x}  {hx:<49} {asc}")
    return out


def parse_hex_bytes(s):
    s = s.replace(",", " ").replace("0x", "").replace("0X", "")
    toks = s.split()
    if len(toks) == 1 and len(toks[0]) > 2:
        return bytes.fromhex(toks[0])
    return bytes(int(t, 16) for t in toks)

"""Standard INQUIRY, VPD pages and READ CAPACITY decoding."""
from .fields import Field as F, hexdump, render_fields

PDT = {0: "Direct access block device", 1: "Sequential access", 5: "CD/DVD", 0x0D: "Enclosure services",
       0x0E: "Simplified direct access", 0x14: "Host managed zoned block", 0x1F: "Unknown / no device"}
VERSIONS = {0: "no standard claimed", 3: "SPC", 4: "SPC-2", 5: "SPC-3", 6: "SPC-4", 7: "SPC-5", 8: "SPC-6"}

STD_INQUIRY = [
    F("Peripheral qualifier", 0, 7, 3), F("Peripheral device type", 0, 4, 5, "hex", PDT),
    F("RMB", 1, 7, 1), F("Version", 2, 7, 8, "hex", VERSIONS),
    F("NORMACA", 3, 5, 1), F("HISUP", 3, 4, 1), F("Response data format", 3, 3, 4),
    F("Additional length", 4), F("SCCS", 5, 7, 1), F("ACC", 5, 6, 1),
    F("TPGS", 5, 5, 2, enum={0: "no ALUA", 1: "implicit", 2: "explicit", 3: "implicit+explicit"}),
    F("3PC", 5, 3, 1), F("PROTECT", 5, 0, 1), F("ENCSERV", 6, 6, 1), F("MULTIP", 6, 4, 1),
    F("CMDQUE", 7, 1, 1),
    F("Vendor identification", 8, 7, 64, "ascii"), F("Product identification", 16, 7, 128, "ascii"),
    F("Product revision level", 32, 7, 32, "ascii"), F("Vendor specific (36-55)", 36, 7, 160, "ascii"),
]

VERSION_DESCRIPTORS = {
    0x0040: "SAM-2", 0x0060: "SAM-3", 0x0080: "SAM-4", 0x00A0: "SAM-5", 0x00C0: "SAM-6",
    0x0120: "SPC", 0x0260: "SPC-2", 0x0300: "SPC-3", 0x0460: "SPC-4", 0x05C0: "SPC-5",
    0x0180: "SBC", 0x0320: "SBC-2", 0x04C0: "SBC-3", 0x0600: "SBC-4",
    0x0BE0: "SAS", 0x0C00: "SAS-1.1", 0x0C20: "SAS-2", 0x0C40: "SAS-2.1", 0x0C60: "SAS-3",
    0x0C80: "SAS-4", 0x20A0: "SPL", 0x20C0: "SPL-2", 0x20E0: "SPL-3", 0x2100: "SPL-4",
    0x2120: "SPL-5", 0x1EA0: "SAT", 0x1EC0: "SAT-2", 0x1EE0: "SAT-3",
}


def inq_strings(d):
    def s(a, b):
        return bytes(d[a:b]).decode("ascii", "replace").strip()
    return s(8, 16), s(16, 32), s(32, 36)


def render_std_inquiry(d):
    out = render_fields(STD_INQUIRY, d)
    vds = []
    for i in range(58, min(74, len(d) - 1), 2):
        v = int.from_bytes(d[i:i + 2], "big")
        if v:
            name = VERSION_DESCRIPTORS.get(v & 0xFFE0, "?")
            vds.append(f"{v:#06x} ({name})")
    if vds:
        out.append("  Version descriptors     : " + ", ".join(vds))
    return out


VPD_NAMES = {
    0x00: "Supported VPD pages", 0x80: "Unit serial number", 0x83: "Device identification",
    0x84: "Software interface identification", 0x85: "Management network addresses",
    0x86: "Extended INQUIRY data", 0x87: "Mode page policy", 0x88: "SCSI ports",
    0x89: "ATA information", 0x8A: "Power condition", 0x8B: "Device constituents",
    0x8D: "Power consumption", 0x8F: "Third-party copy", 0x90: "Protocol-specific logical unit information",
    0x91: "Protocol-specific port information", 0x92: "SCSI feature sets",
    0xB0: "Block limits", 0xB1: "Block device characteristics", 0xB2: "Logical block provisioning",
    0xB3: "Referrals", 0xB4: "Supported block lengths and protection types",
    0xB5: "Block device characteristics extension", 0xB6: "Zoned block device characteristics",
    0xB7: "Block limits extension", 0xB8: "Format presets", 0xB9: "Concurrent positioning ranges",
}

FORM_FACTORS = {0: "not reported", 1: '5.25"', 2: '3.5"', 3: '2.5"', 4: '1.8"', 5: '<1.8"'}

VPD_FIELDS = {
    0x86: [F("ACTIVATE MICROCODE", 4, 7, 2), F("SPT (protection types)", 4, 5, 3),
           F("GRD_CHK", 4, 2, 1), F("APP_CHK", 4, 1, 1), F("REF_CHK", 4, 0, 1),
           F("UASK_SUP", 5, 5, 1), F("GROUP_SUP", 5, 4, 1), F("PRIOR_SUP", 5, 3, 1),
           F("HEADSUP", 5, 2, 1), F("ORDSUP", 5, 1, 1), F("SIMPSUP", 5, 0, 1),
           F("WU_SUP", 6, 3, 1), F("CRD_SUP", 6, 2, 1), F("NV_SUP", 6, 1, 1), F("V_SUP", 6, 0, 1),
           F("P_I_I_SUP", 7, 4, 1), F("LUICLR", 7, 0, 1), F("R_SUP", 8, 4, 1), F("CBCS", 8, 0, 1),
           F("Multi I_T nexus microcode download", 9, 3, 4),
           F("Extended self-test completion", 10, 7, 16, unit="min"),
           F("POA_SUP", 12, 7, 1), F("HRA_SUP", 12, 6, 1), F("VSA_SUP", 12, 5, 1),
           F("Maximum supported sense data length", 13)],
    0x8A: [F("STANDBY_Y", 4, 1, 1), F("STANDBY_Z", 4, 0, 1), F("IDLE_C", 5, 2, 1),
           F("IDLE_B", 5, 1, 1), F("IDLE_A", 5, 0, 1),
           F("Stopped condition recovery time", 6, 7, 16, unit="ms"),
           F("Standby_z recovery time", 8, 7, 16, unit="ms"),
           F("Standby_y recovery time", 10, 7, 16, unit="ms"),
           F("Idle_a recovery time", 12, 7, 16, unit="ms"),
           F("Idle_b recovery time", 14, 7, 16, unit="ms"),
           F("Idle_c recovery time", 16, 7, 16, unit="ms")],
    0xB0: [F("WSNZ", 4, 0, 1), F("Maximum compare and write length", 5, unit="blocks"),
           F("Optimal transfer length granularity", 6, 7, 16, unit="blocks"),
           F("Maximum transfer length", 8, 7, 32, unit="blocks"),
           F("Optimal transfer length", 12, 7, 32, unit="blocks"),
           F("Maximum prefetch length", 16, 7, 32, unit="blocks"),
           F("Maximum unmap LBA count", 20, 7, 32), F("Maximum unmap block descriptor count", 24, 7, 32),
           F("Optimal unmap granularity", 28, 7, 32), F("UGAVALID", 32, 7, 1),
           F("Unmap granularity alignment", 32, 6, 31),
           F("Maximum write same length", 36, 7, 64, unit="blocks")],
    0xB1: [F("Medium rotation rate", 4, 7, 16, enum={0: "not reported", 1: "non-rotating (SSD)"}),
           F("Product type", 6, 7, 8, "hex"), F("WABEREQ", 7, 7, 2), F("WACEREQ", 7, 5, 2),
           F("Nominal form factor", 7, 3, 4, enum=FORM_FACTORS), F("ZONED", 8, 5, 2),
           F("FUAB", 8, 1, 1), F("VBULS", 8, 0, 1)],
    0xB2: [F("Threshold exponent", 4), F("LBPU (UNMAP)", 5, 7, 1), F("LBPWS (WRITE SAME 16)", 5, 6, 1),
           F("LBPWS10", 5, 5, 1), F("LBPRZ", 5, 4, 3), F("ANC_SUP", 5, 1, 1), F("DP", 5, 0, 1),
           F("Minimum percentage", 6, 7, 5),
           F("Provisioning type", 6, 2, 3, enum={0: "not reported/full", 1: "resource provisioned",
                                                 2: "thin provisioned"}),
           F("Threshold percentage", 7)],
}

CODE_SETS = {1: "binary", 2: "ASCII", 3: "UTF-8"}
ASSOC = {0: "LU", 1: "target port", 2: "target device"}
DESIG = {0: "vendor specific", 1: "T10 vendor ID", 2: "EUI-64", 3: "NAA", 4: "relative target port",
         5: "target port group", 6: "LU group", 7: "MD5 LU id", 8: "SCSI name string", 9: "PCIe routing ID",
         0xA: "UUID"}
PROTOCOLS = {0: "FC", 1: "SPI", 2: "SSA", 3: "1394", 4: "SRP", 5: "iSCSI", 6: "SAS", 7: "ADT",
             8: "ATA", 9: "UAS", 0xA: "SOP", 0xB: "PCIe"}


def parse_designators(d):
    out, i, end = [], 4, min(len(d), 4 + int.from_bytes(d[2:4], "big"))
    while i + 4 <= end:
        ln = d[i + 3]
        body = bytes(d[i + 4:i + 4 + ln])
        out.append({"proto": d[i] >> 4, "code_set": d[i] & 0xF, "piv": bool(d[i + 1] & 0x80),
                    "assoc": (d[i + 1] >> 4) & 3, "type": d[i + 1] & 0xF, "value": body})
        i += 4 + ln
    return out


def designator_text(x):
    v, t = x["value"], x["type"]
    if x["code_set"] in (2, 3) or t == 8:
        return v.decode("utf-8", "replace").strip("\0 ")
    if t == 4 and len(v) >= 4:
        return f"port {int.from_bytes(v[2:4], 'big')}"
    if t in (5, 6) and len(v) >= 4:
        return f"group {int.from_bytes(v[2:4], 'big')}"
    return v.hex()


def render_vpd(d, vendor_defs=None):
    if len(d) < 4:
        return ["  (short VPD response)"] + hexdump(d)
    page = d[1]
    out = []
    vd = vendor_defs.vpd_page(page) if vendor_defs else None
    name = (vd or {}).get("name") or VPD_NAMES.get(page) or ("Vendor specific" if page >= 0xC0 else "Unknown")
    out.append(f"VPD page {page:#04x}: {name}  (length {int.from_bytes(d[2:4], 'big')})")
    body = d[4:4 + int.from_bytes(d[2:4], "big")]
    if vd:
        out += render_fields(vd["fields"], d)
    elif page == 0x00:
        for p in body:
            out.append(f"  {p:#04x}  {VPD_NAMES.get(p, 'vendor specific' if p >= 0xC0 else '')}")
    elif page == 0x80:
        out.append(f"  Serial number : {bytes(body).decode('ascii', 'replace').strip()}")
    elif page == 0x83:
        for x in parse_designators(d):
            proto = f", {PROTOCOLS.get(x['proto'], x['proto'])}" if x["piv"] else ""
            out.append(f"  [{ASSOC.get(x['assoc'], '?')}{proto}] {DESIG.get(x['type'], '?')}: {designator_text(x)}")
    elif page in VPD_FIELDS:
        out += render_fields(VPD_FIELDS[page], d)
    else:
        out += hexdump(d)
    return out


READ_CAP16 = [
    F("Last LBA", 0, 7, 64), F("Logical block length", 8, 7, 32, unit="bytes"),
    F("P_TYPE", 12, 3, 3), F("PROT_EN", 12, 0, 1), F("P_I_EXPONENT", 13, 7, 4),
    F("Logical blocks per physical block exponent", 13, 3, 4),
    F("LBPME (thin provisioning / UNMAP)", 14, 7, 1), F("LBPRZ", 14, 6, 1),
    F("Lowest aligned LBA", 14, 5, 14),
]


def capacity_text(last_lba, blk):
    total = (last_lba + 1) * blk
    return f"{last_lba + 1} blocks x {blk} bytes = {total / 1e9:.2f} GB ({total / 2**30:.2f} GiB)"


def render_readcap16(d):
    out = render_fields(READ_CAP16, d)
    out.append("  Capacity : " + capacity_text(int.from_bytes(d[0:8], "big"), int.from_bytes(d[8:12], "big")))
    if d[12] & 1:
        out.append(f"  Protection : enabled, type {((d[12] >> 1) & 7) + 1}")
    return out

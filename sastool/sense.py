"""Sense data decoding (fixed and descriptor formats)."""

SENSE_KEYS = ["NO SENSE", "RECOVERED ERROR", "NOT READY", "MEDIUM ERROR", "HARDWARE ERROR",
              "ILLEGAL REQUEST", "UNIT ATTENTION", "DATA PROTECT", "BLANK CHECK",
              "VENDOR SPECIFIC", "COPY ABORTED", "ABORTED COMMAND", "RESERVED (0xC)",
              "VOLUME OVERFLOW", "MISCOMPARE", "COMPLETED"]

STATUS_NAMES = {0x00: "GOOD", 0x02: "CHECK CONDITION", 0x04: "CONDITION MET", 0x08: "BUSY",
                0x18: "RESERVATION CONFLICT", 0x28: "TASK SET FULL", 0x30: "ACA ACTIVE",
                0x40: "TASK ABORTED"}

ASC = {
    (0x00, 0x00): "No additional sense information",
    (0x00, 0x1D): "ATA pass through information available",
    (0x01, 0x00): "No index/sector signal",
    (0x02, 0x00): "No seek complete",
    (0x03, 0x00): "Peripheral device write fault",
    (0x04, 0x00): "Logical unit not ready, cause not reportable",
    (0x04, 0x01): "Logical unit is in process of becoming ready",
    (0x04, 0x02): "Logical unit not ready, initializing command required",
    (0x04, 0x03): "Logical unit not ready, manual intervention required",
    (0x04, 0x04): "Logical unit not ready, format in progress",
    (0x04, 0x07): "Logical unit not ready, operation in progress",
    (0x04, 0x09): "Logical unit not ready, self-test in progress",
    (0x04, 0x11): "Logical unit not ready, notify (enable spinup) required",
    (0x04, 0x1B): "Logical unit not ready, sanitize in progress",
    (0x04, 0x1C): "Logical unit not ready, additional power use not yet granted",
    (0x05, 0x00): "Logical unit does not respond to selection",
    (0x08, 0x00): "Logical unit communication failure",
    (0x08, 0x01): "Logical unit communication time-out",
    (0x08, 0x02): "Logical unit communication parity error",
    (0x08, 0x03): "Logical unit communication CRC error",
    (0x0B, 0x00): "Warning",
    (0x0B, 0x01): "Warning - specified temperature exceeded",
    (0x0B, 0x02): "Warning - enclosure degraded",
    (0x0B, 0x03): "Warning - background self-test failed",
    (0x0B, 0x04): "Warning - background pre-scan detected medium error",
    (0x0B, 0x05): "Warning - background medium scan detected medium error",
    (0x0B, 0x06): "Warning - non-volatile cache now volatile",
    (0x0B, 0x07): "Warning - degraded power to non-volatile cache",
    (0x0B, 0x08): "Warning - power loss expected",
    (0x0C, 0x00): "Write error",
    (0x0C, 0x01): "Write error - recovered with auto reallocation",
    (0x0C, 0x02): "Write error - auto reallocation failed",
    (0x0C, 0x03): "Write error - recommend reassignment",
    (0x10, 0x00): "ID CRC or ECC error",
    (0x10, 0x01): "Logical block guard check failed",
    (0x10, 0x02): "Logical block application tag check failed",
    (0x10, 0x03): "Logical block reference tag check failed",
    (0x11, 0x00): "Unrecovered read error",
    (0x11, 0x01): "Read retries exhausted",
    (0x11, 0x02): "Error too long to correct",
    (0x11, 0x04): "Unrecovered read error - auto reallocate failed",
    (0x11, 0x0B): "Unrecovered read error - recommend reassignment",
    (0x11, 0x14): "Read error - LBA marked bad by application client",
    (0x14, 0x00): "Recorded entity not found",
    (0x14, 0x01): "Record not found",
    (0x15, 0x00): "Random positioning error",
    (0x16, 0x00): "Data synchronization mark error",
    (0x17, 0x00): "Recovered data with no error correction applied",
    (0x17, 0x01): "Recovered data with retries",
    (0x18, 0x00): "Recovered data with error correction applied",
    (0x18, 0x02): "Recovered data - data auto-reallocated",
    (0x19, 0x00): "Defect list error",
    (0x1A, 0x00): "Parameter list length error",
    (0x1C, 0x00): "Defect list not found",
    (0x1C, 0x01): "Primary defect list not found",
    (0x1C, 0x02): "Grown defect list not found",
    (0x1D, 0x00): "Miscompare during verify operation",
    (0x1F, 0x00): "Partial defect list transfer",
    (0x20, 0x00): "Invalid command operation code",
    (0x21, 0x00): "Logical block address out of range",
    (0x24, 0x00): "Invalid field in CDB",
    (0x25, 0x00): "Logical unit not supported",
    (0x26, 0x00): "Invalid field in parameter list",
    (0x26, 0x01): "Parameter not supported",
    (0x26, 0x02): "Parameter value invalid",
    (0x27, 0x00): "Write protected",
    (0x28, 0x00): "Not ready to ready change, medium may have changed",
    (0x29, 0x00): "Power on, reset, or bus device reset occurred",
    (0x29, 0x01): "Power on occurred",
    (0x29, 0x02): "SCSI bus reset occurred",
    (0x29, 0x03): "Bus device reset function occurred",
    (0x29, 0x04): "Device internal reset",
    (0x29, 0x07): "I_T nexus loss occurred",
    (0x2A, 0x00): "Parameters changed",
    (0x2A, 0x01): "Mode parameters changed",
    (0x2A, 0x02): "Log parameters changed",
    (0x2A, 0x03): "Reservations preempted",
    (0x2A, 0x09): "Capacity data has changed",
    (0x2C, 0x00): "Command sequence error",
    (0x2F, 0x00): "Commands cleared by another initiator",
    (0x30, 0x00): "Incompatible medium installed",
    (0x31, 0x00): "Medium format corrupted",
    (0x31, 0x01): "Format command failed",
    (0x31, 0x02): "Zoned formatting failed due to spare linking",
    (0x31, 0x03): "Sanitize command failed",
    (0x32, 0x00): "No defect spare location available",
    (0x32, 0x01): "Defect list update failure",
    (0x35, 0x00): "Enclosure services failure",
    (0x37, 0x00): "Rounded parameter",
    (0x39, 0x00): "Saving parameters not supported",
    (0x3A, 0x00): "Medium not present",
    (0x3D, 0x00): "Invalid bits in IDENTIFY message",
    (0x3E, 0x00): "Logical unit has not self-configured yet",
    (0x3E, 0x01): "Logical unit failure",
    (0x3E, 0x02): "Timeout on logical unit",
    (0x3E, 0x03): "Logical unit failed self-test",
    (0x3E, 0x04): "Logical unit unable to update self-test log",
    (0x3F, 0x00): "Target operating conditions have changed",
    (0x3F, 0x01): "Microcode has been changed",
    (0x3F, 0x03): "Inquiry data has changed",
    (0x3F, 0x0E): "Reported LUNs data has changed",
    (0x40, 0x00): "RAM failure",
    (0x41, 0x00): "Data path failure",
    (0x42, 0x00): "Power-on or self-test failure",
    (0x44, 0x00): "Internal target failure",
    (0x45, 0x00): "Select or reselect failure",
    (0x47, 0x00): "SCSI parity error",
    (0x47, 0x01): "Data phase CRC error detected",
    (0x47, 0x03): "Information unit iuCRC error detected",
    (0x48, 0x00): "Initiator detected error message received",
    (0x49, 0x00): "Invalid message error",
    (0x4B, 0x00): "Data phase error",
    (0x4B, 0x01): "Invalid target port transfer tag received",
    (0x4B, 0x02): "Too much write data",
    (0x4B, 0x03): "ACK/NAK timeout",
    (0x4B, 0x04): "NAK received",
    (0x4B, 0x05): "Data offset error",
    (0x4B, 0x06): "Initiator response timeout",
    (0x4C, 0x00): "Logical unit failed self-configuration",
    (0x4E, 0x00): "Overlapped commands attempted",
    (0x55, 0x00): "System resource failure",
    (0x55, 0x01): "System buffer full",
    (0x55, 0x03): "Insufficient resources",
    (0x55, 0x04): "Insufficient registration resources",
    (0x5B, 0x00): "Log exception",
    (0x5B, 0x01): "Threshold condition met",
    (0x5B, 0x02): "Log counter at maximum",
    (0x5B, 0x03): "Log list codes exhausted",
    (0x5C, 0x00): "RPL status change",
    (0x5D, 0x00): "Failure prediction threshold exceeded",
    (0x5D, 0xFF): "Failure prediction threshold exceeded (false)",
    (0x5E, 0x00): "Low power condition on",
    (0x5E, 0x01): "Idle condition activated by timer",
    (0x5E, 0x02): "Standby condition activated by timer",
    (0x5E, 0x03): "Idle condition activated by command",
    (0x5E, 0x04): "Standby condition activated by command",
    (0x65, 0x00): "Voltage fault",
    (0x74, 0x00): "Security error",
    (0x74, 0x71): "Logical unit access not authorized",
}

ASC_RANGES = {
    0x5D: "Failure prediction threshold exceeded (impending failure, ASCQ-specific cause)",
    0x40: "Diagnostic failure on component (ASCQ = component)",
    0x4D: "Tagged overlapped commands (ASCQ = task tag)",
}


def asc_text(asc, ascq):
    t = ASC.get((asc, ascq))
    if t:
        return t
    if asc >= 0x80 or ascq >= 0x80:
        base = ASC.get((asc, 0))
        return "Vendor specific" + (f" (ASC family: {base})" if base and asc < 0x80 else "")
    return ASC_RANGES.get(asc) or (ASC.get((asc, 0), "Unknown") + " (unlisted ASCQ)")


def parse_sense(s):
    """Return a dict with key/asc/ascq and optional info fields, or None."""
    if not s or len(s) < 2:
        return None
    rc = s[0] & 0x7F
    d = {"response_code": rc, "deferred": rc in (0x71, 0x73)}
    if rc in (0x70, 0x71):
        if len(s) < 8:
            return None
        d["format"] = "fixed"
        d["key"] = s[2] & 0x0F
        d["filemark"], d["eom"], d["ili"] = bool(s[2] & 0x80), bool(s[2] & 0x40), bool(s[2] & 0x20)
        if s[0] & 0x80:
            d["information"] = int.from_bytes(s[3:7], "big")
        d["asc"] = s[12] if len(s) > 12 else 0
        d["ascq"] = s[13] if len(s) > 13 else 0
        if len(s) > 11:
            d["command_specific"] = int.from_bytes(s[8:12], "big")
        if len(s) > 14 and s[14]:
            d["fru"] = s[14]
        if len(s) > 17 and s[15] & 0x80:
            d["sks"] = bytes(s[15:18])
    elif rc in (0x72, 0x73):
        if len(s) < 8:
            return None
        d["format"] = "descriptor"
        d["key"], d["asc"], d["ascq"] = s[1] & 0x0F, s[2], s[3]
        end = min(len(s), 8 + s[7])
        i = 8
        while i + 2 <= end:
            t, ln = s[i], s[i + 1]
            body = bytes(s[i:i + 2 + ln])
            if t == 0 and len(body) >= 12:
                d["information"] = int.from_bytes(body[4:12], "big")
            elif t == 1 and len(body) >= 12:
                d["command_specific"] = int.from_bytes(body[4:12], "big")
            elif t == 2 and len(body) >= 7:
                d["sks"] = body[4:7]
            elif t == 3 and len(body) >= 4:
                d["fru"] = body[3]
            else:
                d.setdefault("other_descriptors", []).append(body)
            i += 2 + ln
    else:
        return None
    return d


def sense_summary(s):
    d = parse_sense(s)
    if not d:
        return "no valid sense data"
    return (f"{SENSE_KEYS[d['key']]} [{d['key']:x}/{d['asc']:02x}/{d['ascq']:02x}] "
            f"{asc_text(d['asc'], d['ascq'])}")


def render_sense(s, indent="  "):
    d = parse_sense(s)
    if not d:
        return [indent + "no valid sense data"]
    out = [f"{indent}Format            : {d['format']}{' (deferred error)' if d['deferred'] else ''}",
           f"{indent}Sense key         : {d['key']:#x} {SENSE_KEYS[d['key']]}",
           f"{indent}ASC/ASCQ          : {d['asc']:02x}/{d['ascq']:02x} {asc_text(d['asc'], d['ascq'])}"]
    if "information" in d:
        out.append(f"{indent}Information       : {d['information']:#x}")
    if d.get("command_specific"):
        out.append(f"{indent}Command specific  : {d['command_specific']:#x}")
    if "fru" in d:
        out.append(f"{indent}FRU code          : {d['fru']:#04x}")
    if "sks" in d:
        k = d["sks"]
        if d["key"] == 5:
            out.append(f"{indent}Field pointer     : byte {int.from_bytes(k[1:3], 'big')} of "
                       f"{'CDB' if k[0] & 0x40 else 'parameter data'}"
                       + (f", bit {k[0] & 7}" if k[0] & 0x08 else ""))
        elif d["key"] in (1, 3, 4):
            out.append(f"{indent}Actual retry count: {int.from_bytes(k[1:3], 'big')}")
        elif d["key"] in (0, 2):
            out.append(f"{indent}Progress          : {int.from_bytes(k[1:3], 'big') * 100 / 65536:.2f}%")
        else:
            out.append(f"{indent}Sense key specific: {k.hex(' ')}")
    for b in d.get("other_descriptors", []):
        out.append(f"{indent}Descriptor {b[0]:#04x}   : {b.hex(' ')}")
    return out

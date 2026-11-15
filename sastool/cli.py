"""Command-line interface for sastool."""
import argparse
import sys
import time

from . import __version__, inquiry as inq, logpages, modepages, scsi, vendor
from .fields import hexdump, parse_hex_bytes
from .sense import STATUS_NAMES, asc_text, parse_sense, render_sense, sense_summary
from .transport import (DIR_IN, DIR_NONE, DIR_OUT, Device, ScsiError, TransportError,
                        enumerate_drives)


def out(lines):
    if isinstance(lines, str):
        lines = [lines]
    print("\n".join(lines))


def page_arg(s):
    """Page codes are always hexadecimal: '19', '0x19', '19/01', '0x19/0x1'."""
    parts = str(s).lower().replace("h", "").split("/")
    try:
        page = int(parts[0], 16)
        sub = int(parts[1], 16) if len(parts) > 1 else 0
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{s}' is not a hex page code (e.g. 19 or 19/01)")
    return page, sub


def save(path, data):
    if path:
        with open(path, "wb") as fh:
            fh.write(data)
        print(f"  [saved {len(data)} bytes to {path}]")


def open_dev(a):
    return Device(a.device, trace=a.trace)


def get_defs(a, dev=None, std=None):
    v = p = r = ""
    if dev is not None:
        try:
            std = std or scsi.inquiry(dev)
            v, p, r = inq.inq_strings(std)
        except (ScsiError, TransportError):
            pass
    return vendor.load(v, p, r, extra_dirs=a.defs or (), force_files=a.defs_file or ())


def serial_of(dev):
    try:
        d = scsi.inquiry_vpd(dev, 0x80)
        return bytes(d[4:4 + d[3]]).decode("ascii", "replace").strip()
    except ScsiError:
        return ""


def require_confirm(a, dev, what):
    sn = serial_of(dev)
    if not sn:
        raise ValueError("cannot read the drive serial number to confirm against")
    if a.confirm != sn:
        raise ValueError(f"{what} DESTROYS ALL DATA on {dev.path} (serial {sn}). "
                         f"Re-run with --confirm {sn} to proceed.")


def supported_logs(dev):
    try:
        return logpages.supported_pages(scsi.log_sense(dev, 0, 0xFF))
    except ScsiError:
        return logpages.supported_pages(scsi.log_sense(dev, 0, 0))


# ---------------------------------------------------------------- commands
def c_list(a):
    drives = enumerate_drives()
    if not drives:
        out("No physical drives found.")
        return
    out(f"{'#':<4}{'Bus':<8}{'Address':<10}{'Vendor':<10}{'Product':<26}{'Rev':<10}Serial")
    for d in drives:
        mark = "" if d["bus"] in ("SAS", "SCSI", "RAID", "FC") else "  (not SAS)"
        out(f"{d['index']:<4}{d['bus']:<8}{d.get('address', ''):<10}{d['vendor']:<10}"
            f"{d['product']:<26}{d['revision']:<10}{d['serial']}{mark}")
    out("\nUse the # as the device argument, e.g.  sastool info 7")


def c_inquiry(a):
    with open_dev(a) as dev:
        d = scsi.inquiry(dev)
        out("Standard INQUIRY")
        out(hexdump(d) if a.hex else inq.render_std_inquiry(d))
        save(a.save, d)


def c_vpd(a):
    with open_dev(a) as dev:
        defs = get_defs(a, dev)
        if a.page is None:
            sup = scsi.inquiry_vpd(dev, 0)
            pages = list(sup[4:4 + int.from_bytes(sup[2:4], "big")]) if a.all else [0]
        else:
            pages = [a.page[0]]
        for p in pages:
            try:
                d = scsi.inquiry_vpd(dev, p)
            except ScsiError as e:
                out(f"VPD page {p:#04x}: {e}")
                continue
            out([f"VPD page {p:#04x} raw"] + hexdump(d) if a.hex else inq.render_vpd(d, defs))
            out("")
            if len(pages) == 1:
                save(a.save, d)


def c_info(a):
    with open_dev(a) as dev:
        std = scsi.inquiry(dev)
        v, p, r = inq.inq_strings(std)
        rows = [("Device", dev.path), ("Vendor", v), ("Product", p), ("Revision", r),
                ("Serial number", serial_of(dev))]

        def attempt(fn):
            try:
                fn()
            except (ScsiError, ValueError, IndexError):
                pass

        def ids():
            for x in inq.parse_designators(scsi.inquiry_vpd(dev, 0x83)):
                if x["type"] == 3:
                    rows.append((f"NAA ({inq.ASSOC.get(x['assoc'], '?')})", x["value"].hex()))

        def cap():
            try:
                d = scsi.read_capacity16(dev)
                last, blk = int.from_bytes(d[0:8], "big"), int.from_bytes(d[8:12], "big")
                rows.append(("Capacity", inq.capacity_text(last, blk)))
                rows.append(("Physical block", f"{blk << (d[13] & 0xF)} bytes"))
                rows.append(("Protection (T10 PI)", f"type {((d[12] >> 1) & 7) + 1}" if d[12] & 1 else "none"))
                rows.append(("UNMAP (LBPME)", "yes" if d[14] & 0x80 else "no"))
            except ScsiError:
                last, blk = scsi.read_capacity10(dev)
                rows.append(("Capacity", inq.capacity_text(last, blk)))

        def chars():
            d = scsi.inquiry_vpd(dev, 0xB1)
            rr = int.from_bytes(d[4:6], "big")
            rows.append(("Medium", "solid state" if rr == 1 else (f"{rr} rpm" if rr else "not reported")))
            rows.append(("Form factor", inq.FORM_FACTORS.get(d[7] & 0xF, "?")))

        def tur():
            res = scsi.test_unit_ready(dev)
            rows.append(("Unit status", "ready" if res.ok else sense_summary(res.sense)))

        def logs():
            sup = set(supported_logs(dev))

            def params(pg):
                return {c: val for c, _, val, _ in logpages.LogPage(scsi.log_sense(dev, pg)).params()}
            if (0x0D, 0) in sup:
                t = params(0x0D)
                if 0 in t and t[0][1] != 0xFF:
                    ref = f" (reference {t[1][1]} C)" if 1 in t and t[1][1] != 0xFF else ""
                    rows.append(("Temperature", f"{t[0][1]} C{ref}"))
            if (0x11, 0) in sup:
                t = params(0x11)
                if 1 in t:
                    rows.append(("Endurance used", f"{t[1][3]}%"))
            if (0x15, 0) in sup:
                t = params(0x15)
                if 0 in t:
                    m = int.from_bytes(t[0][0:4], "big")
                    rows.append(("Power-on time", f"{m / 60:.0f} h ({m / 1440:.0f} days)"))
                    rows.append(("Background scan events", str(sum(1 for c in t if c))))
            if (0x2F, 0) in sup:
                t = params(0x2F)
                if 0 in t:
                    x = t[0]
                    rows.append(("Informational exception",
                                 "none" if not x[0] and not x[1] else
                                 f"{x[0]:02x}/{x[1]:02x} {asc_text(x[0], x[1])}"))
            for pg, nm in ((0x03, "Read"), (0x02, "Write"), (0x05, "Verify")):
                if (pg, 0) in sup:
                    t = params(pg)
                    if 6 in t:
                        rows.append((f"{nm} uncorrected errors", str(int.from_bytes(t[6], "big"))))
            if (0x06, 0) in sup:
                t = params(0x06)
                if 0 in t:
                    rows.append(("Non-medium errors", str(int.from_bytes(t[0], "big"))))

        def defects():
            d = scsi.read_defect_header(dev, False, True)
            rows.append(("Grown defects", str(int.from_bytes(d[4:8], "big") // 8)))

        for fn in (ids, cap, chars, tur, logs, defects):
            attempt(fn)
        defs = get_defs(a, dev, std)
        if defs.sources:
            rows.append(("Vendor definitions", ", ".join(defs.sources)))
        w = max(len(k) for k, _ in rows)
        out([f"{k:<{w}} : {val}" for k, val in rows])


def c_logs(a):
    with open_dev(a) as dev:
        defs = get_defs(a, dev)
        out("Supported log pages (page/subpage):")
        for p, s in supported_logs(dev):
            vd = defs.log_page(p, s)
            nm = (vd or {}).get("name") or logpages.page_name(p, s)
            out(f"  {p:#04x}/{s:#04x}  {nm}")


def _show_log(dev, defs, a, page, sub, quiet_fail=False):
    try:
        d = scsi.log_sense(dev, page, sub, pc=a.pc, param_ptr=getattr(a, "param_ptr", 0))
    except ScsiError as e:
        if not quiet_fail:
            raise
        out(f"Log page {page:#04x}/{sub:#04x}: {e}\n")
        return None
    out(logpages.render_log_page(d, defs, show_hex=a.hex))
    out("")
    return d


def c_log(a):
    with open_dev(a) as dev:
        defs = get_defs(a, dev)
        if a.page == "all":
            for p, s in supported_logs(dev):
                if p == 0 or s == 0xFF:
                    continue
                _show_log(dev, defs, a, p, s, quiet_fail=True)
            return
        page, sub = page_arg(a.page)
        d = _show_log(dev, defs, a, page, sub)
        save(a.save, d)


def c_log_reset(a):
    with open_dev(a) as dev:
        if a.page:
            page, sub = a.page
            scsi.log_select(dev, page, sub, pc=a.pc, pcr=True, sp=a.sp)
            out(f"Log page {page:#04x}/{sub:#04x} parameters reset (LOG SELECT PCR=1).")
        else:
            if not a.yes:
                raise ValueError("this resets ALL resettable log counters on the drive; add --yes")
            scsi.log_select(dev, 0, 0, pc=a.pc, pcr=True, sp=a.sp)
            out("All resettable log parameters reset (LOG SELECT PCR=1).")


def c_log_write(a):
    data = parse_hex_bytes(a.data) if a.data else open(a.file, "rb").read()
    with open_dev(a) as dev:
        page, sub = a.page
        scsi.log_select(dev, page, sub, pc=a.pc, sp=a.sp, data=data)
        out(f"LOG SELECT wrote {len(data)} bytes of parameter data to page {page:#04x}/{sub:#04x}.")


def _mode_images(dev, page, sub):
    """Return dict pc_name -> page bytes (or None) for current/changeable/default/saved."""
    imgs = {}
    for name, pc in (("current", 0), ("changeable", 1), ("default", 2), ("saved", 3)):
        try:
            imgs[name] = modepages.ModeData(scsi.mode_sense10(dev, page, sub, pc=pc)).find(page, sub)
        except ScsiError as e:
            if name == "current":
                raise
            imgs[name] = None
    return imgs


def c_modes(a):
    with open_dev(a) as dev:
        defs = get_defs(a, dev)
        try:
            d = scsi.mode_sense10(dev, 0x3F, 0xFF, pc=a.pc)
        except ScsiError:
            d = scsi.mode_sense10(dev, 0x3F, 0x00, pc=a.pc)
        md = modepages.ModeData(d)
        out([f"Mode parameter header: write protect={int(md.wp)} DPOFUA={int(md.dpofua)} "
             f"medium type={md.medium_type:#04x}",
             f"Block descriptor: {md.block_descriptor_text()}", ""])
        for code, sub, page in md.pages:
            out(modepages.render_page(page, defs, show_hex=a.hex))
            out("")
        save(a.save, d)


def c_mode(a):
    with open_dev(a) as dev:
        defs = get_defs(a, dev)
        page, sub = a.page
        imgs = _mode_images(dev, page, sub)
        if imgs["current"] is None:
            raise ValueError(f"drive did not return mode page {page:#04x}/{sub:#04x}")
        out(modepages.render_page(imgs["current"], defs, imgs["changeable"], imgs["default"],
                                  imgs["saved"], show_hex=a.hex))
        save(a.save, imgs["current"])


def c_mode_set(a):
    with open_dev(a) as dev:
        defs = get_defs(a, dev)
        page, sub = a.page
        imgs = _mode_images(dev, page, sub)
        cur = imgs["current"]
        if cur is None:
            raise ValueError(f"drive did not return mode page {page:#04x}/{sub:#04x}")
        name, fields = modepages.page_def(page, sub, defs)
        new, changes = modepages.apply_assignments(cur, a.assign, fields)
        out(f"Mode page {page:#04x}/{sub:#04x} ({name}):")
        for nm, old, val in changes:
            out(f"  {nm}: {old} -> {val}")
        if new == cur:
            out("No change needed - the page already holds these values.")
            return
        if imgs["changeable"] is not None:
            bad = modepages.unchangeable_bits(cur, new, imgs["changeable"])
            if bad:
                msg = f"the drive reports bits in byte(s) {bad} as NOT changeable"
                if not a.force:
                    raise ValueError(msg + "; use --force to send anyway")
                out(f"  warning: {msg} (forced)")
        if a.dry_run:
            out(["Dry run - MODE SELECT(10) parameter list that would be sent:"]
                + hexdump(modepages.build_select10(new)))
            return
        try:
            scsi.mode_select10(dev, modepages.build_select10(new), sp=a.save_page)
        except ScsiError as e:
            hint = ""
            if a.save_page and not cur[0] & 0x80:
                hint = " (the page does not report PS=1, so it may not be saveable; retry without --save)"
            raise ValueError(f"MODE SELECT failed: {e}{hint}") from None
        after = modepages.ModeData(scsi.mode_sense10(dev, page, sub)).find(page, sub)
        ok = after is not None and after[2:] == new[2:]
        out("MODE SELECT accepted" + (" and saved." if a.save_page else " (current values only, not saved).")
            + ("  Verified by read-back." if ok else "  WARNING: read-back differs (drive rounded or ignored a value):"))
        if not ok and after is not None:
            out(modepages.render_page(after, defs))


def c_errors(a):
    with open_dev(a) as dev:
        defs = get_defs(a, dev)
        sup = set(supported_logs(dev))
        a.hex, a.pc = False, 1
        for pg in (0x03, 0x02, 0x05, 0x06, 0x2F, 0x11, 0x10, 0x15, 0x18):
            if (pg, 0) in sup:
                _show_log(dev, defs, a, pg, 0, quiet_fail=True)
        _defects(dev)


def _defects(dev):
    out("Defect lists (READ DEFECT DATA(12)):")
    for nm, pl, gl in (("Primary (factory)", True, False), ("Grown", False, True)):
        try:
            d = scsi.read_defect_header(dev, pl, gl)
            fmt = d[1] & 7
            size = 4 if fmt == 0 else 8
            out(f"  {nm:<18}: {int.from_bytes(d[4:8], 'big') // size} entries "
                f"(format {fmt}, generation {int.from_bytes(d[2:4], 'big')})")
        except ScsiError as e:
            out(f"  {nm:<18}: not available - {e}")


def c_defects(a):
    with open_dev(a) as dev:
        _defects(dev)


def c_selftest(a):
    with open_dev(a) as dev:
        if a.action == "status":
            d = scsi.log_sense(dev, 0x10)
            out(logpages.render_log_page(d, None))
            return
        code = scsi.SELF_TEST_CODES[a.action]
        scsi.send_diagnostic_selftest(dev, code, timeout=a.timeout if code >= 5 else 60)
        out({1: "Background short self-test started.", 2: "Background extended self-test started.",
             4: "Background self-test aborted.", 5: "Foreground short self-test completed without error.",
             6: "Foreground extended self-test completed without error."}[code]
            + ("  Check progress with: selftest <dev> status" if code in (1, 2) else ""))


def c_tur(a):
    with open_dev(a) as dev:
        r = scsi.test_unit_ready(dev)
        out("Unit is ready." if r.ok else f"Not ready: {STATUS_NAMES.get(r.status, hex(r.status))}")
        if r.sense:
            out(render_sense(r.sense))


def c_sense(a):
    with open_dev(a) as dev:
        d = scsi.request_sense(dev, desc=a.desc)
        out(["REQUEST SENSE:"] + render_sense(d) + hexdump(d))


def c_startstop(a):
    with open_dev(a) as dev:
        scsi.start_stop(dev, start=(a.cmd == "start"), immed=a.immed)
        out(f"START STOP UNIT ({a.cmd}) accepted.")


def c_readcap(a):
    with open_dev(a) as dev:
        try:
            d = scsi.read_capacity16(dev)
            out(["READ CAPACITY(16):"] + inq.render_readcap16(d))
        except ScsiError:
            last, blk = scsi.read_capacity10(dev)
            out(["READ CAPACITY(10):", "  " + inq.capacity_text(last, blk)])


def c_opcodes(a):
    with open_dev(a) as dev:
        d, _ = scsi.report_opcodes(dev)
        end = min(len(d), 4 + int.from_bytes(d[0:4], "big"))
        out(f"{'Op':<5}{'SA':<8}{'CDB len':<9}{'Timeout (nominal/recommended s)':<34}Name")
        i, quirk = 4, False
        while i + 8 <= end:
            op, sa, flags = d[i], int.from_bytes(d[i + 2:i + 4], "big"), d[i + 5]
            ln = int.from_bytes(d[i + 6:i + 8], "big")
            i += 8
            to = ""
            if flags & 2 and i + 12 <= end:
                nom, rec, q = scsi.parse_timeouts(d[i:i + 12])
                quirk = quirk or q
                to = f"{nom}/{rec}"
                i += 12
            has_sa = bool(flags & 1)
            out(f"{op:02x}   {(f'{sa:04x}' if has_sa else '-'):<8}{ln:<9}{to:<34}"
                f"{scsi.opcode_name(op, sa if has_sa else None)}")
        if quirk:
            out("")
            out("Note: this drive returns non-standard (little-endian) timeout descriptors; "
                "values were decoded accordingly. 0 = no timeout recommended.")


def c_luns(a):
    with open_dev(a) as dev:
        d = scsi.report_luns(dev)
        n = int.from_bytes(d[0:4], "big") // 8
        out(f"{n} logical unit(s):")
        for i in range(n):
            out(f"  {d[8 + i * 8:16 + i * 8].hex()}")


def c_read(a):
    with open_dev(a) as dev:
        try:
            d = scsi.read_capacity16(dev)
            blk = int.from_bytes(d[8:12], "big")
        except ScsiError:
            _, blk = scsi.read_capacity10(dev)
        data = scsi.read16(dev, a.lba, a.count, blk)
        out(f"READ(16) LBA {a.lba} x {a.count} block(s) of {blk} bytes:")
        if a.save:
            save(a.save, data)
        else:
            out(hexdump(data))


def c_sanitize(a):
    with open_dev(a) as dev:
        sa = {"block-erase": 2, "crypto-erase": 3, "exit-failure": 0x1F}[a.method]
        if sa != 0x1F:
            require_confirm(a, dev, f"SANITIZE {a.method}")
        scsi.sanitize(dev, sa, immed=True, ause=a.ause)
        if a.wait:
            out(f"SANITIZE ({a.method}) started. Waiting for completion...")
            _wait_ready(dev, a.interval)
            return
        out(f"SANITIZE ({a.method}) started. Poll progress with: sense <dev>  (progress indication) or tur <dev>")


def _elapsed(t0):
    s = int(time.time() - t0)
    return f"{s // 3600}h {s % 3600 // 60:02d}m {s % 60:02d}s"


def _wait_ready(dev, interval):
    """Poll TEST UNIT READY until a format/sanitize finishes, printing progress."""
    t0 = time.time()
    while True:
        r = scsi.test_unit_ready(dev)
        if r.ok:
            out(f"Operation complete - unit is ready after {_elapsed(t0)}.")
            return
        d = parse_sense(r.sense) or {}
        key, asc, ascq = d.get("key"), d.get("asc"), d.get("ascq")
        if key == 2 and asc == 0x04 and ascq in (0x04, 0x1B, 0x07):
            sks = d.get("sks")
            pct = f"{int.from_bytes(sks[1:3], 'big') * 100 / 65536:6.2f}%" if sks else "  ?"
            out(f"  {_elapsed(t0)}  in progress {pct}")
        elif key != 6:      # unit attentions are expected around a format; anything else is a failure
            raise ValueError(f"operation stopped: {sense_summary(r.sense)}")
        time.sleep(interval)


def c_format(a):
    with open_dev(a) as dev:
        require_confirm(a, dev, "FORMAT UNIT")
        if a.block_size:
            scsi.set_block_descriptor(dev, a.block_size)
            out(f"Block descriptor set to {a.block_size}-byte logical blocks (takes effect with this format).")
        if a.foreground:
            out(f"FORMAT UNIT sent in the foreground (IMMED=0, timeout {a.timeout} s). "
                "Waiting for the drive to finish - do not power off the drive or close this window...")
            t0 = time.time()
            scsi.format_unit(dev, fmtpinfo=a.fmtpinfo, immed=False, timeout=a.timeout)
            out(f"FORMAT UNIT completed with GOOD status after {_elapsed(t0)}.")
            return
        scsi.format_unit(dev, fmtpinfo=a.fmtpinfo, immed=True)
        if not a.wait:
            out("FORMAT UNIT started (IMMED). Poll progress with: sense <dev>. Do not power off the drive.")
            return
        out("FORMAT UNIT started. Waiting for completion - do not power off the drive "
            "(Ctrl+C stops the waiting only, not the format)...")
        _wait_ready(dev, a.interval)


def c_raw(a):
    cdb = parse_hex_bytes(a.cdb)
    data_out = None
    if a.out_hex:
        data_out = parse_hex_bytes(a.out_hex)
    elif a.out_file:
        data_out = open(a.out_file, "rb").read()
    if data_out is not None and a.data_in:
        raise ValueError("a command cannot be both data-in and data-out")
    name = scsi.DESTRUCTIVE_OPCODES.get(cdb[0])
    if name and not a.force:
        raise ValueError(f"opcode {cdb[0]:#04x} ({name}) can modify or destroy data/settings; "
                         "add --force if you really mean it")
    direction = DIR_OUT if data_out is not None else (DIR_IN if a.data_in else DIR_NONE)
    with open_dev(a) as dev:
        r = scsi.raw(dev, cdb, direction, a.data_in or 0, data_out, a.timeout)
    out(f"CDB    : {cdb.hex(' ')}  ({scsi.opcode_name(cdb[0])})")
    out(f"Status : {r.status:#04x} {STATUS_NAMES.get(r.status, '')}")
    if r.sense:
        out(["Sense  :"] + render_sense(r.sense) + hexdump(r.sense, "    "))
    if direction == DIR_IN:
        out(f"Data in: {len(r.data)} bytes")
        if a.save:
            save(a.save, r.data)
        else:
            out(hexdump(r.data))
    elif direction == DIR_OUT:
        out(f"Data out: {len(data_out)} bytes sent")
    if not r.ok:
        sys.exit(2)


def c_decode(a):
    data = parse_hex_bytes(a.hex_data) if a.hex_data else open(a.file, "rb").read()
    defs = vendor.load(a.vendor or "", a.product or "", "", extra_dirs=a.defs or (),
                       force_files=a.defs_file or ())
    if a.kind == "log":
        out(logpages.render_log_page(data, defs))
    elif a.kind in ("mode", "mode6"):
        md = modepages.ModeData(data, ten=(a.kind == "mode"))
        out(f"Block descriptor: {md.block_descriptor_text()}")
        for _, _, page in md.pages:
            out(modepages.render_page(page, defs))
    elif a.kind == "modepage":
        out(modepages.render_page(data, defs))
    elif a.kind == "vpd":
        out(inq.render_vpd(data, defs))
    elif a.kind == "inquiry":
        out(inq.render_std_inquiry(data))
    elif a.kind == "readcap16":
        out(inq.render_readcap16(data))
    elif a.kind == "sense":
        out(render_sense(data))


# ---------------------------------------------------------------- parser
def build_parser():
    p = argparse.ArgumentParser(prog="sastool", description="SAS/SCSI drive diagnostic tool (Windows). "
                                "Page codes are hexadecimal. Run from an elevated prompt.")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--trace", action="store_true", help="print every CDB sent and its status")
    p.add_argument("--defs", action="append", metavar="DIR", help="extra vendor definition directory")
    p.add_argument("--defs-file", action="append", metavar="JSON",
                   help="apply this vendor definition file regardless of its match block")
    sp = p.add_subparsers(dest="cmd", required=True, metavar="command")

    def add(name, fn, help_, dev=True):
        s = sp.add_parser(name, help=help_, description=help_)
        s.set_defaults(fn=fn)
        if dev:
            s.add_argument("device", help="drive number from 'list' (e.g. 7) or a \\\\.\\ device path")
        return s

    def rd(s, pc=False):
        s.add_argument("--hex", action="store_true", help="raw hex dump instead of decoding")
        s.add_argument("--save", metavar="FILE", help="save the raw response to a binary file")
        if pc:
            s.add_argument("--pc", type=int, default=pc - 1 if pc is not True else 0, choices=range(4),
                           help="page control")
        return s

    add("list", c_list, "list physical drives (no admin needed)", dev=False)
    add("info", c_info, "identity, capacity and health summary")
    rd(add("inquiry", c_inquiry, "standard INQUIRY data"))
    s = rd(add("vpd", c_vpd, "VPD pages: no page = supported list, --all = every page"))
    s.add_argument("page", nargs="?", type=page_arg, help="VPD page code (hex)")
    s.add_argument("--all", action="store_true")

    add("logs", c_logs, "list supported log pages and subpages")
    s = rd(add("log", c_log, "read and decode a log page (or 'all')"))
    s.add_argument("page", help="page[/subpage] in hex, or 'all'")
    s.add_argument("--pc", type=int, default=1, choices=range(4),
                   help="page control: 0 threshold, 1 cumulative (default), 2 default threshold, 3 default cumulative")
    s.add_argument("--param-ptr", type=lambda x: int(x, 0), default=0, help="parameter pointer")
    s = add("log-reset", c_log_reset, "reset log parameters with LOG SELECT PCR=1")
    s.add_argument("page", nargs="?", type=page_arg, help="page[/subpage]; omit for all pages (needs --yes)")
    s.add_argument("--pc", type=int, default=1, choices=range(4))
    s.add_argument("--sp", action="store_true", help="save parameters")
    s.add_argument("--yes", action="store_true")
    s = add("log-write", c_log_write, "send a raw LOG SELECT parameter list to a page")
    s.add_argument("page", type=page_arg)
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--data", help="parameter list as hex bytes")
    g.add_argument("--file", help="parameter list from a binary file")
    s.add_argument("--pc", type=int, default=1, choices=range(4))
    s.add_argument("--sp", action="store_true")

    s = rd(add("modes", c_modes, "read and decode every mode page"))
    s.add_argument("--pc", type=int, default=0, choices=range(4),
                   help="0 current (default), 1 changeable, 2 default, 3 saved")
    s = rd(add("mode", c_mode, "one mode page with changeable/default/saved columns"))
    s.add_argument("page", type=page_arg, help="page[/subpage] in hex")
    s = add("mode-set", c_mode_set, "change mode page fields: NAME=value or @byteoffset=value")
    s.add_argument("page", type=page_arg)
    s.add_argument("assign", nargs="+", metavar="NAME=VALUE")
    s.add_argument("--save", dest="save_page", action="store_true", help="SP=1: persist across power cycles")
    s.add_argument("--force", action="store_true", help="send even if bits are not reported changeable")
    s.add_argument("--dry-run", action="store_true", help="show the parameter list without sending it")

    add("errors", c_errors, "error counters, self-test, background scan, phy errors, defect counts")
    add("defects", c_defects, "primary and grown defect list sizes")
    s = add("selftest", c_selftest, "start/abort a self-test or show the results log")
    s.add_argument("action", choices=list(scsi.SELF_TEST_CODES) + ["status"])
    s.add_argument("--timeout", type=int, default=7200, help="seconds, foreground tests only")

    add("tur", c_tur, "TEST UNIT READY")
    add("sense", c_sense, "REQUEST SENSE (also shows format/sanitize progress)").add_argument(
        "--desc", action="store_true", help="request descriptor format")
    for n in ("start", "stop"):
        add(n, c_startstop, f"START STOP UNIT ({n})").add_argument("--immed", action="store_true")
    add("readcap", c_readcap, "READ CAPACITY(16), falling back to (10)")
    add("opcodes", c_opcodes, "REPORT SUPPORTED OPERATION CODES")
    add("luns", c_luns, "REPORT LUNS")
    s = add("read", c_read, "read logical blocks with READ(16)")
    s.add_argument("lba", type=lambda x: int(x, 0))
    s.add_argument("count", type=lambda x: int(x, 0), nargs="?", default=1)
    s.add_argument("--save", metavar="FILE")

    s = add("sanitize", c_sanitize, "SANITIZE block erase / cryptographic erase (DESTROYS DATA)")
    s.add_argument("method", choices=["block-erase", "crypto-erase", "exit-failure"])
    s.add_argument("--ause", action="store_true", help="allow unrestricted sanitize exit")
    s.add_argument("--wait", action="store_true", help="poll and print progress until done")
    s.add_argument("--interval", type=int, default=15, help="seconds between --wait progress polls")
    s.add_argument("--confirm", metavar="SERIAL")
    s = add("format", c_format, "FORMAT UNIT, optionally changing the logical block size (DESTROYS DATA)")
    s.add_argument("--block-size", type=int, help="new logical block length, e.g. 512 or 4096")
    s.add_argument("--fmtpinfo", type=int, default=0, choices=range(4), help="protection information format")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--foreground", action="store_true",
                   help="IMMED=0: the command itself does not return until the format is done")
    g.add_argument("--wait", action="store_true",
                   help="start in the background, then poll and print progress until done")
    s.add_argument("--timeout", type=int, default=86400, help="seconds to allow a --foreground format (default 24 h)")
    s.add_argument("--interval", type=int, default=15, help="seconds between --wait progress polls")
    s.add_argument("--confirm", metavar="SERIAL")

    s = add("raw", c_raw, "send one arbitrary CDB (6-16 bytes)")
    s.add_argument("--cdb", required=True, help='CDB bytes in hex, e.g. "12 00 00 00 60 00"')
    s.add_argument("--in", dest="data_in", type=lambda x: int(x, 0), metavar="LEN", help="data-in length")
    s.add_argument("--out-hex", help="data-out payload as hex bytes")
    s.add_argument("--out-file", help="data-out payload from a binary file")
    s.add_argument("--timeout", type=int, default=30)
    s.add_argument("--save", metavar="FILE", help="save data-in to a file")
    s.add_argument("--force", action="store_true", help="allow opcodes that write or erase")

    s = add("decode", c_decode, "decode a saved response offline (no drive needed)", dev=False)
    s.add_argument("kind", choices=["log", "mode", "mode6", "modepage", "vpd", "inquiry", "readcap16", "sense"])
    s.add_argument("file", nargs="?")
    s.add_argument("--hex-data", help="hex bytes instead of a file")
    s.add_argument("--vendor", help="vendor string for matching definition files")
    s.add_argument("--product", help="product string for matching definition files")
    return p


def main(argv=None):
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass
    a = build_parser().parse_args(argv)
    if a.cmd == "decode" and not (a.file or a.hex_data):
        print("error: decode needs a file or --hex-data", file=sys.stderr)
        return 1
    try:
        a.fn(a)
    except (TransportError, ScsiError, ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0

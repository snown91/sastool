# sastool

A SAS/SCSI drive diagnostic tool for Windows. Pure Python (3.9+), no dependencies. It talks to
drives with `IOCTL_SCSI_PASS_THROUGH_DIRECT`, so it works with any HBA whose driver passes SCSI
commands through to the drive (HBAs in IT/pass-through mode; not drives hidden behind a RAID volume).

## Running

Open an **elevated** prompt (Run as administrator) in this folder:

```
sastool list                 (works without admin)
sastool info 7               (7 = drive number from list)
```

`sastool.cmd` is a launcher for `python -m sastool`. Page codes are always **hexadecimal**
(`19`, `0x19`, `19/01` for page/subpage). Add `--trace` before the command to see every CDB sent.

### GUI

`sastool-gui.cmd` (or `python -m sastool.gui`) opens a Tkinter front end (no extra dependencies).
Pick a drive from the list, then use the tabs: Identify, Log pages, Mode pages (with dry-run/apply
for `mode-set`), Unit / self-test, Destructive (format/sanitize, requires typing the serial plus a
confirmation dialog), Raw CDB and Offline decode. Each button runs the equivalent CLI command and
streams its output to the pane below, where it can be cancelled, copied or saved. Drive commands
need elevation; if started normally the GUI shows a "Restart as administrator" button.

## Commands

| Area | Command | What it does |
|---|---|---|
| Identify | `list` | All physical drives with bus type, address, vendor, product, serial |
| | `info DEV` | Identity, NAA, capacity, block size, protection, temperature, wear, power-on time, error totals |
| | `inquiry DEV` | Standard INQUIRY, decoded |
| | `vpd DEV [PAGE] [--all]` | VPD pages (00, 80, 83, 86, 8A, B0, B1, B2 decoded; others hex) |
| | `readcap`, `luns`, `opcodes` | READ CAPACITY(16), REPORT LUNS, REPORT SUPPORTED OPERATION CODES |
| Logs | `logs DEV` | Supported log pages and subpages |
| | `log DEV PAGE` / `log DEV all` | Read and decode a page; `--pc`, `--hex`, `--save FILE` |
| | `log-reset DEV [PAGE]` | LOG SELECT with PCR=1 (whole drive needs `--yes`) |
| | `log-write DEV PAGE --data HEX` | Send a raw LOG SELECT parameter list |
| Errors | `errors DEV` | Read/write/verify/non-medium counters, informational exceptions, wear, self-test log, background scan events, SAS phy error counters, defect list sizes |
| | `defects DEV` | Primary and grown defect list sizes |
| | `selftest DEV short\|extended\|abort\|fg-short\|fg-extended\|status` | SEND DIAGNOSTIC self-tests |
| Mode pages | `modes DEV` | Every mode page, decoded (`--pc 0..3`) |
| | `mode DEV PAGE` | One page with current value, changeable?, default and saved columns |
| | `mode-set DEV PAGE NAME=VALUE ...` | Change fields; `--save` to persist, `--dry-run` to preview |
| Unit | `tur`, `sense`, `start`, `stop`, `read DEV LBA [COUNT]` | Single standard commands |
| Destructive | `sanitize DEV block-erase\|crypto-erase` | Needs `--confirm <serial>` |
| | `format DEV [--block-size 512] [--foreground \| --wait]` | FORMAT UNIT, e.g. 520 to 512 byte sectors. Needs `--confirm <serial>`. `--foreground` blocks until the drive finishes; `--wait` polls and prints progress |
| Custom | `raw DEV --cdb "..."` | Any 6 to 16 byte CDB, see below |
| Offline | `decode KIND FILE` | Decode a saved response without a drive |

Decoded log pages: 02/03/05 error counters, 06 non-medium, 08 format status, 0C logical block
provisioning, 0D temperature, 0E start-stop, 10 self-test results, 11 solid state media,
15 background scan, 18 SAS protocol-specific port (phy counters and events), 19 general statistics,
1A power transitions, 2F informational exceptions. Anything else is shown parameter by parameter.

Decoded mode pages: 01, 02, 07, 08, 0A, 0A/01, 18, 19, 19/02, 1A, 1C, 1C/01.

### Editing mode pages

```
sastool mode 7 08                      show Caching page with changeable mask
sastool mode-set 7 08 WCE=1 --dry-run  preview the MODE SELECT parameter list
sastool mode-set 7 08 WCE=1 --save     apply and save
sastool mode-set 7 00 @5=0x40          set a raw byte in a page with no field definitions
```

`mode-set` reads the current page, applies your changes, checks them against the drive's
changeable mask (refuses unless `--force`), sends MODE SELECT(10), then reads the page back to verify.

### Raw commands

```
sastool raw 7 --cdb "12 00 00 00 60 00" --in 96                     data-in
sastool raw 7 --cdb "00 00 00 00 00 00"                             no data
sastool raw 7 --cdb "55 11 00 00 00 00 00 00 1c 00" --out-file p.bin --force   data-out
```

Prints status, decoded sense data and a hex dump (`--save FILE` to capture data-in). Opcodes that
write or erase (FORMAT, SANITIZE, WRITE*, MODE/LOG SELECT, WRITE BUFFER, UNMAP...) need `--force`.
Exit code is 2 when the drive returns a non-GOOD status.

## Vendor-unique definitions

Drop a JSON file in `sastool/definitions/` (or a folder given with `--defs DIR` or the
`SASTOOL_DEFS` environment variable). It is applied to every drive whose INQUIRY strings match its
`match` regexes. `--defs-file X.json` forces one file regardless. Start from
`sastool/definitions/_template.json` (files starting with `_` are ignored).

```json
{
  "match": { "vendor": "^HGST", "product": "H4STR" },
  "log_pages": {
    "0x30": {
      "name": "My vendor log",
      "params": {
        "0x0001": { "name": "Simple counter", "unit": "events" },
        "0x0002": { "name": "Structured", "fields": [
          { "name": "Flag",  "byte": 0, "bit": 7, "bits": 1 },
          { "name": "Count", "byte": 4, "bits": 32 } ] },
        "*": { "name": "Anything else", "format": "hex" }
      }
    }
  },
  "mode_pages": { "0x00": { "name": "Vendor page", "fields": [ ... ] } },
  "vpd_pages":  { "0xC0": { "name": "Vendor VPD",  "fields": [ ... ] } }
}
```

Field keys: `name`, `byte` (offset), `bit` (most significant bit of the field within that byte, 7..0,
default 7), `bits` (width, default 8; multi-byte fields are big-endian), `format`
(`dec`, `hex`, `signed`, `ascii`, `bytes`), `enum` (value to label), `unit`.

Offsets are relative to:

- log parameter `fields`: the first byte of the parameter **value** (after its 4-byte header)
- log page with `"layout": "flat"`: byte 0 of the page (for vendor logs that are not parameter lists)
- mode page: byte 0 of the page (the page code byte), matching how the standards draw them
- VPD page: byte 0 of the page

Keys are `"0x30"` or `"0x30/0x01"` for a subpage. Vendor mode page fields become settable by name
in `mode-set`. A definition for a standard page overrides the built-in decoding.

To develop definitions without touching the drive: `sastool log 7 30 --save p30.bin`, then
`sastool --defs-file mine.json decode log p30.bin`.

## Limits

- CDBs up to 16 bytes (32-byte variable-length CDBs are not implemented).
- No firmware download (WRITE BUFFER) or SES/enclosure helpers yet; both are reachable with `raw`.
- Tests: `python -m unittest discover -s tests`

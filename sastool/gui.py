"""Tkinter front end for sastool.

Every action builds the same argument list you would type at the command line and runs
``python -m sastool ...`` as a child process, streaming its output into the output pane.
That keeps the GUI and the CLI behaviour identical and lets a long operation be cancelled.
"""
import ctypes
import os
import queue
import shlex
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import __version__

PKG_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    exe = sys.executable
    if exe.lower().endswith("python.exe"):          # avoid a console window for the GUI
        w = exe[:-10] + "pythonw.exe"
        exe = w if os.path.exists(w) else exe
    params = subprocess.list2cmdline(["-m", "sastool.gui"])
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, PKG_PARENT, 1)
    return rc > 32


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"sastool {__version__} - SAS/SCSI drive diagnostics")
        self.geometry("1100x760")
        self.minsize(900, 600)
        self.proc = None
        self.q = queue.Queue()
        self.drives = {}                      # tree iid -> drive dict
        self.v_trace = tk.BooleanVar()
        self.v_defs_file = tk.StringVar()
        self.v_status = tk.StringVar(value="Ready")
        self._build()
        self.after(100, self._pump)
        self.after(200, self.refresh_drives)

    # ------------------------------------------------------------ layout
    def _build(self):
        top = ttk.Frame(self, padding=(8, 8, 8, 0))
        top.pack(fill="x")
        if not is_admin():
            bar = tk.Frame(top, bg="#fff3cd")
            bar.pack(fill="x", pady=(0, 6))
            tk.Label(bar, bg="#fff3cd", fg="#664d03", anchor="w",
                     text="Not running as administrator - 'list' works, but drive commands need elevation."
                     ).pack(side="left", padx=8, pady=4)
            ttk.Button(bar, text="Restart as administrator", command=self._elevate).pack(side="right", padx=8, pady=3)

        cols = ("#", "Bus", "Address", "Vendor", "Product", "Rev", "Serial")
        wid = (40, 60, 80, 90, 220, 80, 200)
        box = ttk.LabelFrame(top, text="Drives", padding=4)
        box.pack(fill="x")
        self.tree = ttk.Treeview(box, columns=cols, show="headings", height=5, selectmode="browse")
        for c, w in zip(cols, wid):
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, anchor="w", stretch=(c in ("Product", "Serial")))
        self.tree.pack(side="left", fill="x", expand=True)
        sb = ttk.Scrollbar(box, command=self.tree.yview)
        sb.pack(side="left", fill="y")
        self.tree.configure(yscrollcommand=sb.set)
        btns = ttk.Frame(box, padding=(6, 0))
        btns.pack(side="left", fill="y")
        ttk.Button(btns, text="Refresh", command=self.refresh_drives).pack(fill="x")
        ttk.Checkbutton(btns, text="Trace CDBs", variable=self.v_trace).pack(anchor="w", pady=(6, 0))

        opt = ttk.Frame(top)
        opt.pack(fill="x", pady=(4, 0))
        ttk.Label(opt, text="Vendor definition file:").pack(side="left")
        ttk.Entry(opt, textvariable=self.v_defs_file).pack(side="left", fill="x", expand=True, padx=4)
        ttk.Button(opt, text="Browse...", command=lambda: self._pick(self.v_defs_file, "JSON", "*.json")).pack(side="left")

        nb = ttk.Notebook(self, padding=4)
        nb.pack(fill="x", padx=8, pady=6)
        self._tab_identify(nb)
        self._tab_logs(nb)
        self._tab_modes(nb)
        self._tab_unit(nb)
        self._tab_destructive(nb)
        self._tab_raw(nb)
        self._tab_decode(nb)

        mid = ttk.Frame(self, padding=(8, 0))
        mid.pack(fill="x")
        self.btn_cancel = ttk.Button(mid, text="Cancel running command", command=self.cancel, state="disabled")
        self.btn_cancel.pack(side="left")
        ttk.Button(mid, text="Clear", command=lambda: self._set_output("")).pack(side="left", padx=4)
        ttk.Button(mid, text="Copy", command=self._copy).pack(side="left")
        ttk.Button(mid, text="Save output...", command=self._save_output).pack(side="left", padx=4)
        self.pb = ttk.Progressbar(mid, mode="indeterminate", length=120)
        self.pb.pack(side="right")

        of = ttk.Frame(self, padding=(8, 4, 8, 0))
        of.pack(fill="both", expand=True)
        self.out = tk.Text(of, wrap="none", font=("Consolas", 10), state="disabled", undo=False)
        self.out.tag_configure("cmd", foreground="#0b5394")
        self.out.tag_configure("err", foreground="#b00020")
        ys = ttk.Scrollbar(of, command=self.out.yview)
        xs = ttk.Scrollbar(of, orient="horizontal", command=self.out.xview)
        self.out.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        ys.pack(side="right", fill="y")
        xs.pack(side="bottom", fill="x")
        self.out.pack(fill="both", expand=True)
        ttk.Label(self, textvariable=self.v_status, relief="sunken", anchor="w", padding=(6, 2)).pack(fill="x", side="bottom")

    def _row(self, parent):
        f = ttk.Frame(parent)
        f.pack(fill="x", pady=2)
        return f

    def _tab(self, nb, title):
        f = ttk.Frame(nb, padding=6)
        nb.add(f, text=title)
        return f

    def _btn(self, parent, text, args, **kw):
        """A button that runs a fixed command on the selected drive."""
        b = ttk.Button(parent, text=text, command=lambda: self.run(args, **kw))
        b.pack(side="left", padx=2)
        return b

    def _entry(self, parent, label, default="", width=10):
        ttk.Label(parent, text=label).pack(side="left", padx=(8, 2))
        v = tk.StringVar(value=default)
        ttk.Entry(parent, textvariable=v, width=width).pack(side="left")
        return v

    def _tab_identify(self, nb):
        t = self._tab(nb, "Identify")
        r = self._row(t)
        for text, a in (("Summary (info)", ["info"]), ("Inquiry", ["inquiry"]), ("Read capacity", ["readcap"]),
                        ("LUNs", ["luns"]), ("Supported opcodes", ["opcodes"])):
            self._btn(r, text, a)
        r = self._row(t)
        self._btn(r, "VPD supported list", ["vpd"])
        self._btn(r, "All VPD pages", ["vpd", "--all"])
        self.v_vpd = self._entry(r, "VPD page (hex):", "83", 6)
        ttk.Button(r, text="Read page", command=lambda: self.run(["vpd", self.v_vpd.get().strip()])).pack(side="left", padx=4)

    def _tab_logs(self, nb):
        t = self._tab(nb, "Log pages")
        r = self._row(t)
        self._btn(r, "List supported pages", ["logs"])
        self._btn(r, "Error summary (errors)", ["errors"])
        self._btn(r, "Defect lists", ["defects"])
        self._btn(r, "Self-test results", ["selftest", "status"])
        r = self._row(t)
        self.v_logpage = self._entry(r, "Page[/sub] (hex) or 'all':", "03", 8)
        ttk.Label(r, text="Control:").pack(side="left", padx=(8, 2))
        self.v_logpc = tk.StringVar(value="1 cumulative")
        ttk.Combobox(r, textvariable=self.v_logpc, state="readonly", width=20,
                     values=["0 threshold", "1 cumulative", "2 default threshold", "3 default cumulative"]
                     ).pack(side="left")
        self.v_loghex = tk.BooleanVar()
        ttk.Checkbutton(r, text="Raw hex", variable=self.v_loghex).pack(side="left", padx=6)
        ttk.Button(r, text="Read log page", command=self._read_log).pack(side="left", padx=4)
        ttk.Button(r, text="Save raw...", command=self._save_log).pack(side="left")
        r = self._row(t)
        ttk.Label(r, text="Reset counters (LOG SELECT PCR=1):").pack(side="left")
        self.v_resetpage = self._entry(r, "Page (blank = ALL pages):", "", 8)
        ttk.Button(r, text="Reset", command=self._log_reset).pack(side="left", padx=6)

    def _tab_modes(self, nb):
        t = self._tab(nb, "Mode pages")
        r = self._row(t)
        self.v_modepc = tk.StringVar(value="0 current")
        ttk.Label(r, text="All pages as:").pack(side="left")
        ttk.Combobox(r, textvariable=self.v_modepc, state="readonly", width=14,
                     values=["0 current", "1 changeable", "2 default", "3 saved"]).pack(side="left", padx=4)
        ttk.Button(r, text="Read all mode pages", command=lambda: self.run(["modes", "--pc", self.v_modepc.get()[0]])).pack(side="left", padx=4)
        r = self._row(t)
        self.v_modepage = self._entry(r, "Page[/sub] (hex):", "08", 8)
        ttk.Button(r, text="Show page (current/changeable/default/saved)",
                   command=lambda: self.run(["mode", self.v_modepage.get().strip()])).pack(side="left", padx=6)
        r = self._row(t)
        ttk.Label(r, text="Change fields (NAME=VALUE, space-separated, or @byte=value):").pack(side="left")
        r = self._row(t)
        self.v_assign = tk.StringVar(value="WCE=1")
        ttk.Entry(r, textvariable=self.v_assign, width=50).pack(side="left")
        self.v_savepage = tk.BooleanVar()
        self.v_force = tk.BooleanVar()
        ttk.Checkbutton(r, text="Persist (--save)", variable=self.v_savepage).pack(side="left", padx=6)
        ttk.Checkbutton(r, text="Force", variable=self.v_force).pack(side="left")
        ttk.Button(r, text="Dry run", command=lambda: self._mode_set(True)).pack(side="left", padx=6)
        ttk.Button(r, text="Apply", command=lambda: self._mode_set(False)).pack(side="left")

    def _tab_unit(self, nb):
        t = self._tab(nb, "Unit / self-test")
        r = self._row(t)
        self._btn(r, "Test unit ready", ["tur"])
        self._btn(r, "Request sense", ["sense"])
        self._btn(r, "Start (spin up)", ["start"], confirm="Send START STOP UNIT (start)?")
        self._btn(r, "Stop (spin down)", ["stop"], confirm="Send START STOP UNIT (stop)? The drive will spin down.")
        r = self._row(t)
        ttk.Label(r, text="Self-test:").pack(side="left")
        for act in ("short", "extended", "abort", "fg-short", "fg-extended"):
            self._btn(r, act, ["selftest", act], confirm=f"Start self-test '{act}'?" if act != "abort" else None)
        ttk.Label(t, text="Foreground tests block until finished; use Cancel to stop waiting.").pack(anchor="w")
        r = self._row(t)
        self.v_lba = self._entry(r, "Read LBA:", "0", 12)
        self.v_cnt = self._entry(r, "Blocks:", "1", 6)
        ttk.Button(r, text="Read (hex dump)", command=lambda: self.run(
            ["read", self.v_lba.get().strip(), self.v_cnt.get().strip()])).pack(side="left", padx=6)

    def _tab_destructive(self, nb):
        t = self._tab(nb, "Destructive")
        tk.Label(t, fg="#b00020", anchor="w", font=("Segoe UI", 10, "bold"),
                 text="These commands ERASE ALL DATA on the selected drive. You must type its serial number to proceed."
                 ).pack(fill="x")
        r = self._row(t)
        ttk.Label(r, text="Confirm serial number:").pack(side="left")
        self.v_serial = tk.StringVar()
        ttk.Entry(r, textvariable=self.v_serial, width=30).pack(side="left", padx=4)
        ttk.Button(r, text="Use selected drive's serial", command=self._fill_serial).pack(side="left")
        r = self._row(t)
        ttk.Label(r, text="Sanitize:").pack(side="left")
        self.v_sanmethod = tk.StringVar(value="block-erase")
        ttk.Combobox(r, textvariable=self.v_sanmethod, state="readonly", width=14,
                     values=["block-erase", "crypto-erase", "exit-failure"]).pack(side="left", padx=4)
        ttk.Button(r, text="Run sanitize (wait for completion)", command=self._sanitize).pack(side="left", padx=4)
        r = self._row(t)
        ttk.Label(r, text="Format unit:").pack(side="left")
        self.v_bs = self._entry(r, "New block size (blank = keep):", "", 6)
        self.v_fmode = tk.StringVar(value="wait")
        ttk.Radiobutton(r, text="Background + progress", variable=self.v_fmode, value="wait").pack(side="left", padx=6)
        ttk.Radiobutton(r, text="Foreground (blocks)", variable=self.v_fmode, value="foreground").pack(side="left")
        ttk.Button(r, text="Run FORMAT UNIT", command=self._format).pack(side="left", padx=8)
        ttk.Label(t, text="Progress can also be checked from the Unit tab (Request sense). "
                          "Do not power off the drive during a format or sanitize.").pack(anchor="w")

    def _tab_raw(self, nb):
        t = self._tab(nb, "Raw CDB")
        r = self._row(t)
        self.v_cdb = self._entry(r, "CDB (hex):", "12 00 00 00 60 00", 40)
        self.v_in = self._entry(r, "Data-in length:", "96", 6)
        r = self._row(t)
        self.v_outhex = self._entry(r, "Data-out (hex, optional):", "", 40)
        self.v_rawforce = tk.BooleanVar()
        ttk.Checkbutton(r, text="Force (write/erase opcodes)", variable=self.v_rawforce).pack(side="left", padx=8)
        ttk.Button(r, text="Send", command=self._raw).pack(side="left", padx=6)

    def _tab_decode(self, nb):
        t = self._tab(nb, "Offline decode")
        r = self._row(t)
        ttk.Label(r, text="Kind:").pack(side="left")
        self.v_dkind = tk.StringVar(value="log")
        ttk.Combobox(r, textvariable=self.v_dkind, state="readonly", width=10,
                     values=["log", "mode", "mode6", "modepage", "vpd", "inquiry", "readcap16", "sense"]).pack(side="left", padx=4)
        self.v_dfile = tk.StringVar()
        ttk.Entry(r, textvariable=self.v_dfile, width=40).pack(side="left", padx=4)
        ttk.Button(r, text="Browse...", command=lambda: self._pick(self.v_dfile, "Binary", "*.*")).pack(side="left")
        r = self._row(t)
        self.v_dhex = self._entry(r, "...or hex bytes:", "", 50)
        r = self._row(t)
        self.v_dvendor = self._entry(r, "Vendor:", "", 12)
        self.v_dproduct = self._entry(r, "Product:", "", 16)
        ttk.Button(r, text="Decode", command=self._decode).pack(side="left", padx=8)

    # ------------------------------------------------------------ helpers
    def _pick(self, var, label, pattern):
        p = filedialog.askopenfilename(filetypes=[(label, pattern), ("All files", "*.*")])
        if p:
            var.set(p)

    def _elevate(self):
        if relaunch_as_admin():
            self.destroy()
        else:
            messagebox.showerror("Elevation", "Could not restart as administrator (cancelled?).")

    def _selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Select a drive", "Select a drive in the list first.")
            return None
        return self.drives[sel[0]]

    def _fill_serial(self):
        d = self._selected()
        if d:
            self.v_serial.set(d["serial"])

    def _set_output(self, text):
        self.out.configure(state="normal")
        self.out.delete("1.0", "end")
        if text:
            self.out.insert("end", text)
        self.out.configure(state="disabled")

    def _append(self, text, tag=None):
        self.out.configure(state="normal")
        self.out.insert("end", text, tag)
        self.out.see("end")
        self.out.configure(state="disabled")

    def _copy(self):
        self.clipboard_clear()
        self.clipboard_append(self.out.get("1.0", "end-1c"))

    def _save_output(self):
        p = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if p:
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(self.out.get("1.0", "end-1c"))

    # ------------------------------------------------------------ process running
    def _global_args(self):
        g = []
        if self.v_trace.get():
            g.append("--trace")
        if self.v_defs_file.get().strip():
            g += ["--defs-file", self.v_defs_file.get().strip()]
        return g

    def _start(self, argv, on_done=None):
        if self.proc is not None:
            messagebox.showwarning("Busy", "A command is still running. Cancel it or wait for it to finish.")
            return False
        full = [sys.executable, "-m", "sastool"] + argv
        if os.path.basename(full[0]).lower() == "pythonw.exe":
            alt = os.path.join(os.path.dirname(full[0]), "python.exe")
            if os.path.exists(alt):
                full[0] = alt
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1",
                   PYTHONPATH=PKG_PARENT + os.pathsep + os.environ.get("PYTHONPATH", ""))
        shown = "sastool " + subprocess.list2cmdline(argv)
        self._append(f"\n> {shown}\n", "cmd")
        try:
            self.proc = subprocess.Popen(full, cwd=PKG_PARENT, env=env, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, creationflags=NO_WINDOW)
        except OSError as e:
            self._append(f"cannot start: {e}\n", "err")
            return False
        self.btn_cancel.configure(state="normal")
        self.pb.start(12)
        self.v_status.set("Running: " + shown)
        threading.Thread(target=self._reader, args=(self.proc, on_done), daemon=True).start()
        return True

    def _reader(self, proc, on_done):
        for line in iter(proc.stdout.readline, b""):
            self.q.put(("line", line.decode("utf-8", "replace")))
        proc.wait()
        self.q.put(("done", (proc.returncode, on_done)))

    def _pump(self):
        try:
            while True:
                kind, val = self.q.get_nowait()
                if kind == "line":
                    self._append(val, "err" if val.startswith("error:") else None)
                else:
                    rc, cb = val
                    self.proc = None
                    self.pb.stop()
                    self.btn_cancel.configure(state="disabled")
                    self.v_status.set("Finished" if rc == 0 else f"Finished with exit code {rc}")
                    if cb:
                        cb(rc)
        except queue.Empty:
            pass
        self.after(80, self._pump)

    def cancel(self):
        if self.proc is not None:
            self.proc.terminate()
            self._append("[cancelled - note: a format/sanitize already started on the drive keeps running]\n", "err")

    def run(self, args, confirm=None, device=True):
        if confirm and not messagebox.askyesno("Confirm", confirm):
            return
        if device:
            d = self._selected()
            if not d:
                return
            argv = self._global_args() + [args[0], str(d["index"])] + list(args[1:])
        else:
            argv = self._global_args() + list(args)
        self._start(argv)

    # ------------------------------------------------------------ drive list
    def refresh_drives(self):
        if self.proc is not None:
            return
        buf = []

        def done(rc):
            self.tree.delete(*self.tree.get_children())
            self.drives.clear()
            for d in buf:
                iid = self.tree.insert("", "end", values=(d["index"], d["bus"], d.get("address", ""), d["vendor"],
                                                           d["product"], d["revision"], d["serial"]))
                self.drives[iid] = d
            if self.drives:
                sas = [i for i, d in self.drives.items() if d["bus"] in ("SAS", "SCSI", "RAID", "FC")]
                first = sas[0] if sas else next(iter(self.drives))
                self.tree.selection_set(first)

        try:
            from .transport import enumerate_drives
            buf.extend(enumerate_drives())
        except Exception as e:
            self._append(f"drive enumeration failed: {e}\n", "err")
        done(0)
        self.v_status.set(f"{len(self.drives)} drive(s) found")

    # ------------------------------------------------------------ actions with arguments
    def _read_log(self):
        a = ["log", self.v_logpage.get().strip(), "--pc", self.v_logpc.get()[0]]
        if self.v_loghex.get():
            a.append("--hex")
        self.run(a)

    def _save_log(self):
        p = filedialog.asksaveasfilename(defaultextension=".bin", filetypes=[("Binary", "*.bin")])
        if p:
            self.run(["log", self.v_logpage.get().strip(), "--pc", self.v_logpc.get()[0], "--save", p])

    def _log_reset(self):
        pg = self.v_resetpage.get().strip()
        if pg:
            self.run(["log-reset", pg], confirm=f"Reset log page {pg}?")
        else:
            self.run(["log-reset", "--yes"], confirm="Reset ALL resettable log counters on this drive?")

    def _mode_set(self, dry):
        try:
            assigns = shlex.split(self.v_assign.get(), posix=False)
        except ValueError as e:
            messagebox.showerror("Assignments", str(e))
            return
        if not assigns:
            messagebox.showinfo("Assignments", "Enter at least one NAME=VALUE.")
            return
        a = ["mode-set", self.v_modepage.get().strip()] + assigns
        if dry:
            a.append("--dry-run")
        else:
            if self.v_savepage.get():
                a.append("--save")
        if self.v_force.get():
            a.append("--force")
        self.run(a, confirm=None if dry else "Send MODE SELECT with these changes to the drive?")

    def _need_serial(self, what):
        d = self._selected()
        if not d:
            return None
        sn = self.v_serial.get().strip()
        if not sn:
            messagebox.showerror("Serial required", "Type the drive's serial number in the confirm box.")
            return None
        if not messagebox.askyesno(
                "DESTROYS ALL DATA",
                f"{what} on drive #{d['index']} ({d['vendor']} {d['product']}, serial {sn}) "
                "will ERASE ALL DATA and cannot be undone.\n\nProceed?", icon="warning", default="no"):
            return None
        return d, sn

    def _sanitize(self):
        m = self.v_sanmethod.get()
        if m == "exit-failure":
            self.run(["sanitize", m])
            return
        r = self._need_serial(f"SANITIZE ({m})")
        if r:
            self.run(["sanitize", m, "--wait", "--confirm", r[1]])

    def _format(self):
        r = self._need_serial("FORMAT UNIT")
        if not r:
            return
        a = ["format", "--confirm", r[1], "--foreground" if self.v_fmode.get() == "foreground" else "--wait"]
        if self.v_bs.get().strip():
            a += ["--block-size", self.v_bs.get().strip()]
        self.run(a)

    def _raw(self):
        a = ["raw", "--cdb", self.v_cdb.get().strip()]
        if self.v_in.get().strip():
            a += ["--in", self.v_in.get().strip()]
        if self.v_outhex.get().strip():
            a += ["--out-hex", self.v_outhex.get().strip()]
        if self.v_rawforce.get():
            a.append("--force")
        self.run(a, confirm="Send this CDB with --force (it may write or erase)?" if self.v_rawforce.get() else None)

    def _decode(self):
        a = ["decode", self.v_dkind.get()]
        if self.v_dhex.get().strip():
            a += ["--hex-data", self.v_dhex.get().strip()]
        elif self.v_dfile.get().strip():
            a.append(self.v_dfile.get().strip())
        else:
            messagebox.showinfo("Decode", "Choose a file or enter hex bytes.")
            return
        if self.v_dvendor.get().strip():
            a += ["--vendor", self.v_dvendor.get().strip()]
        if self.v_dproduct.get().strip():
            a += ["--product", self.v_dproduct.get().strip()]
        self.run(a, device=False)


def main():
    App().mainloop()


if __name__ == "__main__":
    main()

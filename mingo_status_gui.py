#!/usr/bin/env python3
import os
import re
import subprocess
import threading
import time
import argparse
import tkinter as tk
from tkinter import messagebox, ttk


CONFIG_PATH = os.path.expanduser("~/.ssh/config")
DEFAULT_PROCESS = "dabc_exe"
DEFAULT_INTERVAL_S = 5
RESTART_COOLDOWN_S = 60


def parse_mingo_hosts():
    hosts = []
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line.lower().startswith("host "):
                    continue
                names = line.split()[1:]
                for name in names:
                    if re.match(r"^mingo0\d+$", name):
                        hosts.append(name)
    except OSError:
        return []
    return sorted(set(hosts))


def check_host(host, process_name):
    if not process_name:
        return "red", "no process name set"
    cmd = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "ConnectionAttempts=1",
        host,
        "pgrep",
        "-f",
        process_name,
    ]
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError as exc:
        return "red", f"ssh error: {exc}"
    if result.returncode == 0:
        return "green", "connected, measurement running"
    if result.returncode == 1:
        return "orange", "connected, no measurement"
    return "red", f"ssh/pgrep error (rc={result.returncode})"


class HostRow:
    def __init__(self, parent, host, restart_callback):
        self.host = host
        self.frame = ttk.Frame(parent)
        self.canvas = tk.Canvas(self.frame, width=16, height=16, highlightthickness=0)
        self.indicator = self.canvas.create_oval(2, 2, 14, 14, fill="red", outline="")
        self.host_label = ttk.Label(self.frame, text=host, width=10)
        self.status_label = ttk.Label(self.frame, text="checking...")
        self.time_label = ttk.Label(self.frame, text="")
        self.restart_button = ttk.Button(
            self.frame, text="Restart tunnel", command=lambda: restart_callback(host)
        )

        self.canvas.grid(row=0, column=0, padx=(0, 6))
        self.host_label.grid(row=0, column=1, sticky="w")
        self.status_label.grid(row=0, column=2, sticky="w", padx=(8, 0))
        self.time_label.grid(row=0, column=3, sticky="w", padx=(8, 0))
        self.restart_button.grid(row=0, column=4, sticky="e", padx=(10, 0))
        self.frame.grid_columnconfigure(2, weight=1)

    def grid(self, row):
        self.frame.grid(row=row, column=0, sticky="ew", pady=2)

    def set_status(self, color, text):
        self.canvas.itemconfigure(self.indicator, fill=color)
        self.status_label.configure(text=text)
        self.time_label.configure(text=time.strftime("%H:%M:%S"))


class App:
    def __init__(self, root, hosts=None, process=None, interval=None):
        self.root = root
        self.root.title("miniTRASGO Status Monitor")
        self.root.resizable(False, False)

        self.process_var = tk.StringVar(value=process or DEFAULT_PROCESS)
        self.interval_var = tk.StringVar(
            value=str(interval if interval is not None else DEFAULT_INTERVAL_S)
        )
        self.hosts_var = tk.StringVar(value=hosts or "")

        self.checking = False
        self.after_id = None
        self.last_restart_at = {}

        self.host_rows = []
        self.hosts = []
        self.auto_restart_var = tk.BooleanVar(value=False)

        self._build_ui()
        self._load_default_hosts()
        self.apply_settings()

    def _build_ui(self):
        controls = ttk.Frame(self.root, padding=10)
        status_frame = ttk.Frame(self.root, padding=(10, 0, 10, 10))

        ttk.Label(controls, text="Hosts (comma-separated):").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Entry(controls, textvariable=self.hosts_var, width=40).grid(
            row=0, column=1, sticky="w"
        )
        ttk.Label(controls, text="Process:").grid(row=1, column=0, sticky="w")
        ttk.Entry(controls, textvariable=self.process_var, width=20).grid(
            row=1, column=1, sticky="w"
        )
        ttk.Label(controls, text="Interval (s):").grid(row=2, column=0, sticky="w")
        ttk.Entry(controls, textvariable=self.interval_var, width=10).grid(
            row=2, column=1, sticky="w"
        )

        ttk.Button(controls, text="Apply", command=self.apply_settings).grid(
            row=3, column=0, pady=(6, 0), sticky="w"
        )
        ttk.Button(controls, text="Check now", command=self.check_now).grid(
            row=3, column=1, pady=(6, 0), sticky="w"
        )
        ttk.Checkbutton(
            controls,
            text="Auto-restart tunnel on red (1/min)",
            variable=self.auto_restart_var,
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(6, 0))
        # ttk.Button(controls, text="Help", command=self.show_help).grid(
        #     row=3, column=2, pady=(6, 0), sticky="w", padx=(10, 0),
        # )

        self.status_frame = status_frame
        controls.grid(row=0, column=0, sticky="ew")
        status_frame.grid(row=1, column=0, sticky="ew")

    def show_help(self):
        message = (
            "Checks SSH connectivity to mingo0X hosts and whether the analysis "
            "process is running.\n\n"
            "Colors:\n"
            "- Red: SSH failed or error\n"
            "- Orange: SSH ok, process not found\n"
            "- Green: SSH ok, process found\n\n"
            "Tips:\n"
            "- Hosts: comma-separated SSH aliases (from ~/.ssh/config)\n"
            "- Process: match against full command (default dabc_exe)\n"
            "- Interval: seconds between checks (min 2s)"
        )
        messagebox.showinfo("Help", message, parent=self.root)

    def _load_default_hosts(self):
        if self.hosts_var.get().strip():
            return
        hosts = parse_mingo_hosts()
        if hosts:
            self.hosts_var.set(", ".join(hosts))

    def _parse_hosts(self):
        raw = self.hosts_var.get().strip()
        if not raw:
            return []
        return [h.strip() for h in raw.split(",") if h.strip()]

    def _rebuild_rows(self, hosts):
        for row in self.host_rows:
            row.frame.destroy()
        self.host_rows = []
        for i, host in enumerate(hosts):
            row = HostRow(self.status_frame, host, self.restart_tunnel_async)
            row.grid(i)
            self.host_rows.append(row)
        self.status_frame.grid_columnconfigure(0, weight=1)
        self.last_restart_at = {host: 0 for host in hosts}

    def apply_settings(self):
        hosts = self._parse_hosts()
        if not hosts:
            hosts = parse_mingo_hosts()
        if not hosts:
            hosts = ["mingo01"]

        if hosts != self.hosts:
            self.hosts = hosts
            self._rebuild_rows(hosts)

        if self.after_id is not None:
            self.root.after_cancel(self.after_id)
            self.after_id = None

        self.check_now()

    def _get_interval_ms(self):
        try:
            interval = int(self.interval_var.get().strip())
        except ValueError:
            interval = DEFAULT_INTERVAL_S
        if interval < 2:
            interval = 2
        return interval * 1000

    def check_now(self):
        if self.checking:
            return
        self.checking = True
        thread = threading.Thread(target=self._do_checks, daemon=True)
        thread.start()

    def _do_checks(self):
        process_name = self.process_var.get().strip()
        results = {}
        for host in self.hosts:
            results[host] = check_host(host, process_name)
        self.root.after(0, lambda: self._apply_results(results))

    def _apply_results(self, results):
        for row in self.host_rows:
            color, text = results.get(row.host, ("red", "no result"))
            row.set_status(color, text)
            if color == "red" and self.auto_restart_var.get():
                self._maybe_restart_tunnel(row.host)
        self.checking = False
        self.after_id = self.root.after(self._get_interval_ms(), self.check_now)

    def _maybe_restart_tunnel(self, host):
        now = time.time()
        last = self.last_restart_at.get(host, 0)
        if now - last < RESTART_COOLDOWN_S:
            return
        self.last_restart_at[host] = now
        thread = threading.Thread(
            target=self.restart_tunnel, args=(host, False), daemon=True
        )
        thread.start()

    def restart_tunnel_async(self, host):
        self.last_restart_at[host] = time.time()
        thread = threading.Thread(
            target=self.restart_tunnel, args=(host, True), daemon=True
        )
        thread.start()

    def restart_tunnel(self, host, notify=True):
        patterns = [f"autossh.*{host}", "autossh.*lipana"]
        for pattern in patterns:
            try:
                pids = subprocess.check_output(
                    ["pgrep", "-f", pattern], text=True
                ).strip()
            except subprocess.CalledProcessError:
                pids = ""
            except OSError as exc:
                if notify:
                    self.root.after(
                        0,
                        lambda: messagebox.showerror(
                            "Restart tunnel",
                            f"Error running pgrep: {exc}",
                            parent=self.root,
                        ),
                    )
                return

            if not pids:
                continue

            for pid in pids.splitlines():
                subprocess.run(["kill", pid], check=False)
            if notify:
                self.root.after(
                    0,
                    lambda: messagebox.showinfo(
                        "Restart tunnel",
                        f"Closing the tunnel for {host}... It will reopen in less than a minute.",
                        parent=self.root,
                    ),
                )
            return

        if notify:
            self.root.after(
                0,
                lambda: messagebox.showinfo(
                    "Restart tunnel",
                    f"No autossh process found for {host}.",
                    parent=self.root,
                ),
            )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "GUI monitor for mingo0X hosts that checks SSH connectivity and whether "
            "the analysis process is running."
        )
    )
    parser.add_argument(
        "--hosts",
        default="",
        help="Comma-separated SSH aliases (default: auto-detect mingo0X from ~/.ssh/config)",
    )
    parser.add_argument(
        "--process",
        default=DEFAULT_PROCESS,
        help=f"Process match for pgrep -f (default: {DEFAULT_PROCESS})",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_INTERVAL_S,
        help=f"Seconds between checks (min 2s, default: {DEFAULT_INTERVAL_S})",
    )
    args = parser.parse_args()

    root = tk.Tk()
    ttk.Style().theme_use("clam")
    app = App(root, hosts=args.hosts, process=args.process, interval=args.interval)
    root.mainloop()


if __name__ == "__main__":
    main()

"""
ESI Checker — GUI Launcher
Run this file to start/stop the server from a desktop window.
No extra packages required (uses built-in tkinter).
"""
import os
import subprocess
import sys
import threading
import webbrowser
import tkinter as tk
from tkinter import scrolledtext, font

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PYTHON = sys.executable
APP_URL = "http://localhost:8000"

# ---------------------------------------------------------------------------
# Colours (matches the web app dark theme)
# ---------------------------------------------------------------------------
BG        = "#0d0d1a"
SURFACE   = "#141428"
SURFACE2  = "#1e1e38"
BORDER    = "#2a2a50"
ACCENT    = "#4a90d9"
TEXT      = "#c8ccd4"
TEXT_DIM  = "#6b7280"
GREEN     = "#22c55e"
RED       = "#ef4444"
ORANGE    = "#f97316"


class Launcher(tk.Tk):
    def __init__(self):
        super().__init__()

        self._proc: subprocess.Popen | None = None
        self._log_thread: threading.Thread | None = None
        self._running = False

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # -----------------------------------------------------------------------
    # UI construction
    # -----------------------------------------------------------------------

    def _build_ui(self):
        self.title("ESI Checker — Launcher")
        self.configure(bg=BG)
        self.resizable(False, False)

        # --- Header ---
        header = tk.Frame(self, bg=SURFACE, pady=14)
        header.pack(fill="x")

        tk.Label(
            header, text="🛡  ESI Checker",
            bg=SURFACE, fg=ACCENT,
            font=("Segoe UI", 16, "bold"), padx=20,
        ).pack(side="left")

        tk.Label(
            header, text="Recruitment Platform",
            bg=SURFACE, fg=TEXT_DIM,
            font=("Segoe UI", 10), padx=0,
        ).pack(side="left")

        # --- Status bar ---
        status_frame = tk.Frame(self, bg=SURFACE2, pady=10, padx=20)
        status_frame.pack(fill="x")

        tk.Label(
            status_frame, text="Server status:",
            bg=SURFACE2, fg=TEXT_DIM,
            font=("Segoe UI", 9),
        ).pack(side="left")

        self._status_dot = tk.Label(
            status_frame, text="●",
            bg=SURFACE2, fg=RED,
            font=("Segoe UI", 14),
        )
        self._status_dot.pack(side="left", padx=(6, 2))

        self._status_label = tk.Label(
            status_frame, text="Stopped",
            bg=SURFACE2, fg=RED,
            font=("Segoe UI", 9, "bold"),
        )
        self._status_label.pack(side="left")

        self._url_label = tk.Label(
            status_frame, text="",
            bg=SURFACE2, fg=ACCENT,
            font=("Segoe UI", 9, "underline"),
            cursor="hand2",
        )
        self._url_label.pack(side="left", padx=(16, 0))
        self._url_label.bind("<Button-1>", lambda _: self._open_browser())

        # --- Buttons ---
        btn_frame = tk.Frame(self, bg=BG, pady=14, padx=20)
        btn_frame.pack(fill="x")

        self._start_btn = self._make_btn(
            btn_frame, "▶  Start Server", ACCENT, self._start_server
        )
        self._start_btn.pack(side="left", padx=(0, 8))

        self._stop_btn = self._make_btn(
            btn_frame, "■  Stop Server", RED, self._stop_server, state="disabled"
        )
        self._stop_btn.pack(side="left", padx=(0, 8))

        self._browser_btn = self._make_btn(
            btn_frame, "🌐  Open Browser", GREEN, self._open_browser, state="disabled"
        )
        self._browser_btn.pack(side="left", padx=(0, 8))

        # --- Log output ---
        log_frame = tk.Frame(self, bg=BG, padx=20, pady=0)
        log_frame.pack(fill="both", expand=True)

        tk.Label(
            log_frame, text="SERVER LOG",
            bg=BG, fg=TEXT_DIM,
            font=("Segoe UI", 8),
        ).pack(anchor="w")

        self._log = scrolledtext.ScrolledText(
            log_frame,
            width=74, height=18,
            bg=SURFACE, fg=TEXT,
            insertbackground=TEXT,
            font=("Consolas", 9),
            relief="flat",
            bd=0,
            state="disabled",
        )
        self._log.pack(fill="both", expand=True, pady=(4, 16))

        # colour tags
        self._log.tag_config("info",    foreground=TEXT_DIM)
        self._log.tag_config("access",  foreground=ACCENT)
        self._log.tag_config("error",   foreground=RED)
        self._log.tag_config("warning", foreground=ORANGE)
        self._log.tag_config("start",   foreground=GREEN)

        # Window size
        self.geometry("680x500")
        self._log_line("ESI Checker launcher ready. Click ▶ Start Server to begin.\n", "info")

    # -----------------------------------------------------------------------
    # Button factory
    # -----------------------------------------------------------------------

    def _make_btn(self, parent, text, colour, cmd, state="normal"):
        btn = tk.Button(
            parent,
            text=text,
            bg=colour,
            fg="#ffffff",
            activebackground=colour,
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            padx=14,
            pady=7,
            font=("Segoe UI", 9, "bold"),
            cursor="hand2",
            command=cmd,
            state=state,
            disabledforeground="#555577",
        )
        return btn

    # -----------------------------------------------------------------------
    # Server control
    # -----------------------------------------------------------------------

    def _start_server(self):
        if self._running:
            return

        self._log_line("Starting server...\n", "start")
        self._proc = subprocess.Popen(
            [PYTHON, "-m", "uvicorn", "app:app",
             "--host", "0.0.0.0", "--port", "8000"],
            cwd=BASE_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        self._running = True
        self._set_status(True)

        # Stream logs in background thread
        self._log_thread = threading.Thread(
            target=self._stream_logs, daemon=True
        )
        self._log_thread.start()

    def _stop_server(self):
        if self._proc and self._running:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._running = False
        self._proc = None
        self._set_status(False)
        self._log_line("Server stopped.\n", "error")

    def _stream_logs(self):
        """Read subprocess stdout and append to the log widget."""
        try:
            for line in self._proc.stdout:
                self._classify_log(line)
        except Exception:
            pass
        finally:
            if self._running:
                # Process died unexpectedly
                self._running = False
                self.after(0, lambda: self._set_status(False))
                self.after(0, lambda: self._log_line("Server process ended.\n", "error"))

    def _classify_log(self, line: str):
        tag = "info"
        lo = line.lower()
        if "error" in lo or "exception" in lo or "traceback" in lo:
            tag = "error"
        elif "warning" in lo or "warn" in lo:
            tag = "warning"
        elif "http/1" in lo:
            tag = "access"
        elif "started" in lo or "running on" in lo or "uvicorn" in lo:
            tag = "start"
        self.after(0, lambda l=line, t=tag: self._log_line(l, t))

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _set_status(self, running: bool):
        if running:
            self._status_dot.config(fg=GREEN)
            self._status_label.config(text="Running", fg=GREEN)
            self._url_label.config(text=APP_URL)
            self._start_btn.config(state="disabled")
            self._stop_btn.config(state="normal")
            self._browser_btn.config(state="normal")
        else:
            self._status_dot.config(fg=RED)
            self._status_label.config(text="Stopped", fg=RED)
            self._url_label.config(text="")
            self._start_btn.config(state="normal")
            self._stop_btn.config(state="disabled")
            self._browser_btn.config(state="disabled")

    def _log_line(self, text: str, tag: str = "info"):
        self._log.config(state="normal")
        self._log.insert("end", text, tag)
        self._log.see("end")
        self._log.config(state="disabled")

    def _open_browser(self):
        webbrowser.open(APP_URL)

    def _on_close(self):
        self._stop_server()
        self.destroy()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    os.chdir(BASE_DIR)
    app = Launcher()
    app.mainloop()

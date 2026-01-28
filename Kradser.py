# Kradser.py
# GUI: CSV (kolonne B, fra række 2) vs mappefilnavne (PDF)
# + e-conomic: find voucher via "Ref YY NNNN" og upload PDF som bilag.
#
# Krav: Kun standardbibliotek (tkinter, urllib, csv, json, os, re, etc.)
# Kør: python Kradser.py

from __future__ import annotations

import csv
import json
import mimetypes
import re
import sys
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import tkinter as tk
from tkinter import ttk, filedialog, messagebox


# -----------------------------
# Parsing / matching (STRICT 1-1)
# -----------------------------

REF_REGEX = re.compile(
    r"""
    (?<![0-9A-Za-z])    # ikke bogstav/tal lige før
    ref                 # 'ref'
    (?![0-9A-Za-z])     # ikke bogstav/tal lige efter (underscore er OK)
    [^0-9A-Za-z]*       # separators (space, _, -, #, etc.)
    (?P<yy>\d{2})       # 2-digit year
    [^0-9A-Za-z]*       # separators
    (?P<num>\d{3,8})    # voucher number
    (?!\d)              # stop hvis næste tegn er et ciffer (undgå at sluge længere tal)
    """,
    re.IGNORECASE | re.VERBOSE,
)



def extract_ref_key(text: str) -> Optional[str]:
    """
    Extract strict key: 'ref {yy} {num}' from arbitrary text.
    Example matches:
      'Ref 24 1700'
      'Ref ´24 #1700.pdf'
    Returns normalized lowercase key or None.
    """
    if not text:
        return None
    m = REF_REGEX.search(text)
    if not m:
        return None
    yy = m.group("yy")
    num = m.group("num").lstrip("0") or "0"
    return f"ref {yy.lower()} {num}"


def accounting_year_from_key(key: str) -> Optional[int]:
    """
    key = 'ref yy num' -> accountingYear = 2000+yy (heuristic)
    """
    m = re.match(r"^ref\s+(\d{2})\s+(\d+)$", key.strip().lower())
    if not m:
        return None
    yy = int(m.group(1))
    return 2000 + yy if yy <= 79 else 1900 + yy


def voucher_number_from_key(key: str) -> Optional[int]:
    m = re.match(r"^ref\s+(\d{2})\s+(\d+)$", key.strip().lower())
    if not m:
        return None
    return int(m.group(2))


def smart_csv_dialect(sample: str) -> csv.Dialect:
    """
    Try to sniff delimiter; fallback to semicolon (common DK exports) then comma.
    """
    try:
        return csv.Sniffer().sniff(sample, delimiters=";,\t")
    except Exception:
        class _D(csv.Dialect):
            delimiter = ";"
            quotechar = '"'
            doublequote = True
            skipinitialspace = True
            lineterminator = "\n"
            quoting = csv.QUOTE_MINIMAL
        return _D()


def read_csv_col_refs(
    csv_path: Path,
    col_index_zero_based: int = 1,
    start_row_1_based: int = 2
) -> List[str]:
    """
    Read refs from a CSV column (e.g. B => index 1), starting at row 2.
    Returns list of keys ('ref yy num') found in that column.
    """
    raw = csv_path.read_text(encoding="utf-8", errors="replace")
    dialect = smart_csv_dialect(raw[:4096])

    keys: List[str] = []
    with csv_path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f, dialect)
        for i, row in enumerate(reader, start=1):
            if i < start_row_1_based:
                continue
            if col_index_zero_based >= len(row):
                continue
            cell = row[col_index_zero_based]
            key = extract_ref_key(cell)
            if key:
                keys.append(key)
    return keys


def list_folder_pdf_refs(folder: Path) -> Tuple[Dict[str, Path], Dict[str, List[Path]]]:
    """
    Non-recursive: mapping key -> first PDF path.
    Also returns duplicates mapping (key -> list of paths) if same key appears multiple times.
    """
    out: Dict[str, Path] = {}
    dups: Dict[str, List[Path]] = {}
    if not folder.exists():
        return out, dups

    temp: Dict[str, List[Path]] = {}
    for p in sorted(folder.iterdir()):
        if not p.is_file():
            continue
        if p.suffix.lower() != ".pdf":
            continue
        key = extract_ref_key(p.stem) or extract_ref_key(p.name)
        if not key:
            continue
        temp.setdefault(key, []).append(p)

    for key, paths in temp.items():
        out[key] = paths[0]
        if len(paths) > 1:
            dups[key] = paths

    return out, dups


# -----------------------------
# e-conomic REST client (journals/vouchers/attachments)
# -----------------------------

ECONOMIC_BASE = "https://restapi.e-conomic.com"


@dataclass
class EconomicTokens:
    app_secret_token: str
    agreement_grant_token: str


class EconomicClient:
    def __init__(self, tokens: EconomicTokens, base_url: str = ECONOMIC_BASE, timeout: int = 30):
        self.tokens = tokens
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _headers(self, content_type: Optional[str] = "application/json") -> Dict[str, str]:
        h = {
            "X-AppSecretToken": self.tokens.app_secret_token.strip(),
            "X-AgreementGrantToken": self.tokens.agreement_grant_token.strip(),
            "Accept": "application/json",
        }
        if content_type:
            h["Content-Type"] = content_type
        return h

    def _request(
        self,
        method: str,
        path: str,
        query: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
    ) -> Tuple[int, bytes, Dict[str, str]]:
        url = f"{self.base_url}{path}"
        if query:
            url = f"{url}?{urllib.parse.urlencode(query)}"

        req = urllib.request.Request(url=url, data=body, method=method)
        for k, v in (headers or {}).items():
            req.add_header(k, v)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = resp.read()
                return resp.status, data, dict(resp.headers.items())
        except urllib.error.HTTPError as e:
            data = e.read() if e.fp else b""
            return e.code, data, dict(e.headers.items()) if e.headers else {}
        except Exception as e:
            raise RuntimeError(f"Netværksfejl: {e}") from e

    def test_connection(self) -> Tuple[bool, str]:
        status, data, _ = self._request(
            "GET",
            "/self",
            headers=self._headers(content_type=None),
        )
        if status == 200:
            return True, "OK: Forbindelse virker (/self)."
        return False, f"Fejl: status {status}. Svar: {data[:300]!r}"

    def get_journals(self) -> List[int]:
        status, data, _ = self._request("GET", "/journals", headers=self._headers(content_type=None))
        if status != 200:
            raise RuntimeError(f"Kunne ikke hente journals (status {status}): {data[:400]!r}")
        payload = json.loads(data.decode("utf-8", errors="replace"))
        items = payload.get("collection", []) if isinstance(payload, dict) else payload
        journal_numbers: List[int] = []
        for it in items:
            jn = it.get("journalNumber")
            if isinstance(jn, int):
                journal_numbers.append(jn)
        return journal_numbers

    def voucher_exists_in_journal(self, journal_number: int, accounting_year: int, voucher_number: int) -> bool:
        path = f"/journals/{journal_number}/vouchers/{accounting_year}-{voucher_number}"
        status, _, _ = self._request("GET", path, headers=self._headers(content_type=None))
        return status == 200

    def voucher_attachment_exists(self, journal_number: int, accounting_year: int, voucher_number: int) -> bool:
        path = f"/journals/{journal_number}/vouchers/{accounting_year}-{voucher_number}/attachment"
        status, _, _ = self._request("GET", path, headers=self._headers(content_type=None))
        return status == 200

    def upload_voucher_attachment_file(
        self,
        journal_number: int,
        accounting_year: int,
        voucher_number: int,
        file_path: Path,
        method: str = "POST",
    ) -> Tuple[bool, str]:
        """
        Upload file as multipart/form-data to:
          POST /journals/:journalNumber/vouchers/:accountingYear-voucherNumber/attachment/file
        method can be POST (create/replace) or PATCH (append pages).
        """
        path = f"/journals/{journal_number}/vouchers/{accounting_year}-{voucher_number}/attachment/file"

        boundary = "----KradserBoundary" + uuid.uuid4().hex
        ctype = f"multipart/form-data; boundary={boundary}"

        mime = mimetypes.guess_type(str(file_path))[0] or "application/pdf"
        filename = file_path.name
        file_bytes = file_path.read_bytes()

        parts: List[bytes] = []
        parts.append(f"--{boundary}\r\n".encode("utf-8"))
        parts.append(f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode("utf-8"))
        parts.append(f"Content-Type: {mime}\r\n\r\n".encode("utf-8"))
        parts.append(file_bytes)
        parts.append(b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode("utf-8"))

        body = b"".join(parts)

        status, resp_data, _ = self._request(
            method,
            path,
            headers=self._headers(content_type=ctype),
            body=body,
        )

        if status in (200, 201, 204):
            return True, f"Upload OK (status {status})"
        snippet = resp_data.decode("utf-8", errors="replace")[:600]
        return False, f"Upload fejlede (status {status}): {snippet}"

    def find_journal_for_voucher(self, accounting_year: int, voucher_number: int, journals: List[int]) -> Optional[int]:
        for jn in journals:
            if self.voucher_exists_in_journal(jn, accounting_year, voucher_number):
                return jn
        return None


# -----------------------------
# Config persistence (tokens)
# -----------------------------

def config_path() -> Path:
    try:
        base = Path(__file__).resolve().parent
    except Exception:
        base = Path.cwd()
    return base / "kradser_config.json"


def load_config() -> Dict[str, str]:
    p = config_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_config(cfg: Dict[str, str]) -> None:
    p = config_path()
    p.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")


# -----------------------------
# GUI
# -----------------------------

class App(ttk.Frame):
    def __init__(self, master: tk.Tk):
        super().__init__(master)
        self.master = master

        self.csv_path_var = tk.StringVar()
        self.folder_path_var = tk.StringVar()

        self.col_var = tk.IntVar(value=2)       # Column B (1-based) default
        self.start_row_var = tk.IntVar(value=2)

        self.app_secret_var = tk.StringVar()
        self.agreement_grant_var = tk.StringVar()

        self.skip_if_attachment_exists_var = tk.BooleanVar(value=True)
        self.use_patch_append_var = tk.BooleanVar(value=False)
        self.dry_run_var = tk.BooleanVar(value=True)  # NEW: safe default

        self.status_var = tk.StringVar(value="Klar.")

        self.csv_keys: List[str] = []
        self.folder_map: Dict[str, Path] = {}
        self.duplicates_in_folder: Dict[str, List[Path]] = {}

        self._build_ui()
        self._load_tokens()

    def _build_ui(self) -> None:
        self.master.title("Kradser – CSV vs PDF + e-conomic bilagsupload")
        self.master.geometry("1100x720")
        self.pack(fill="both", expand=True)

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # --- Top input ---
        top = ttk.LabelFrame(self, text="1) Input")
        top.pack(fill="x", padx=12, pady=10)

        row1 = ttk.Frame(top)
        row1.pack(fill="x", padx=10, pady=6)
        ttk.Label(row1, text="CSV fil:").pack(side="left")
        ttk.Entry(row1, textvariable=self.csv_path_var).pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(row1, text="Vælg…", command=self.choose_csv).pack(side="left")

        row2 = ttk.Frame(top)
        row2.pack(fill="x", padx=10, pady=6)
        ttk.Label(row2, text="Mappe med PDF’er:").pack(side="left")
        ttk.Entry(row2, textvariable=self.folder_path_var).pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(row2, text="Vælg…", command=self.choose_folder).pack(side="left")

        row3 = ttk.Frame(top)
        row3.pack(fill="x", padx=10, pady=6)
        ttk.Label(row3, text="CSV-kolonne (1-based):").pack(side="left")
        ttk.Spinbox(row3, from_=1, to=200, textvariable=self.col_var, width=6).pack(side="left", padx=(6, 18))
        ttk.Label(row3, text="Start-række (1-based):").pack(side="left")
        ttk.Spinbox(row3, from_=1, to=999999, textvariable=self.start_row_var, width=8).pack(side="left", padx=6)
        ttk.Button(row3, text="Scan & sammenlign", command=self.scan_and_compare).pack(side="right")

        # --- Middle split (results / e-conomic) ---
        mid = ttk.PanedWindow(self, orient="horizontal")
        mid.pack(fill="both", expand=True, padx=12, pady=8)

        # Left results pane
        left = ttk.LabelFrame(mid, text="2) Resultater (STRICT: ref YY NNNN)")
        mid.add(left, weight=3)

        res_top = ttk.Frame(left)
        res_top.pack(fill="both", expand=True, padx=10, pady=10)

        lf1 = ttk.LabelFrame(res_top, text="Findes i CSV men IKKE i mappe")
        lf1.pack(side="left", fill="both", expand=True, padx=(0, 8))
        lf2 = ttk.LabelFrame(res_top, text="Findes i mappe men IKKE i CSV")
        lf2.pack(side="left", fill="both", expand=True)

        # Scrollable list 1
        frame1 = ttk.Frame(lf1)
        frame1.pack(fill="both", expand=True, padx=6, pady=6)
        sb1 = ttk.Scrollbar(frame1, orient="vertical")
        sb1.pack(side="right", fill="y")
        self.list_csv_not_in_folder = tk.Listbox(frame1, height=14, yscrollcommand=sb1.set)
        self.list_csv_not_in_folder.pack(side="left", fill="both", expand=True)
        sb1.config(command=self.list_csv_not_in_folder.yview)

        # Scrollable list 2
        frame2 = ttk.Frame(lf2)
        frame2.pack(fill="both", expand=True, padx=6, pady=6)
        sb2 = ttk.Scrollbar(frame2, orient="vertical")
        sb2.pack(side="right", fill="y")
        self.list_folder_not_in_csv = tk.Listbox(frame2, height=14, yscrollcommand=sb2.set)
        self.list_folder_not_in_csv.pack(side="left", fill="both", expand=True)
        sb2.config(command=self.list_folder_not_in_csv.yview)

        # Right e-conomic pane
        right = ttk.LabelFrame(mid, text="3) e-conomic (REST API)")
        mid.add(right, weight=2)

        econ = ttk.Frame(right)
        econ.pack(fill="both", expand=True, padx=10, pady=10)

        ttk.Label(econ, text="App Secret Token:").grid(row=0, column=0, sticky="w")
        ttk.Entry(econ, textvariable=self.app_secret_var, show="•").grid(row=0, column=1, sticky="ew", padx=6, pady=4)

        ttk.Label(econ, text="Agreement Grant Token:").grid(row=1, column=0, sticky="w")
        ttk.Entry(econ, textvariable=self.agreement_grant_var, show="•").grid(row=1, column=1, sticky="ew", padx=6, pady=4)

        btns = ttk.Frame(econ)
        btns.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(6, 10))
        ttk.Button(btns, text="Gem tokens", command=self.save_tokens).pack(side="left")
        ttk.Button(btns, text="Test forbindelse", command=self.test_economic).pack(side="left", padx=8)

        ttk.Separator(econ).grid(row=3, column=0, columnspan=2, sticky="ew", pady=8)

        ttk.Checkbutton(
            econ,
            text="Skip hvis voucher allerede har bilag (sikker default)",
            variable=self.skip_if_attachment_exists_var
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=4)

        ttk.Checkbutton(
            econ,
            text="Brug PATCH (append sider) i stedet for POST",
            variable=self.use_patch_append_var
        ).grid(row=5, column=0, columnspan=2, sticky="w", pady=4)

        ttk.Checkbutton(
            econ,
            text="Dry-run (ingen upload) — find journal + vis hvad der ville ske",
            variable=self.dry_run_var
        ).grid(row=6, column=0, columnspan=2, sticky="w", pady=4)

        ttk.Separator(econ).grid(row=7, column=0, columnspan=2, sticky="ew", pady=8)

        ttk.Button(
            econ,
            text="Upload/Preview PDF’er fra mappen (Ref YY NNNN)",
            command=self.upload_flow
        ).grid(row=8, column=0, columnspan=2, sticky="ew", pady=6)

        econ.columnconfigure(1, weight=1)

        # Bottom status bar
        bottom = ttk.Frame(self)
        bottom.pack(fill="x", padx=12, pady=(0, 10))
        ttk.Label(bottom, textvariable=self.status_var).pack(side="left")

    def _load_tokens(self) -> None:
        cfg = load_config()
        self.app_secret_var.set(cfg.get("app_secret_token", ""))
        self.agreement_grant_var.set(cfg.get("agreement_grant_token", ""))

    def set_status(self, msg: str) -> None:
        self.status_var.set(msg)
        self.master.update_idletasks()

    def choose_csv(self) -> None:
        p = filedialog.askopenfilename(
            title="Vælg CSV",
            filetypes=[("CSV", "*.csv"), ("Alle filer", "*.*")]
        )
        if p:
            self.csv_path_var.set(p)

    def choose_folder(self) -> None:
        p = filedialog.askdirectory(title="Vælg mappe med PDF’er")
        if p:
            self.folder_path_var.set(p)

    def scan_and_compare(self) -> None:
        csv_path = Path(self.csv_path_var.get().strip())
        folder = Path(self.folder_path_var.get().strip())

        if not csv_path.exists():
            messagebox.showerror("Fejl", "CSV-sti findes ikke.")
            return
        if not folder.exists():
            messagebox.showerror("Fejl", "Mappe-sti findes ikke.")
            return

        col = max(1, int(self.col_var.get()))
        start_row = max(1, int(self.start_row_var.get()))
        col_idx = col - 1

        self.set_status("Læser CSV…")
        try:
            self.csv_keys = read_csv_col_refs(csv_path, col_index_zero_based=col_idx, start_row_1_based=start_row)
        except Exception as e:
            messagebox.showerror("CSV-fejl", f"Kunne ikke læse CSV:\n{e}")
            return

        self.set_status("Scanner mappe…")
        try:
            self.folder_map, self.duplicates_in_folder = list_folder_pdf_refs(folder)
        except Exception as e:
            messagebox.showerror("Mappe-fejl", f"Kunne ikke scanne mappe:\n{e}")
            return

        csv_set = set(self.csv_keys)
        folder_set = set(self.folder_map.keys())

        csv_not_in_folder = sorted(csv_set - folder_set)
        folder_not_in_csv = sorted(folder_set - csv_set)

        self.list_csv_not_in_folder.delete(0, tk.END)
        self.list_folder_not_in_csv.delete(0, tk.END)

        for k in csv_not_in_folder:
            self.list_csv_not_in_folder.insert(tk.END, k)

        for k in folder_not_in_csv:
            self.list_folder_not_in_csv.insert(tk.END, f"{k}    -> {self.folder_map[k].name}")

        msg = (
            f"Done. CSV refs: {len(csv_set)} | Mappe refs: {len(folder_set)} | "
            f"CSV→mangler: {len(csv_not_in_folder)} | Mappe→mangler: {len(folder_not_in_csv)}"
        )
        if self.duplicates_in_folder:
            msg += f" | Duplicates i mappe: {len(self.duplicates_in_folder)}"
        self.set_status(msg)

        if self.duplicates_in_folder:
            lines = []
            for k, paths in list(self.duplicates_in_folder.items())[:15]:
                lines.append(f"{k}: " + ", ".join(p.name for p in paths))
            extra = "" if len(self.duplicates_in_folder) <= 15 else f"\n… (+{len(self.duplicates_in_folder)-15} flere)"
            messagebox.showwarning(
                "Dubletter i mappen",
                "Der er flere PDF’er med samme ref (STRICT 1-1). Programmet bruger den første.\n\n"
                + "\n".join(lines) + extra
            )

    def save_tokens(self) -> None:
        cfg = load_config()
        cfg["app_secret_token"] = self.app_secret_var.get().strip()
        cfg["agreement_grant_token"] = self.agreement_grant_var.get().strip()
        save_config(cfg)
        messagebox.showinfo("OK", f"Tokens gemt i:\n{config_path()}")

    def _client(self) -> EconomicClient:
        t = EconomicTokens(
            app_secret_token=self.app_secret_var.get().strip(),
            agreement_grant_token=self.agreement_grant_var.get().strip(),
        )
        if not t.app_secret_token or not t.agreement_grant_token:
            raise RuntimeError("Udfyld både App Secret Token og Agreement Grant Token.")
        return EconomicClient(tokens=t)

    def test_economic(self) -> None:
        try:
            self.set_status("Tester e-conomic forbindelse…")
            ok, msg = self._client().test_connection()
            self.set_status(msg)
            if ok:
                messagebox.showinfo("Forbindelse OK", msg)
            else:
                messagebox.showerror("Forbindelse fejlede", msg)
        except Exception as e:
            self.set_status("Fejl.")
            messagebox.showerror("Fejl", str(e))

    def upload_flow(self) -> None:
        folder = Path(self.folder_path_var.get().strip())
        if not folder.exists():
            messagebox.showerror("Fejl", "Vælg en gyldig mappe først.")
            return

        self.set_status("Forbereder kandidater…")
        folder_map, _dups = list_folder_pdf_refs(folder)
        if not folder_map:
            messagebox.showinfo("Ingen kandidater", "Ingen PDF’er i mappen med mønsteret 'Ref YY NNNN' blev fundet.")
            return

        candidates: List[Tuple[str, Path]] = sorted(folder_map.items(), key=lambda x: x[0])
        preview = "\n".join([f"{k} -> {p.name}" for k, p in candidates[:15]])
        if len(candidates) > 15:
            preview += f"\n… (+{len(candidates)-15} flere)"

        dry_run = bool(self.dry_run_var.get())
        mode_txt = "DRY-RUN (ingen upload)" if dry_run else "UPLOAD"

        if not messagebox.askyesno(
            f"Klar til {mode_txt}",
            f"Jeg fandt {len(candidates)} PDF’er med 'Ref YY NNNN' i filnavnet.\n\n"
            f"Eksempler:\n{preview}\n\n"
            f"Starte flowet nu?"
        ):
            self.set_status("Flow annulleret.")
            return

        try:
            client = self._client()
        except Exception as e:
            messagebox.showerror("Tokens mangler", str(e))
            return

        try:
            self.set_status("Henter journals…")
            journals = client.get_journals()
            if not journals:
                messagebox.showerror("Fejl", "Kunne ikke finde nogen journals på aftalen.")
                self.set_status("Fejl: ingen journals.")
                return
        except Exception as e:
            messagebox.showerror("Fejl", f"Kunne ikke hente journals:\n{e}")
            self.set_status("Fejl.")
            return

        yes_to_all = False
        uploaded = 0
        skipped_existing = 0
        not_found = 0
        failed = 0

        method = "PATCH" if self.use_patch_append_var.get() else "POST"
        skip_if_exists = bool(self.skip_if_attachment_exists_var.get())

        # Dry-run reporting
        report_lines: List[str] = []

        for idx, (key, pdf_path) in enumerate(candidates, start=1):
            accounting_year = accounting_year_from_key(key)
            voucher_number = voucher_number_from_key(key)
            if accounting_year is None or voucher_number is None:
                not_found += 1
                report_lines.append(f"NOT PARSED | {key} | {pdf_path.name}")
                continue

            if not yes_to_all:
                res = messagebox.askyesnocancel(
                    f"Bekræft ({mode_txt})",
                    f"[{idx}/{len(candidates)}]\n\n"
                    f"Ref: {key}\nFil: {pdf_path.name}\n\n"
                    f"{'Preview mapping?' if dry_run else f'Upload som bilag til voucher {accounting_year}-{voucher_number}?'}"
                )
                if res is None:
                    break
                if res is False:
                    report_lines.append(f"USER SKIP | {key} | {pdf_path.name}")
                    continue
                if messagebox.askyesno("Fortsæt", "Vil du sige 'Ja til alle' for resten?"):
                    yes_to_all = True

            try:
                self.set_status(f"Finder journal for {key}…")
                jn = client.find_journal_for_voucher(accounting_year, voucher_number, journals)
                if jn is None:
                    not_found += 1
                    report_lines.append(f"NOT FOUND | {key} | {accounting_year}-{voucher_number} | {pdf_path.name}")
                    continue

                if skip_if_exists:
                    self.set_status(f"Tjekker eksisterende bilag ({key})…")
                    if client.voucher_attachment_exists(jn, accounting_year, voucher_number):
                        skipped_existing += 1
                        report_lines.append(f"SKIP EXISTS | journal {jn} | {key} | {accounting_year}-{voucher_number} | {pdf_path.name}")
                        continue

                if dry_run:
                    report_lines.append(f"WOULD {'PATCH' if method=='PATCH' else 'POST'} | journal {jn} | {key} | {accounting_year}-{voucher_number} | {pdf_path.name}")
                    self.set_status(f"Dry-run OK: {key}")
                else:
                    self.set_status(f"Uploader ({method}) {key}…")
                    ok, msg = client.upload_voucher_attachment_file(
                        jn, accounting_year, voucher_number, pdf_path, method=method
                    )
                    if ok:
                        uploaded += 1
                        report_lines.append(f"UPLOADED | {method} | journal {jn} | {key} | {accounting_year}-{voucher_number} | {pdf_path.name}")
                    else:
                        failed += 1
                        report_lines.append(f"FAILED | {method} | journal {jn} | {key} | {accounting_year}-{voucher_number} | {pdf_path.name} | {msg}")
                        if not messagebox.askyesno("Upload fejlede", f"{key}\n{pdf_path.name}\n\n{msg}\n\nFortsæt med næste?"):
                            break

            except Exception as e:
                failed += 1
                report_lines.append(f"ERROR | {key} | {pdf_path.name} | {e}")
                if not messagebox.askyesno("Fejl", f"{key}\n{pdf_path.name}\n\n{e}\n\nFortsæt med næste?"):
                    break

            time.sleep(0.15)

        # Show summary + a preview of the report
        head_n = 40
        head = report_lines[:head_n]
        extra = ""
        if len(report_lines) > head_n:
            extra = f"\n… (+{len(report_lines)-head_n} flere linjer)"

        summary = (
            f"{'Dry-run færdig (ingen upload).' if dry_run else 'Upload færdig.'}\n\n"
            f"Would upload/Uploaded: {uploaded if not dry_run else sum(1 for l in report_lines if l.startswith('WOULD'))}\n"
            f"Skipped (havde allerede bilag): {skipped_existing}\n"
            f"Not found (voucher/journal ikke fundet / parse): {not_found}\n"
            f"Failed/Errors: {failed}\n\n"
            f"Log (første {min(head_n, len(report_lines))}):\n"
            + "\n".join(head)
            + extra
        )

        messagebox.showinfo("Resultat", summary)
        self.set_status(summary.splitlines()[0])


def main() -> None:
    root = tk.Tk()
    try:
        if sys.platform.startswith("win"):
            root.tk.call("tk", "scaling", 1.2)
    except Exception:
        pass

    _app = App(root)
    root.mainloop()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import csv
import re
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk

# Hvis din CSV ikke har kolonnenavnet "Tekst", så ret den her:
CSV_TEXT_COLUMN = "Tekst"

# Finder "ref <år> <nr>" inde i tekst, uanset specialtegn imellem.
REF_PATTERN = re.compile(r"\bref\b\D*(\d+)\D+(\d+)\b", re.IGNORECASE)


def normalize(s: str) -> str:
    """Case-insensitive + fjern specialtegn + kollaps spaces."""
    s = (s or "").casefold()
    s = re.sub(r"[^a-z0-9]+", " ", s)     # alt andet end [a-z0-9] -> space
    s = re.sub(r"\s+", " ", s).strip()
    return s


def canonical_ref(year: str, num: str) -> str:
    """Ens repræsentation af refs."""
    return normalize(f"ref {year} {num}")


def extract_ref(text: str) -> str | None:
    """Returnér canonical 'ref YY NNNN' fra tekst, ellers None."""
    m = REF_PATTERN.search(text or "")
    if not m:
        return None
    return canonical_ref(m.group(1), m.group(2))


def read_csv_refs(csv_path: Path) -> set[str]:
    """Læs CSV og udtræk refs (unikke) fra kolonnen CSV_TEXT_COLUMN."""
    def _read(enc: str) -> set[str]:
        with csv_path.open(newline="", encoding=enc) as f:
            sample = f.read(4096)
            f.seek(0)
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=";,\t")
            except Exception:
                dialect = csv.excel
                dialect.delimiter = ";"

            reader = csv.DictReader(f, dialect=dialect)
            fields = reader.fieldnames or []
            if CSV_TEXT_COLUMN not in fields:
                raise ValueError(f"CSV mangler kolonnen '{CSV_TEXT_COLUMN}'. Fundet: {fields}")

            out: set[str] = set()
            for row in reader:
                r = extract_ref(row.get(CSV_TEXT_COLUMN, "") or "")
                if r:
                    out.add(r)
            return out

    try:
        return _read("utf-8-sig")
    except UnicodeDecodeError:
        return _read("latin-1")


def folder_ref_stems(folder: Path, recursive: bool) -> set[str]:
    """
    Udtræk refs fra filnavne i mappen.
    Vi tager p.stem (uden extension), normaliserer, og forsøger at finde ref i navnet.
    """
    iterator = folder.rglob("*") if recursive else folder.glob("*")
    out: set[str] = set()

    for p in iterator:
        if not p.is_file():
            continue
        # macOS junk:
        if p.name.startswith("._"):
            continue
        if "__MACOSX" in p.parts:
            continue

        stem = p.stem
        r = extract_ref(stem)
        if r:
            out.add(r)

    return out


def export_to_txt(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


class App(ttk.Frame):
    def __init__(self, master: tk.Tk):
        super().__init__(master, padding=14)
        self.master = master

        self.csv_path = tk.StringVar(value="")
        self.folder_path = tk.StringVar(value="")
        self.recursive = tk.BooleanVar(value=False)

        self.status = tk.StringVar(value="Vælg en CSV-fil og en mappe.")
        self.count_csv = tk.StringVar(value="CSV refs: –")
        self.count_folder = tk.StringVar(value="Mappe refs: –")

        self.csv_missing_files: list[str] = []   # CSV -> folder (missing in folder)
        self.folder_extra_files: list[str] = []  # folder -> CSV (extra in folder)

        self._build()

    def _build(self) -> None:
        self.master.title("Kradser — Ref-match (to-vejs)")
        self.master.minsize(980, 600)

        style = ttk.Style()
        for theme in ("clam", "vista", "xpnative", "alt"):
            if theme in style.theme_names():
                style.theme_use(theme)
                break
        style.configure("Title.TLabel", font=("Segoe UI", 14, "bold"))
        style.configure("Sub.TLabel", font=("Segoe UI", 10))
        style.configure("Muted.TLabel", foreground="#666")
        style.configure("TButton", padding=(10, 6))

        self.grid(sticky="nsew")
        self.master.columnconfigure(0, weight=1)
        self.master.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        header = ttk.Frame(self)
        header.grid(row=0, column=0, sticky="ew")
        ttk.Label(header, text="Kradser — Ref-match (to-vejs)", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            header,
            text="Viser både: (1) refs i CSV der mangler filer, og (2) filer der ikke findes som refs i CSV.",
            style="Sub.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(2, 0))

        card = ttk.Frame(self, padding=12)
        card.grid(row=1, column=0, sticky="ew", pady=(12, 12))
        card.columnconfigure(1, weight=1)

        ttk.Label(card, text="CSV-fil:").grid(row=0, column=0, sticky="w")
        ttk.Entry(card, textvariable=self.csv_path).grid(row=0, column=1, sticky="ew", padx=8)
        ttk.Button(card, text="Vælg…", command=self.pick_csv).grid(row=0, column=2)

        ttk.Label(card, text="Mappe:").grid(row=1, column=0, sticky="w", pady=(10, 0))
        ttk.Entry(card, textvariable=self.folder_path).grid(row=1, column=1, sticky="ew", padx=8, pady=(10, 0))
        ttk.Button(card, text="Vælg…", command=self.pick_folder).grid(row=1, column=2, pady=(10, 0))

        ttk.Checkbutton(card, text="Rekursiv søgning i undermapper", variable=self.recursive)\
            .grid(row=2, column=1, sticky="w", pady=(10, 0))

        ttk.Button(card, text="Sammenlign", command=self.run_compare)\
            .grid(row=3, column=1, sticky="w", pady=(12, 0))

        # Meta counts
        meta = ttk.Frame(self)
        meta.grid(row=2, column=0, sticky="ew")
        ttk.Label(meta, textvariable=self.count_csv, style="Muted.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(meta, textvariable=self.count_folder, style="Muted.TLabel").grid(row=0, column=1, sticky="w", padx=16)

        # Tabs for results
        self.tabs = ttk.Notebook(self)
        self.tabs.grid(row=3, column=0, sticky="nsew", pady=(8, 0))
        self.rowconfigure(3, weight=1)

        self.tab_csv_to_folder = ttk.Frame(self.tabs, padding=8)
        self.tab_folder_to_csv = ttk.Frame(self.tabs, padding=8)
        self.tabs.add(self.tab_csv_to_folder, text="CSV → Mappe (mangler filer)")
        self.tabs.add(self.tab_folder_to_csv, text="Mappe → CSV (ekstra filer)")

        self.list_csv_to_folder = self._make_list(self.tab_csv_to_folder)
        self.list_folder_to_csv = self._make_list(self.tab_folder_to_csv)

        # Footer actions
        footer = ttk.Frame(self)
        footer.grid(row=4, column=0, sticky="ew", pady=(10, 0))
        ttk.Button(footer, text="Kopiér aktiv liste", command=self.copy_active).grid(row=0, column=0, sticky="w")
        ttk.Button(footer, text="Eksportér aktiv liste til .txt…", command=self.export_active).grid(row=0, column=1, sticky="w", padx=(10, 0))

        statusbar = ttk.Frame(self)
        statusbar.grid(row=5, column=0, sticky="ew", pady=(8, 0))
        ttk.Label(statusbar, textvariable=self.status).grid(row=0, column=0, sticky="w")

    def _make_list(self, parent: ttk.Frame) -> tk.Listbox:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)

        frame = ttk.Frame(parent)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        lb = tk.Listbox(frame)
        lb.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(frame, orient="vertical", command=lb.yview)
        sb.grid(row=0, column=1, sticky="ns")
        lb.configure(yscrollcommand=sb.set)
        return lb

    def pick_csv(self) -> None:
        p = filedialog.askopenfilename(title="Vælg CSV-fil", filetypes=[("CSV", "*.csv"), ("Alle filer", "*.*")])
        if p:
            self.csv_path.set(p)
            self.status.set("CSV valgt. Vælg nu en mappe.")

    def pick_folder(self) -> None:
        p = filedialog.askdirectory(title="Vælg mappe")
        if p:
            self.folder_path.set(p)
            self.status.set("Mappe valgt. Klar til sammenligning.")

    def run_compare(self) -> None:
        csv_p = Path(self.csv_path.get()).expanduser()
        folder_p = Path(self.folder_path.get()).expanduser()

        if not csv_p.exists() or not csv_p.is_file():
            messagebox.showerror("Fejl", "CSV-filen findes ikke. Vælg en gyldig CSV.")
            return
        if not folder_p.exists() or not folder_p.is_dir():
            messagebox.showerror("Fejl", "Mappen findes ikke. Vælg en gyldig mappe.")
            return

        try:
            csv_refs = read_csv_refs(csv_p)
            folder_refs = folder_ref_stems(folder_p, recursive=bool(self.recursive.get()))

            # Begge retninger:
            csv_minus_folder = sorted(csv_refs - folder_refs)     # i CSV, mangler fil
            folder_minus_csv = sorted(folder_refs - csv_refs)     # i mappe, mangler i CSV

            self.csv_missing_files = csv_minus_folder
            self.folder_extra_files = folder_minus_csv

            self.count_csv.set(f"CSV refs: {len(csv_refs)}")
            self.count_folder.set(f"Mappe refs: {len(folder_refs)}")

            # Render
            self._render_list(self.list_csv_to_folder, csv_minus_folder,
                              empty_msg="✅ Ingen refs i CSV mangler filer i mappen.")
            self._render_list(self.list_folder_to_csv, folder_minus_csv,
                              empty_msg="✅ Ingen ekstra filer (alt i mappen findes i CSV).")

            self.status.set("Færdig. Se fanerne for begge retninger.")
        except Exception as e:
            messagebox.showerror("Fejl", f"Noget gik galt:\n\n{e}")
            self.status.set("Fejl under sammenligning.")

    def _render_list(self, lb: tk.Listbox, items: list[str], empty_msg: str) -> None:
        lb.delete(0, tk.END)
        if items:
            for it in items:
                lb.insert(tk.END, it)
        else:
            lb.insert(tk.END, empty_msg)

    def _active_items(self) -> list[str]:
        idx = self.tabs.index(self.tabs.select())
        if idx == 0:
            return self.csv_missing_files
        return self.folder_extra_files

    def copy_active(self) -> None:
        items = self._active_items()
        if not items:
            messagebox.showinfo("Info", "Der er ingen items at kopiere i den aktive fane.")
            return
        txt = "\n".join(items)
        self.master.clipboard_clear()
        self.master.clipboard_append(txt)
        self.status.set("Kopieret aktiv liste til udklipsholder.")

    def export_active(self) -> None:
        items = self._active_items()
        if not items:
            messagebox.showinfo("Info", "Der er ingen items at eksportere i den aktive fane.")
            return
        p = filedialog.asksaveasfilename(
            title="Gem aktiv liste som .txt",
            defaultextension=".txt",
            filetypes=[("Tekstfil", "*.txt"), ("Alle filer", "*.*")]
        )
        if not p:
            return
        export_to_txt(Path(p), items)
        self.status.set("Eksporteret aktiv liste.")


def main() -> int:
    root = tk.Tk()
    App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

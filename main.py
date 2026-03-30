import hashlib
import json
import os
import platform
import shutil
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

import psutil
import requests

try:
    from scapy.all import sniff  # type: ignore
except Exception:
    sniff = None

try:
    import winreg
except Exception:
    winreg = None

APP_TITLE = "WinPE Security Center"
SETTINGS_FILE = Path("settings.json")
DEFAULT_SETTINGS = {
    "log_dir": str(Path.cwd() / "logs"),
    "theme": "light",
    "autosave_logs": True,
    "vt_api_key": os.environ.get("VT_API_KEY", ""),
}


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1380x900")
        self.minsize(1150, 740)

        self.settings = self.load_settings()
        self.log_dir = Path(self.settings["log_dir"])
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.session_log = self.log_dir / f"session_{datetime.now():%Y%m%d_%H%M%S}.txt"

        self.style = ttk.Style(self)
        self.apply_theme(self.settings["theme"])
        self.status_var = tk.StringVar(value="Готово")

        self.usb_seen = {}
        self.sniffer_running = False
        self.key_guard_running = False

        self.build_ui()
        self.bind_hotkeys()
        self.log("Приложение запущено", "info")

    # ---------- base ----------
    def load_settings(self):
        if SETTINGS_FILE.exists():
            try:
                data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
                return {**DEFAULT_SETTINGS, **data}
            except Exception:
                pass
        return DEFAULT_SETTINGS.copy()

    def save_settings(self):
        SETTINGS_FILE.write_text(json.dumps(self.settings, ensure_ascii=False, indent=2), encoding="utf-8")

    def apply_theme(self, theme):
        self.style.theme_use("clam")
        if theme == "dark":
            bg = "#202124"
            fg = "#e8eaed"
            self.configure(bg=bg)
            self.style.configure("TFrame", background=bg)
            self.style.configure("TLabelframe", background=bg, foreground=fg)
            self.style.configure("TLabelframe.Label", background=bg, foreground=fg)
            self.style.configure("TLabel", background=bg, foreground=fg)
            self.style.configure("TButton", background="#303134", foreground=fg)
            self.style.configure("Treeview", background="#2b2c2e", foreground=fg, fieldbackground="#2b2c2e")
        else:
            self.configure(bg="#f2f2f2")
            self.style.configure("TFrame", background="#f2f2f2")
            self.style.configure("TLabelframe", background="#f2f2f2")
            self.style.configure("TLabelframe.Label", background="#f2f2f2")
            self.style.configure("TLabel", background="#f2f2f2", foreground="#111")
            self.style.configure("TButton", background="#fff", foreground="#111")
            self.style.configure("Treeview", background="#fff", foreground="#111", fieldbackground="#fff")

    def log(self, message, level="info"):
        line = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {message}\n"
        if hasattr(self, "log_text"):
            self.log_text.insert("end", line, level)
            self.log_text.see("end")
        if self.settings.get("autosave_logs", True):
            with self.session_log.open("a", encoding="utf-8") as f:
                f.write(line)

    def set_status(self, txt):
        self.status_var.set(txt)
        self.log(txt, "info")

    def bind_hotkeys(self):
        self.bind_all("<Control-r>", lambda e: self.refresh_processes())
        self.bind_all("<Control-l>", lambda e: self.notebook.select(self.tab_logs))
        self.bind_all("<Control-f>", lambda e: self.notebook.select(self.tab_filemgr))
        self.bind_all("<Control-h>", lambda e: self.notebook.select(self.tab_internet))

    # ---------- UI ----------
    def build_ui(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=6, pady=6)

        self.tab_vt = ttk.Frame(self.notebook)
        self.tab_system = ttk.Frame(self.notebook)
        self.tab_logs = ttk.Frame(self.notebook)
        self.tab_recovery = ttk.Frame(self.notebook)
        self.tab_tasks = ttk.Frame(self.notebook)
        self.tab_filemgr = ttk.Frame(self.notebook)
        self.tab_internet = ttk.Frame(self.notebook)
        self.tab_usb = ttk.Frame(self.notebook)
        self.tab_key = ttk.Frame(self.notebook)
        self.tab_boot = ttk.Frame(self.notebook)
        self.tab_settings = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_vt, text="VirusTotal")
        self.notebook.add(self.tab_system, text="Системный анализ")
        self.notebook.add(self.tab_logs, text="Логи")
        self.notebook.add(self.tab_recovery, text="Восстановление")
        self.notebook.add(self.tab_tasks, text="Диспетчер задач")
        self.notebook.add(self.tab_filemgr, text="Файловый менеджер Pro")
        self.notebook.add(self.tab_internet, text="Интернет")
        self.notebook.add(self.tab_usb, text="USB")
        self.notebook.add(self.tab_key, text="Анти-кейлоггер")
        self.notebook.add(self.tab_boot, text="Boot")
        self.notebook.add(self.tab_settings, text="Настройки")

        self.build_vt_tab()
        self.build_system_tab()
        self.build_logs_tab()
        self.build_recovery_tab()
        self.build_tasks_tab()
        self.build_filemgr_tab()
        self.build_internet_tab()
        self.build_usb_tab()
        self.build_keylogger_tab()
        self.build_boot_tab()
        self.build_settings_tab()

        ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w").pack(fill="x", padx=6, pady=(0, 6))

    # ---------- Logs ----------
    def build_logs_tab(self):
        top = ttk.Frame(self.tab_logs)
        top.pack(fill="x", padx=8, pady=6)
        ttk.Button(top, text="Сохранить TXT", command=self.save_logs_manual).pack(side="left", padx=3)
        ttk.Button(top, text="Очистить", command=lambda: self.log_text.delete("1.0", "end")).pack(side="left", padx=3)

        self.log_text = ScrolledText(self.tab_logs, font=("Consolas", 10))
        self.log_text.pack(fill="both", expand=True, padx=8, pady=6)
        self.log_text.tag_config("clean", foreground="green")
        self.log_text.tag_config("malicious", foreground="red")
        self.log_text.tag_config("suspicious", foreground="orange")
        self.log_text.tag_config("unknown", foreground="goldenrod")
        self.log_text.tag_config("info", foreground="deepskyblue4")
        self.log_text.tag_config("error", foreground="red", underline=True)

    def save_logs_manual(self):
        p = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if p:
            Path(p).write_text(self.log_text.get("1.0", "end-1c"), encoding="utf-8")
            self.log(f"Логи сохранены: {p}", "clean")

    # ---------- VirusTotal ----------
    def build_vt_tab(self):
        one = ttk.Labelframe(self.tab_vt, text="Проверка файла")
        one.pack(fill="x", padx=8, pady=8)
        self.vt_file_var = tk.StringVar()
        ttk.Entry(one, textvariable=self.vt_file_var).pack(side="left", fill="x", expand=True, padx=5, pady=5)
        ttk.Button(one, text="Выбрать", command=self.pick_vt_file).pack(side="left", padx=4)
        ttk.Button(one, text="Скан", command=self.scan_one_file).pack(side="left", padx=4)

        fold = ttk.Labelframe(self.tab_vt, text="Рекурсивная проверка папки")
        fold.pack(fill="x", padx=8, pady=8)
        self.vt_dir_var = tk.StringVar()
        ttk.Entry(fold, textvariable=self.vt_dir_var).pack(side="left", fill="x", expand=True, padx=5, pady=5)
        ttk.Button(fold, text="Выбрать", command=self.pick_vt_dir).pack(side="left", padx=4)
        ttk.Button(fold, text="Скан папки", command=self.start_folder_scan).pack(side="left", padx=4)

        self.scan_pb = ttk.Progressbar(self.tab_vt, mode="determinate")
        self.scan_pb.pack(fill="x", padx=10, pady=(4, 10))

    @staticmethod
    def sha256_file(path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def vt_lookup(self, file_hash):
        key = self.settings.get("vt_api_key", "").strip()
        if not key:
            self.log("VirusTotal API key не задан", "unknown")
            return None
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": key},
                timeout=30,
            )
            if r.status_code == 404:
                return "unknown", "Неизвестно VT"
            r.raise_for_status()
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            m, s = stats.get("malicious", 0), stats.get("suspicious", 0)
            if m > 0:
                return "malicious", f"Вредоносный ({m})"
            if s > 0:
                return "suspicious", f"Подозрительный ({s})"
            return "clean", "Чисто"
        except Exception as e:
            self.log(f"VT ошибка: {e}", "error")
            return None

    def pick_vt_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.vt_file_var.set(p)

    def pick_vt_dir(self):
        p = filedialog.askdirectory()
        if p:
            self.vt_dir_var.set(p)

    def scan_one_file(self):
        p = Path(self.vt_file_var.get().strip())
        if not p.is_file():
            return messagebox.showwarning("Ошибка", "Выберите файл")
        h = self.sha256_file(p)
        self.log(f"VT файл: {p}", "info")
        self.log(f"SHA256: {h}", "info")
        res = self.vt_lookup(h)
        if res:
            self.log(f"VT: {p} -> {res[1]}", res[0])
            self.set_status(f"Проверка завершена: {res[1]}")

    def start_folder_scan(self):
        d = Path(self.vt_dir_var.get().strip())
        if not d.is_dir():
            return messagebox.showwarning("Ошибка", "Выберите папку")
        threading.Thread(target=self.scan_folder_thread, args=(d,), daemon=True).start()

    def scan_folder_thread(self, d):
        files = [p for p in d.rglob("*") if p.is_file()]
        threats = 0
        self.after(0, lambda: self.scan_pb.configure(maximum=max(1, len(files)), value=0))
        for i, fp in enumerate(files, 1):
            try:
                res = self.vt_lookup(self.sha256_file(fp))
                if res:
                    self.log(f"VT папка: {fp} -> {res[1]}", res[0])
                    if res[0] == "malicious":
                        threats += 1
            except Exception as e:
                self.log(f"Ошибка {fp}: {e}", "error")
            self.after(0, lambda idx=i: self.scan_pb.configure(value=idx))
        self.set_status(f"Сканирование завершено, найдено угроз: {threats}")

    # ---------- System analysis ----------
    def build_system_tab(self):
        ttk.Button(self.tab_system, text="Показать автозапуски HKLM/HKCU Run", command=self.show_autoruns).pack(
            anchor="w", padx=10, pady=10
        )

    def show_autoruns(self):
        if not winreg:
            return self.log("Реестр недоступен (не Windows)", "unknown")
        paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
        ]
        for hive, key_path, name in paths:
            self.log(f"Автозапуски {name}", "info")
            try:
                with winreg.OpenKey(hive, key_path) as key:
                    i = 0
                    while True:
                        try:
                            n, v, _ = winreg.EnumValue(key, i)
                            self.log(f"{name}\\Run: {n} = {v}", "unknown")
                            i += 1
                        except OSError:
                            break
            except Exception as e:
                self.log(f"Ошибка {name}: {e}", "error")

    # ---------- Recovery ----------
    def build_recovery_tab(self):
        frm = ttk.Frame(self.tab_recovery)
        frm.pack(fill="x", padx=10, pady=10)
        cmds = [
            ("FixMBR", "bootrec /fixmbr"),
            ("SFC Scan", "sfc /scannow"),
            ("Defender Offline", "MpCmdRun.exe -Scan -ScanType 2"),
        ]
        for t, c in cmds:
            ttk.Button(frm, text=f"{t} ({c})", command=lambda cmd=c: self.run_cmd_async(cmd)).pack(fill="x", pady=3)
        ttk.Button(frm, text="Создать точку восстановления", command=self.create_restore_point).pack(fill="x", pady=3)

    def run_cmd_async(self, cmd):
        def worker():
            self.log(f"Запуск: {cmd}", "info")
            try:
                p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                out = (p.stdout or "") + (p.stderr or "")
                for line in out.splitlines():
                    self.log(f"[{cmd}] {line}", "unknown")
                self.log(f"Код завершения {cmd}: {p.returncode}", "clean" if p.returncode == 0 else "suspicious")
            except Exception as e:
                self.log(f"Ошибка запуска {cmd}: {e}", "error")

        threading.Thread(target=worker, daemon=True).start()

    def create_restore_point(self):
        self.run_cmd_async(
            "powershell -Command \"Checkpoint-Computer -Description 'SecurityCenter Point' -RestorePointType 'MODIFY_SETTINGS'\""
        )

    # ---------- Task manager ----------
    def build_tasks_tab(self):
        top = ttk.Frame(self.tab_tasks)
        top.pack(fill="x", padx=8, pady=8)
        ttk.Button(top, text="Обновить список", command=self.refresh_processes).pack(side="left", padx=3)
        ttk.Button(top, text="Завершить процесс", command=self.kill_selected).pack(side="left", padx=3)
        ttk.Button(top, text="АнКрИт Kill", command=self.ankrit_kill).pack(side="left", padx=3)

        self.proc_tree = ttk.Treeview(self.tab_tasks, columns=("pid", "name", "cpu", "mem"), show="headings")
        for c, t, w in [("pid", "PID", 90), ("name", "Имя", 400), ("cpu", "CPU%", 90), ("mem", "MB", 110)]:
            self.proc_tree.heading(c, text=t)
            self.proc_tree.column(c, width=w, anchor="w")
        self.proc_tree.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.refresh_processes()

    def refresh_processes(self):
        if not hasattr(self, "proc_tree"):
            return
        for i in self.proc_tree.get_children():
            self.proc_tree.delete(i)
        for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info"]):
            try:
                mem = p.info["memory_info"].rss / (1024 * 1024)
                self.proc_tree.insert("", "end", values=(p.info["pid"], p.info["name"], p.info["cpu_percent"], f"{mem:.1f}"))
            except Exception:
                continue
        self.log("Список процессов обновлён", "info")

    def selected_pid(self):
        s = self.proc_tree.selection()
        return int(self.proc_tree.item(s[0], "values")[0]) if s else None

    def kill_selected(self):
        pid = self.selected_pid()
        if not pid:
            return
        try:
            psutil.Process(pid).terminate()
            self.log(f"Процесс завершён PID={pid}", "clean")
        except Exception as e:
            self.log(f"Ошибка завершения PID={pid}: {e}", "error")
        self.refresh_processes()

    def ankrit_kill(self):
        pid = self.selected_pid()
        if not pid:
            return
        try:
            p = psutil.Process(pid)
            try:
                p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS if hasattr(psutil, "BELOW_NORMAL_PRIORITY_CLASS") else 10)
                self.log(f"АнКрИт: критичность понижена PID={pid}", "unknown")
            except Exception as e:
                self.log(f"АнКрИт: не удалось понизить приоритет PID={pid}: {e}", "suspicious")
            r = subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, text=True)
            self.log(
                f"АнКрИт Kill PID={pid}: {'успешно' if r.returncode == 0 else (r.stderr.strip() or 'ошибка')}",
                "malicious" if r.returncode == 0 else "error",
            )
        except Exception as e:
            self.log(f"АнКрИт Kill ошибка PID={pid}: {e}", "error")
        self.refresh_processes()

    # ---------- File manager ----------
    def build_filemgr_tab(self):
        root = ttk.Frame(self.tab_filemgr)
        root.pack(fill="both", expand=True, padx=8, pady=8)
        root.columnconfigure(0, weight=1)
        root.columnconfigure(1, weight=2)
        root.rowconfigure(0, weight=1)

        self.dir_tree = ttk.Treeview(root)
        self.dir_tree.heading("#0", text="Директории")
        self.dir_tree.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        self.dir_tree.bind("<<TreeviewSelect>>", self.on_dir_change)

        right = ttk.Frame(root)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(0, weight=1)

        self.file_tree = ttk.Treeview(right, columns=("name", "size", "date"), show="headings")
        for c, t, w in [("name", "Имя", 420), ("size", "Размер", 120), ("date", "Изменён", 190)]:
            self.file_tree.heading(c, text=t)
            self.file_tree.column(c, width=w, anchor="w")
        self.file_tree.grid(row=0, column=0, sticky="nsew")

        btns = ttk.Frame(right)
        btns.grid(row=1, column=0, sticky="ew", pady=6)
        for t, cmd in [
            ("Открыть", self.fm_open),
            ("Удалить", self.fm_delete),
            ("Копировать", self.fm_copy),
            ("VirusTotal Check", self.fm_vt),
        ]:
            ttk.Button(btns, text=t, command=cmd).pack(side="left", padx=3)

        root_path = Path.home()
        node = self.dir_tree.insert("", "end", text=str(root_path), values=(str(root_path),))
        self.fill_tree_node(node, root_path)

    def fill_tree_node(self, node, path):
        self.dir_tree.delete(*self.dir_tree.get_children(node))
        try:
            for p in sorted(path.iterdir(), key=lambda x: x.name.lower()):
                if p.is_dir():
                    c = self.dir_tree.insert(node, "end", text=p.name, values=(str(p),))
                    self.dir_tree.insert(c, "end", text="...")
        except Exception:
            pass

    def on_dir_change(self, _=None):
        sel = self.dir_tree.selection()
        if not sel:
            return
        node = sel[0]
        vals = self.dir_tree.item(node, "values")
        if not vals:
            return
        path = Path(vals[0])

        kids = self.dir_tree.get_children(node)
        if kids and self.dir_tree.item(kids[0], "text") == "...":
            self.fill_tree_node(node, path)

        for r in self.file_tree.get_children():
            self.file_tree.delete(r)
        try:
            for p in sorted(path.iterdir(), key=lambda x: x.name.lower()):
                if p.is_file():
                    st = p.stat()
                    dt = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                    self.file_tree.insert("", "end", values=(str(p), f"{st.st_size}", dt))
        except Exception as e:
            self.log(f"FM ошибка: {e}", "error")

    def sel_file(self):
        s = self.file_tree.selection()
        return Path(self.file_tree.item(s[0], "values")[0]) if s else None

    def fm_open(self):
        p = self.sel_file()
        if not p:
            return
        try:
            if hasattr(os, "startfile"):
                os.startfile(str(p))  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", str(p)])
            self.log(f"Открыт файл: {p}", "info")
        except Exception as e:
            self.log(f"Ошибка открытия {p}: {e}", "error")

    def fm_delete(self):
        p = self.sel_file()
        if not p:
            return
        if not messagebox.askyesno("Подтверждение", f"Удалить {p}?"):
            return
        try:
            p.unlink()
            self.log(f"Удалён файл: {p}", "suspicious")
            self.on_dir_change()
        except Exception as e:
            self.log(f"Ошибка удаления {p}: {e}", "error")

    def fm_copy(self):
        p = self.sel_file()
        if not p:
            return
        dst_dir = filedialog.askdirectory()
        if not dst_dir:
            return
        try:
            dst = Path(dst_dir) / p.name
            shutil.copy2(p, dst)
            self.log(f"Скопирован: {p} -> {dst}", "clean")
        except Exception as e:
            self.log(f"Ошибка копирования: {e}", "error")

    def fm_vt(self):
        p = self.sel_file()
        if not p:
            return
        try:
            res = self.vt_lookup(self.sha256_file(p))
            if res:
                self.log(f"FM VT: {p} -> {res[1]}", res[0])
        except Exception as e:
            self.log(f"FM VT ошибка: {e}", "error")

    # ---------- Internet ----------
    def build_internet_tab(self):
        pw = ttk.PanedWindow(self.tab_internet, orient="vertical")
        pw.pack(fill="both", expand=True, padx=8, pady=8)

        top = ttk.Labelframe(pw, text="Hosts")
        mid = ttk.Labelframe(pw, text="Сетевые соединения")
        snf = ttk.Labelframe(pw, text="Sniffer")
        pw.add(top, weight=2)
        pw.add(mid, weight=3)
        pw.add(snf, weight=1)

        b = ttk.Frame(top)
        b.pack(fill="x", padx=6, pady=6)
        ttk.Button(b, text="Загрузить hosts", command=self.load_hosts).pack(side="left", padx=3)
        ttk.Button(b, text="Сохранить hosts", command=self.save_hosts).pack(side="left", padx=3)
        ttk.Button(b, text="Добавить блок", command=self.add_host).pack(side="left", padx=3)
        ttk.Button(b, text="Удалить блок", command=self.del_host).pack(side="left", padx=3)

        self.hosts_txt = ScrolledText(top, height=8, font=("Consolas", 10))
        self.hosts_txt.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        mb = ttk.Frame(mid)
        mb.pack(fill="x", padx=6, pady=6)
        ttk.Button(mb, text="Обновить список", command=self.refresh_connections).pack(side="left", padx=3)

        self.conn_tree = ttk.Treeview(mid, columns=("pid", "proc", "local", "remote", "status"), show="headings")
        for c, t, w in [("pid", "PID", 70), ("proc", "Процесс", 200), ("local", "Локальный", 240), ("remote", "Удалённый", 240), ("status", "Статус", 130)]:
            self.conn_tree.heading(c, text=t)
            self.conn_tree.column(c, width=w, anchor="w")
        self.conn_tree.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        sb = ttk.Frame(snf)
        sb.pack(fill="x", padx=6, pady=6)
        ttk.Button(sb, text="Старт Sniffer", command=self.start_sniffer).pack(side="left", padx=3)
        ttk.Button(sb, text="Стоп Sniffer", command=lambda: setattr(self, "sniffer_running", False)).pack(side="left", padx=3)

        self.load_hosts()
        self.refresh_connections()

    def hosts_path(self):
        w = Path(r"C:\Windows\System32\drivers\etc\hosts")
        return w if w.exists() else Path("/etc/hosts")

    def load_hosts(self):
        try:
            p = self.hosts_path()
            self.hosts_txt.delete("1.0", "end")
            self.hosts_txt.insert("1.0", p.read_text(encoding="utf-8", errors="ignore"))
            self.log(f"hosts загружен: {p}", "info")
        except Exception as e:
            self.log(f"hosts load ошибка: {e}", "error")

    def save_hosts(self):
        try:
            p = self.hosts_path()
            p.write_text(self.hosts_txt.get("1.0", "end-1c"), encoding="utf-8")
            self.log(f"hosts сохранён: {p}", "clean")
        except Exception as e:
            self.log(f"hosts save ошибка: {e}", "error")

    def add_host(self):
        d = prompt(self, "Добавить блок", "Домен:")
        if d:
            self.hosts_txt.insert("end", f"\n127.0.0.1 {d.strip()}")
            self.log(f"Добавлен блок hosts: {d}", "suspicious")

    def del_host(self):
        d = prompt(self, "Удалить блок", "Домен:")
        if not d:
            return
        lines = self.hosts_txt.get("1.0", "end-1c").splitlines()
        self.hosts_txt.delete("1.0", "end")
        self.hosts_txt.insert("1.0", "\n".join([ln for ln in lines if d.strip() not in ln]))
        self.log(f"Удалён блок hosts: {d}", "info")

    def refresh_connections(self):
        for i in self.conn_tree.get_children():
            self.conn_tree.delete(i)
        for c in psutil.net_connections(kind="inet"):
            pid = c.pid or 0
            try:
                pn = psutil.Process(pid).name() if pid else "-"
            except Exception:
                pn = "?"
            l = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
            r = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
            self.conn_tree.insert("", "end", values=(pid, pn, l, r, c.status))
        self.log("Сетевые соединения обновлены", "info")

    def start_sniffer(self):
        if sniff is None:
            return self.log("Scapy не установлен: sniffer недоступен", "unknown")
        if self.sniffer_running:
            return
        self.sniffer_running = True

        def run():
            self.log("Sniffer запущен", "info")

            def handler(pkt):
                if not self.sniffer_running:
                    return True
                try:
                    if hasattr(pkt, "src") and hasattr(pkt, "dst"):
                        src = getattr(pkt, "src", "?")
                        dst = getattr(pkt, "dst", "?")
                        sport = getattr(pkt, "sport", "-")
                        dport = getattr(pkt, "dport", "-")
                        self.log(f"Sniffer: {src}:{sport} -> {dst}:{dport}", "unknown")
                except Exception:
                    pass

            while self.sniffer_running:
                sniff(prn=handler, timeout=2, store=False)
            self.log("Sniffer остановлен", "info")

        threading.Thread(target=run, daemon=True).start()

    # ---------- USB ----------
    def build_usb_tab(self):
        top = ttk.Frame(self.tab_usb)
        top.pack(fill="x", padx=8, pady=8)
        ttk.Button(top, text="Обновить список USB", command=self.refresh_usb).pack(side="left", padx=3)
        ttk.Button(top, text="Блокировать флешки (кроме текущего носителя*)", command=self.block_usb).pack(side="left", padx=3)

        self.usb_tree = ttk.Treeview(self.tab_usb, columns=("dev", "mount", "time"), show="headings")
        for c, t, w in [("dev", "Устройство", 320), ("mount", "Точка монтирования", 260), ("time", "Время обнаружения", 220)]:
            self.usb_tree.heading(c, text=t)
            self.usb_tree.column(c, width=w, anchor="w")
        self.usb_tree.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.refresh_usb()

    def refresh_usb(self):
        for i in self.usb_tree.get_children():
            self.usb_tree.delete(i)

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for p in psutil.disk_partitions(all=False):
            if "removable" in p.opts.lower() or p.device.lower().startswith("\\\\.\\") or "media" in p.opts.lower():
                key = f"{p.device}|{p.mountpoint}"
                if key not in self.usb_seen:
                    self.usb_seen[key] = now
                    self.log(f"USB подключено: {p.device} @ {p.mountpoint}", "unknown")
                self.usb_tree.insert("", "end", values=(p.device, p.mountpoint, self.usb_seen[key]))

    def block_usb(self):
        if platform.system().lower() != "windows":
            return self.log("Блокировка USB доступна только в Windows", "unknown")
        app_drive = str(Path(__file__).resolve().drive)
        self.log(f"Текущий носитель приложения: {app_drive or 'не определён'}", "info")
        self.log(
            "Применяется глобальная блокировка USBSTOR (исключение текущего носителя аппаратно зависит от ОС/политик)",
            "suspicious",
        )
        self.run_cmd_async(r'reg add "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" /v Start /t REG_DWORD /d 4 /f')

    # ---------- Anti-keylogger ----------
    def build_keylogger_tab(self):
        top = ttk.Frame(self.tab_key)
        top.pack(fill="x", padx=8, pady=8)
        ttk.Button(top, text="Старт мониторинга", command=self.start_key_guard).pack(side="left", padx=3)
        ttk.Button(top, text="Стоп мониторинга", command=lambda: setattr(self, "key_guard_running", False)).pack(side="left", padx=3)
        ttk.Label(
            self.tab_key,
            text="Эвристический мониторинг: поиск подозрительных процессов (keylog/hook/inject/spy).",
        ).pack(anchor="w", padx=10, pady=4)

    def start_key_guard(self):
        if self.key_guard_running:
            return
        self.key_guard_running = True

        suspicious_markers = ["keylog", "hook", "inject", "spy", "grabber", "logger"]

        def worker():
            self.log("Анти-кейлоггер мониторинг запущен", "info")
            while self.key_guard_running:
                for p in psutil.process_iter(["pid", "name", "exe"]):
                    try:
                        text = f"{p.info.get('name','')} {p.info.get('exe','')}".lower()
                        if any(m in text for m in suspicious_markers):
                            self.log(f"Подозрительный процесс: PID={p.pid} {p.info.get('name','?')}", "suspicious")
                    except Exception:
                        continue
                time.sleep(8)
            self.log("Анти-кейлоггер мониторинг остановлен", "info")

        threading.Thread(target=worker, daemon=True).start()

    # ---------- Boot ----------
    def build_boot_tab(self):
        top = ttk.Frame(self.tab_boot)
        top.pack(fill="x", padx=8, pady=8)
        ttk.Button(top, text="Показать boot-order", command=self.show_boot_order).pack(side="left", padx=3)

        ttk.Label(top, text="Приоритет загрузки:").pack(side="left", padx=(10, 4))
        self.boot_target_var = tk.StringVar(value="disk")
        ttk.Combobox(top, textvariable=self.boot_target_var, values=["flash", "disk", "network"], width=12, state="readonly").pack(
            side="left", padx=4
        )
        ttk.Button(top, text="Применить (bcdedit/WMI)", command=self.apply_boot_priority).pack(side="left", padx=4)

        self.boot_text = ScrolledText(self.tab_boot, height=20, font=("Consolas", 10))
        self.boot_text.pack(fill="both", expand=True, padx=8, pady=8)

    def show_boot_order(self):
        self.boot_text.delete("1.0", "end")
        try:
            r = subprocess.run("bcdedit /enum {fwbootmgr}", shell=True, capture_output=True, text=True)
            out = (r.stdout or "") + (r.stderr or "")
            self.boot_text.insert("1.0", out if out else "Нет данных")
            self.log("Boot-order обновлён", "info")
        except Exception as e:
            self.log(f"Ошибка получения boot-order: {e}", "error")

    def apply_boot_priority(self):
        target = self.boot_target_var.get()
        self.log(f"Запрошено изменение boot-priority на: {target}", "info")
        if target == "disk":
            cmd = "bcdedit /set {fwbootmgr} displayorder {bootmgr} /addfirst"
        elif target == "flash":
            cmd = "wmic path Win32_BootConfiguration get /value"
        else:
            cmd = "wmic nicconfig where IPEnabled=true get Description,Index"
        self.run_cmd_async(cmd)

    # ---------- Settings ----------
    def build_settings_tab(self):
        frm = ttk.Frame(self.tab_settings)
        frm.pack(fill="both", expand=True, padx=12, pady=12)

        ttk.Label(frm, text="Папка логов:").grid(row=0, column=0, sticky="w", pady=4)
        self.log_dir_var = tk.StringVar(value=self.settings["log_dir"])
        ttk.Entry(frm, textvariable=self.log_dir_var, width=72).grid(row=0, column=1, sticky="ew", padx=5)
        ttk.Button(frm, text="...", command=self.choose_log_dir).grid(row=0, column=2)

        ttk.Label(frm, text="Тема:").grid(row=1, column=0, sticky="w", pady=4)
        self.theme_var = tk.StringVar(value=self.settings["theme"])
        ttk.Combobox(frm, textvariable=self.theme_var, values=["light", "dark"], width=12, state="readonly").grid(
            row=1, column=1, sticky="w", padx=5
        )

        self.autosave_var = tk.BooleanVar(value=self.settings["autosave_logs"])
        ttk.Checkbutton(frm, text="Авто-сохранение логов", variable=self.autosave_var).grid(
            row=2, column=1, sticky="w", padx=5, pady=4
        )

        ttk.Label(frm, text="VirusTotal API key:").grid(row=3, column=0, sticky="w", pady=4)
        self.vt_key_var = tk.StringVar(value=self.settings.get("vt_api_key", ""))
        ttk.Entry(frm, textvariable=self.vt_key_var, show="*", width=72).grid(row=3, column=1, sticky="ew", padx=5)

        ttk.Button(frm, text="Сохранить настройки", command=self.apply_settings).grid(row=4, column=1, sticky="w", pady=10)
        frm.columnconfigure(1, weight=1)

    def choose_log_dir(self):
        p = filedialog.askdirectory()
        if p:
            self.log_dir_var.set(p)

    def apply_settings(self):
        self.settings["log_dir"] = self.log_dir_var.get().strip() or self.settings["log_dir"]
        self.settings["theme"] = self.theme_var.get()
        self.settings["autosave_logs"] = bool(self.autosave_var.get())
        self.settings["vt_api_key"] = self.vt_key_var.get().strip()

        self.log_dir = Path(self.settings["log_dir"])
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.session_log = self.log_dir / f"session_{datetime.now():%Y%m%d_%H%M%S}.txt"
        self.save_settings()
        self.apply_theme(self.settings["theme"])
        self.log("Настройки сохранены", "clean")


def prompt(parent, title, text):
    out = {"v": None}
    w = tk.Toplevel(parent)
    w.title(title)
    w.resizable(False, False)
    w.grab_set()

    ttk.Label(w, text=text).pack(padx=10, pady=(10, 4))
    var = tk.StringVar()
    e = ttk.Entry(w, textvariable=var, width=40)
    e.pack(padx=10, pady=4)
    e.focus_set()

    f = ttk.Frame(w)
    f.pack(pady=8)

    def ok():
        out["v"] = var.get().strip()
        w.destroy()

    ttk.Button(f, text="OK", command=ok).pack(side="left", padx=4)
    ttk.Button(f, text="Cancel", command=w.destroy).pack(side="left", padx=4)
    w.wait_window()
    return out["v"]


if __name__ == "__main__":
    app = App()
    app.mainloop()

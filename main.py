import hashlib
import json
import os
import shutil
import subprocess
import threading
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

import psutil
import requests

try:
    import winreg
except ImportError:  # non-Windows fallback
    winreg = None

APP_TITLE = "WinPE Security & Recovery Center"
DEFAULT_SETTINGS = {
    "log_dir": str(Path.cwd() / "logs"),
    "theme": "light",
    "autosave_logs": True,
    "virustotal_api_key": os.environ.get("VT_API_KEY", ""),
}
SETTINGS_FILE = Path("settings.json")


class SecurityCenterApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1300x850")
        self.minsize(1100, 700)

        self.settings = self._load_settings()
        Path(self.settings["log_dir"]).mkdir(parents=True, exist_ok=True)

        self.style = ttk.Style(self)
        self._apply_theme(self.settings.get("theme", "light"))

        self.status_var = tk.StringVar(value="Готово")
        self.current_log_file = Path(self.settings["log_dir"]) / f"session_{datetime.now():%Y%m%d_%H%M%S}.txt"

        self._build_ui()
        self._bind_hotkeys()

        self.log("Приложение запущено", "info")

    # ----------------------------- SETTINGS -----------------------------
    def _load_settings(self):
        if SETTINGS_FILE.exists():
            try:
                data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
                return {**DEFAULT_SETTINGS, **data}
            except Exception:
                return DEFAULT_SETTINGS.copy()
        return DEFAULT_SETTINGS.copy()

    def _save_settings(self):
        SETTINGS_FILE.write_text(json.dumps(self.settings, ensure_ascii=False, indent=2), encoding="utf-8")

    # ----------------------------- UI -----------------------------
    def _build_ui(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=6, pady=6)

        self.tab_file = ttk.Frame(self.notebook)
        self.tab_folder = ttk.Frame(self.notebook)
        self.tab_system = ttk.Frame(self.notebook)
        self.tab_logs = ttk.Frame(self.notebook)
        self.tab_recovery = ttk.Frame(self.notebook)
        self.tab_tasks = ttk.Frame(self.notebook)
        self.tab_filemgr = ttk.Frame(self.notebook)
        self.tab_internet = ttk.Frame(self.notebook)
        self.tab_settings = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_file, text="Файл")
        self.notebook.add(self.tab_folder, text="Папка")
        self.notebook.add(self.tab_system, text="Системный анализ")
        self.notebook.add(self.tab_logs, text="Логи")
        self.notebook.add(self.tab_recovery, text="Восстановление")
        self.notebook.add(self.tab_tasks, text="Диспетчер задач")
        self.notebook.add(self.tab_filemgr, text="Файловый менеджер Pro")
        self.notebook.add(self.tab_internet, text="Интернет")
        self.notebook.add(self.tab_settings, text="Настройки")

        self._build_file_tab()
        self._build_folder_tab()
        self._build_system_tab()
        self._build_logs_tab()
        self._build_recovery_tab()
        self._build_tasks_tab()
        self._build_filemgr_tab()
        self._build_internet_tab()
        self._build_settings_tab()

        status_bar = ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w")
        status_bar.pack(fill="x", padx=6, pady=(0, 6))

    def _bind_hotkeys(self):
        self.bind_all("<Control-r>", lambda e: self.refresh_processes())
        self.bind_all("<Control-l>", lambda e: self._go_to_tab(self.tab_logs))
        self.bind_all("<Control-f>", lambda e: self._go_to_tab(self.tab_filemgr))
        self.bind_all("<Control-h>", lambda e: self._go_to_tab(self.tab_internet))

    def _go_to_tab(self, tab):
        self.notebook.select(tab)

    def _apply_theme(self, theme_name):
        if theme_name == "dark":
            self.style.theme_use("clam")
            bg = "#202124"
            fg = "#e8eaed"
            self.configure(bg=bg)
            self.style.configure("TFrame", background=bg)
            self.style.configure("TLabel", background=bg, foreground=fg)
            self.style.configure("TButton", background="#303134", foreground=fg)
            self.style.configure("Treeview", background="#2b2c2e", foreground=fg, fieldbackground="#2b2c2e")
            self.style.map("Treeview", background=[("selected", "#5f6368")])
        else:
            self.style.theme_use("clam")
            self.style.configure("TFrame", background="#f2f2f2")
            self.style.configure("TLabel", background="#f2f2f2", foreground="#000")
            self.style.configure("TButton", background="#ffffff", foreground="#000")
            self.style.configure("Treeview", background="#fff", foreground="#000", fieldbackground="#fff")

    # ----------------------------- LOGGING -----------------------------
    def _build_logs_tab(self):
        top = ttk.Frame(self.tab_logs)
        top.pack(fill="x", pady=4)
        ttk.Button(top, text="Сохранить логи в TXT", command=self.save_logs_manual).pack(side="left", padx=4)
        ttk.Button(top, text="Очистить", command=self.clear_logs).pack(side="left", padx=4)

        self.log_text = ScrolledText(self.tab_logs, wrap="word", font=("Consolas", 10))
        self.log_text.pack(fill="both", expand=True, padx=6, pady=6)
        self.log_text.tag_config("clean", foreground="green")
        self.log_text.tag_config("malicious", foreground="red")
        self.log_text.tag_config("suspicious", foreground="orange")
        self.log_text.tag_config("unknown", foreground="goldenrod")
        self.log_text.tag_config("info", foreground="deepskyblue4")
        self.log_text.tag_config("error", foreground="red", underline=True)

    def log(self, message, level="info"):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {message}\n"
        if hasattr(self, "log_text"):
            self.log_text.insert("end", line, level)
            self.log_text.see("end")
        if self.settings.get("autosave_logs", True):
            self.current_log_file.parent.mkdir(parents=True, exist_ok=True)
            with self.current_log_file.open("a", encoding="utf-8") as f:
                f.write(line)

    def save_logs_manual(self):
        path = filedialog.asksaveasfilename(
            title="Сохранить логи",
            defaultextension=".txt",
            filetypes=[("Text", "*.txt")],
        )
        if path:
            content = self.log_text.get("1.0", "end-1c")
            Path(path).write_text(content, encoding="utf-8")
            self.log(f"Логи сохранены: {path}", "info")

    def clear_logs(self):
        self.log_text.delete("1.0", "end")
        self.log("Лог очищен", "info")

    # ----------------------------- VIRUSTOTAL -----------------------------
    @staticmethod
    def sha256_file(file_path):
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def vt_check_hash(self, file_hash):
        api_key = self.settings.get("virustotal_api_key", "").strip()
        if not api_key:
            self.log("VirusTotal API key не задан (Настройки)", "unknown")
            return None

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": api_key}
        try:
            r = requests.get(url, headers=headers, timeout=30)
            if r.status_code == 404:
                return {"status": "unknown", "label": "Неизвестно VirusTotal"}
            r.raise_for_status()
            data = r.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            mal = stats.get("malicious", 0)
            susp = stats.get("suspicious", 0)
            if mal > 0:
                return {"status": "malicious", "label": f"Вредоносный ({mal})"}
            if susp > 0:
                return {"status": "suspicious", "label": f"Подозрительный ({susp})"}
            return {"status": "clean", "label": "Чисто"}
        except requests.RequestException as e:
            self.log(f"Ошибка VirusTotal: {e}", "error")
            return None

    # ----------------------------- TAB: FILE -----------------------------
    def _build_file_tab(self):
        frm = ttk.Frame(self.tab_file)
        frm.pack(fill="x", padx=10, pady=10)

        self.single_file_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.single_file_var).pack(side="left", fill="x", expand=True, padx=4)
        ttk.Button(frm, text="Выбрать", command=self.select_single_file).pack(side="left", padx=4)
        ttk.Button(frm, text="Проверить через VirusTotal", command=self.scan_single_file).pack(side="left", padx=4)

    def select_single_file(self):
        path = filedialog.askopenfilename(title="Выберите файл")
        if path:
            self.single_file_var.set(path)

    def scan_single_file(self):
        path = self.single_file_var.get().strip()
        if not path or not Path(path).exists():
            messagebox.showwarning("Ошибка", "Выберите корректный файл")
            return
        try:
            file_hash = self.sha256_file(path)
            self.log(f"Файл: {path}", "info")
            self.log(f"SHA256: {file_hash}", "info")
            result = self.vt_check_hash(file_hash)
            if result:
                self.log(f"VirusTotal: {result['label']} | {path}", result["status"])
                self.status_var.set(f"Проверка файла завершена: {result['label']}")
        except Exception as e:
            self.log(f"Ошибка сканирования файла: {e}", "error")

    # ----------------------------- TAB: FOLDER -----------------------------
    def _build_folder_tab(self):
        top = ttk.Frame(self.tab_folder)
        top.pack(fill="x", padx=10, pady=10)

        self.folder_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.folder_var).pack(side="left", fill="x", expand=True, padx=4)
        ttk.Button(top, text="Выбрать папку", command=self.select_folder).pack(side="left", padx=4)
        ttk.Button(top, text="Рекурсивный скан", command=self.start_folder_scan).pack(side="left", padx=4)

        self.scan_progress = ttk.Progressbar(self.tab_folder, mode="determinate")
        self.scan_progress.pack(fill="x", padx=12, pady=8)

    def select_folder(self):
        path = filedialog.askdirectory(title="Выберите папку")
        if path:
            self.folder_var.set(path)

    def start_folder_scan(self):
        folder = self.folder_var.get().strip()
        if not folder or not Path(folder).is_dir():
            messagebox.showwarning("Ошибка", "Выберите корректную папку")
            return
        t = threading.Thread(target=self.scan_folder_recursive, args=(folder,), daemon=True)
        t.start()

    def scan_folder_recursive(self, folder):
        files = [p for p in Path(folder).rglob("*") if p.is_file()]
        total = len(files)
        threats = 0
        suspicious = 0
        unknown = 0

        self.after(0, lambda: self.scan_progress.configure(maximum=max(total, 1), value=0))
        self.log(f"Старт сканирования папки: {folder}, файлов: {total}", "info")

        for idx, fp in enumerate(files, start=1):
            try:
                file_hash = self.sha256_file(fp)
                result = self.vt_check_hash(file_hash)
                if result:
                    status = result["status"]
                    self.log(f"{fp} -> {result['label']}", status)
                    if status == "malicious":
                        threats += 1
                    elif status == "suspicious":
                        suspicious += 1
                    elif status == "unknown":
                        unknown += 1
                self.after(0, lambda i=idx: self.scan_progress.configure(value=i))
            except Exception as e:
                self.log(f"Ошибка файла {fp}: {e}", "error")

        self.status_var.set(
            f"Сканирование завершено, найдено угроз: {threats}, подозрительных: {suspicious}, неизвестных: {unknown}"
        )
        self.log(self.status_var.get(), "info")

    # ----------------------------- TAB: SYSTEM ANALYSIS -----------------------------
    def _build_system_tab(self):
        ttk.Button(self.tab_system, text="Показать автозапуски HKLM/HKCU Run", command=self.read_autoruns).pack(
            anchor="w", padx=10, pady=10
        )

    def read_autoruns(self):
        if winreg is None:
            self.log("Реестр недоступен вне Windows", "unknown")
            return

        locations = [
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
        ]
        for hive, path, title in locations:
            self.log(f"Автозапуск {title}:", "info")
            try:
                with winreg.OpenKey(hive, path) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            self.log(f"{title}\\Run -> {name} = {value}", "unknown")
                            i += 1
                        except OSError:
                            break
            except Exception as e:
                self.log(f"Ошибка чтения {title}: {e}", "error")

    # ----------------------------- TAB: RECOVERY -----------------------------
    def _build_recovery_tab(self):
        frame = ttk.Frame(self.tab_recovery)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        ttk.Button(frame, text="FixMBR (bootrec /fixmbr)", command=lambda: self.run_recovery_cmd("bootrec /fixmbr")).pack(
            fill="x", pady=3
        )
        ttk.Button(frame, text="SFC Scan (sfc /scannow)", command=lambda: self.run_recovery_cmd("sfc /scannow")).pack(
            fill="x", pady=3
        )
        ttk.Button(
            frame,
            text="Defender Offline (MpCmdRun.exe -Scan -ScanType 2)",
            command=lambda: self.run_recovery_cmd('MpCmdRun.exe -Scan -ScanType 2'),
        ).pack(fill="x", pady=3)
        ttk.Button(frame, text="Создать точку восстановления", command=self.create_restore_point).pack(fill="x", pady=3)

    def run_recovery_cmd(self, cmd):
        def worker():
            self.log(f"Запуск: {cmd}", "info")
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                out = (result.stdout or "") + (result.stderr or "")
                for line in out.splitlines():
                    self.log(f"[{cmd}] {line}", "unknown")
                if result.returncode == 0:
                    self.log(f"Команда выполнена успешно: {cmd}", "clean")
                else:
                    self.log(f"Команда завершилась с кодом {result.returncode}: {cmd}", "suspicious")
            except Exception as e:
                self.log(f"Ошибка запуска команды {cmd}: {e}", "error")

        threading.Thread(target=worker, daemon=True).start()

    def create_restore_point(self):
        cmd = (
            "powershell -Command \"Checkpoint-Computer -Description 'SecurityCenter Restore Point' "
            "-RestorePointType 'MODIFY_SETTINGS'\""
        )
        self.run_recovery_cmd(cmd)

    # ----------------------------- TAB: TASK MANAGER -----------------------------
    def _build_tasks_tab(self):
        controls = ttk.Frame(self.tab_tasks)
        controls.pack(fill="x", padx=8, pady=8)
        ttk.Button(controls, text="Обновить список", command=self.refresh_processes).pack(side="left", padx=3)
        ttk.Button(controls, text="Завершить процесс", command=self.terminate_selected_process).pack(side="left", padx=3)
        ttk.Button(controls, text="АнКрИт Kill", command=self.ankrit_kill_selected).pack(side="left", padx=3)

        cols = ("pid", "name", "cpu", "mem")
        self.proc_tree = ttk.Treeview(self.tab_tasks, columns=cols, show="headings")
        for c, title, width in [
            ("pid", "PID", 90),
            ("name", "Имя", 400),
            ("cpu", "CPU%", 100),
            ("mem", "Память MB", 120),
        ]:
            self.proc_tree.heading(c, text=title)
            self.proc_tree.column(c, width=width, anchor="w")
        self.proc_tree.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.refresh_processes()

    def refresh_processes(self):
        for row in self.proc_tree.get_children():
            self.proc_tree.delete(row)

        for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info"]):
            try:
                mem_mb = p.info["memory_info"].rss / (1024 * 1024)
                self.proc_tree.insert(
                    "", "end", values=(p.info["pid"], p.info["name"], f"{p.info['cpu_percent']:.1f}", f"{mem_mb:.1f}")
                )
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
        self.status_var.set("Список процессов обновлён")
        self.log("Обновлён список процессов", "info")

    def _selected_pid(self):
        sel = self.proc_tree.selection()
        if not sel:
            return None
        values = self.proc_tree.item(sel[0], "values")
        return int(values[0])

    def terminate_selected_process(self):
        pid = self._selected_pid()
        if pid is None:
            return
        try:
            psutil.Process(pid).terminate()
            self.log(f"Процесс завершён: PID={pid}", "clean")
        except Exception as e:
            self.log(f"Ошибка завершения PID={pid}: {e}", "error")
        self.refresh_processes()

    def ankrit_kill_selected(self):
        pid = self._selected_pid()
        if pid is None:
            return
        try:
            p = psutil.Process(pid)
            try:
                if hasattr(psutil, "BELOW_NORMAL_PRIORITY_CLASS"):
                    p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
                else:
                    p.nice(10)
                self.log(f"АнКрИт: приоритет процесса снижен PID={pid}", "unknown")
            except Exception as e:
                self.log(f"АнКрИт: не удалось снизить приоритет PID={pid}: {e}", "suspicious")

            result = subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, text=True)
            if result.returncode == 0:
                self.log(f"АнКрИт Kill выполнен: PID={pid}", "malicious")
            else:
                self.log(f"АнКрИт Kill ошибка: {result.stderr.strip()}", "error")
        except Exception as e:
            self.log(f"АнКрИт Kill не выполнен для PID={pid}: {e}", "error")
        self.refresh_processes()

    # ----------------------------- TAB: FILE MANAGER -----------------------------
    def _build_filemgr_tab(self):
        container = ttk.Frame(self.tab_filemgr)
        container.pack(fill="both", expand=True, padx=8, pady=8)
        container.columnconfigure(0, weight=1)
        container.columnconfigure(1, weight=2)
        container.rowconfigure(0, weight=1)

        self.dir_tree = ttk.Treeview(container)
        self.dir_tree.heading("#0", text="Директории")
        self.dir_tree.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        self.dir_tree.bind("<<TreeviewSelect>>", self.on_dir_select)

        file_frame = ttk.Frame(container)
        file_frame.grid(row=0, column=1, sticky="nsew")
        file_frame.rowconfigure(0, weight=1)
        file_frame.columnconfigure(0, weight=1)

        self.files_tree = ttk.Treeview(file_frame, columns=("name", "size", "mtime"), show="headings")
        for c, t, w in [
            ("name", "Имя", 350),
            ("size", "Размер", 120),
            ("mtime", "Изменён", 220),
        ]:
            self.files_tree.heading(c, text=t)
            self.files_tree.column(c, width=w, anchor="w")
        self.files_tree.grid(row=0, column=0, sticky="nsew")

        btns = ttk.Frame(file_frame)
        btns.grid(row=1, column=0, sticky="ew", pady=6)
        for text, cmd in [
            ("Открыть", self.fm_open_file),
            ("Удалить", self.fm_delete_file),
            ("Копировать", self.fm_copy_file),
            ("VirusTotal Check", self.fm_vt_check),
        ]:
            ttk.Button(btns, text=text, command=cmd).pack(side="left", padx=3)

        self.fm_root = Path.home()
        root_node = self.dir_tree.insert("", "end", text=str(self.fm_root), values=(str(self.fm_root),))
        self._populate_dir_node(root_node, self.fm_root)

    def _populate_dir_node(self, node, path):
        self.dir_tree.delete(*self.dir_tree.get_children(node))
        try:
            for p in sorted(path.iterdir(), key=lambda x: x.name.lower()):
                if p.is_dir():
                    child = self.dir_tree.insert(node, "end", text=p.name, values=(str(p),))
                    self.dir_tree.insert(child, "end", text="...")
        except Exception:
            return

    def on_dir_select(self, _event=None):
        sel = self.dir_tree.selection()
        if not sel:
            return
        node = sel[0]
        raw = self.dir_tree.item(node, "values")
        if raw:
            path = Path(raw[0])
        else:
            parts = []
            current = node
            while current:
                parts.append(self.dir_tree.item(current, "text"))
                parent = self.dir_tree.parent(current)
                current = parent if parent else ""
            path = Path(*reversed(parts))

        if self.dir_tree.get_children(node):
            first_child = self.dir_tree.get_children(node)[0]
            if self.dir_tree.item(first_child, "text") == "...":
                self._populate_dir_node(node, path)

        for row in self.files_tree.get_children():
            self.files_tree.delete(row)
        try:
            for p in sorted(path.iterdir(), key=lambda x: x.name.lower()):
                if p.is_file():
                    st = p.stat()
                    mtime = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                    self.files_tree.insert("", "end", values=(str(p), f"{st.st_size} B", mtime))
        except Exception as e:
            self.log(f"Файловый менеджер: ошибка чтения {path}: {e}", "error")

    def _selected_file(self):
        sel = self.files_tree.selection()
        if not sel:
            return None
        return Path(self.files_tree.item(sel[0], "values")[0])

    def fm_open_file(self):
        p = self._selected_file()
        if not p:
            return
        try:
            os.startfile(str(p))  # type: ignore[attr-defined]
            self.log(f"Открыт файл: {p}", "info")
        except Exception as e:
            self.log(f"Ошибка открытия файла {p}: {e}", "error")

    def fm_delete_file(self):
        p = self._selected_file()
        if not p:
            return
        if not messagebox.askyesno("Подтверждение", f"Удалить файл?\n{p}"):
            return
        try:
            p.unlink()
            self.log(f"Удалён файл: {p}", "suspicious")
            self.on_dir_select()
        except Exception as e:
            self.log(f"Ошибка удаления {p}: {e}", "error")

    def fm_copy_file(self):
        p = self._selected_file()
        if not p:
            return
        target_dir = filedialog.askdirectory(title="Куда копировать")
        if not target_dir:
            return
        try:
            dst = Path(target_dir) / p.name
            shutil.copy2(p, dst)
            self.log(f"Скопирован файл: {p} -> {dst}", "clean")
        except Exception as e:
            self.log(f"Ошибка копирования {p}: {e}", "error")

    def fm_vt_check(self):
        p = self._selected_file()
        if not p:
            return
        try:
            file_hash = self.sha256_file(p)
            result = self.vt_check_hash(file_hash)
            if result:
                self.log(f"FM VT: {p} -> {result['label']}", result["status"])
        except Exception as e:
            self.log(f"FM VT ошибка {p}: {e}", "error")

    # ----------------------------- TAB: INTERNET -----------------------------
    def _build_internet_tab(self):
        paned = ttk.PanedWindow(self.tab_internet, orient="vertical")
        paned.pack(fill="both", expand=True, padx=8, pady=8)

        hosts_frame = ttk.Labelframe(paned, text="Hosts редактор")
        net_frame = ttk.Labelframe(paned, text="Мониторинг сети")
        paned.add(hosts_frame, weight=2)
        paned.add(net_frame, weight=3)

        btns = ttk.Frame(hosts_frame)
        btns.pack(fill="x", padx=6, pady=6)
        ttk.Button(btns, text="Загрузить hosts", command=self.load_hosts).pack(side="left", padx=3)
        ttk.Button(btns, text="Сохранить изменения", command=self.save_hosts).pack(side="left", padx=3)
        ttk.Button(btns, text="Добавить блокировку", command=self.add_host_block).pack(side="left", padx=3)
        ttk.Button(btns, text="Удалить блокировку", command=self.remove_host_block).pack(side="left", padx=3)

        self.hosts_text = ScrolledText(hosts_frame, height=10, font=("Consolas", 10))
        self.hosts_text.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        nbtns = ttk.Frame(net_frame)
        nbtns.pack(fill="x", padx=6, pady=6)
        ttk.Button(nbtns, text="Обновить список", command=self.refresh_connections).pack(side="left", padx=3)

        self.conn_tree = ttk.Treeview(
            net_frame,
            columns=("pid", "proc", "laddr", "raddr", "port", "status"),
            show="headings",
        )
        for c, t, w in [
            ("pid", "PID", 70),
            ("proc", "Процесс", 220),
            ("laddr", "Локальный", 220),
            ("raddr", "Удалённый", 220),
            ("port", "Порт", 80),
            ("status", "Статус", 120),
        ]:
            self.conn_tree.heading(c, text=t)
            self.conn_tree.column(c, width=w, anchor="w")
        self.conn_tree.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        self.refresh_connections()
        self.load_hosts()

    def _hosts_path(self):
        win = Path(r"C:\Windows\System32\drivers\etc\hosts")
        return win if win.exists() else Path("/etc/hosts")

    def load_hosts(self):
        path = self._hosts_path()
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            self.hosts_text.delete("1.0", "end")
            self.hosts_text.insert("1.0", content)
            self.log(f"hosts загружен: {path}", "info")
        except Exception as e:
            self.log(f"Ошибка загрузки hosts: {e}", "error")

    def save_hosts(self):
        path = self._hosts_path()
        try:
            content = self.hosts_text.get("1.0", "end-1c")
            path.write_text(content, encoding="utf-8")
            self.log(f"hosts сохранён: {path}", "clean")
        except Exception as e:
            self.log(f"Ошибка сохранения hosts: {e}", "error")

    def add_host_block(self):
        domain = simple_prompt(self, "Добавить блокировку", "Введите домен (site.com):")
        if not domain:
            return
        line = f"127.0.0.1 {domain.strip()}"
        self.hosts_text.insert("end", "\n" + line)
        self.log(f"Добавлена блокировка в hosts: {line}", "suspicious")

    def remove_host_block(self):
        domain = simple_prompt(self, "Удалить блокировку", "Введите домен (site.com):")
        if not domain:
            return
        lines = self.hosts_text.get("1.0", "end-1c").splitlines()
        filtered = [ln for ln in lines if domain.strip() not in ln]
        self.hosts_text.delete("1.0", "end")
        self.hosts_text.insert("1.0", "\n".join(filtered))
        self.log(f"Удалена блокировка для: {domain}", "info")

    def refresh_connections(self):
        for row in self.conn_tree.get_children():
            self.conn_tree.delete(row)

        for c in psutil.net_connections(kind="inet"):
            pid = c.pid or 0
            try:
                proc_name = psutil.Process(pid).name() if pid else "-"
            except Exception:
                proc_name = "?"
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
            port = c.raddr.port if c.raddr else "-"
            self.conn_tree.insert("", "end", values=(pid, proc_name, laddr, raddr, port, c.status))

        self.log("Обновлён список сетевых соединений", "info")

    # ----------------------------- TAB: SETTINGS -----------------------------
    def _build_settings_tab(self):
        frm = ttk.Frame(self.tab_settings)
        frm.pack(fill="both", expand=True, padx=12, pady=12)

        ttk.Label(frm, text="Папка логов:").grid(row=0, column=0, sticky="w", pady=5)
        self.log_dir_var = tk.StringVar(value=self.settings["log_dir"])
        ttk.Entry(frm, textvariable=self.log_dir_var, width=70).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(frm, text="...", command=self.choose_log_dir).grid(row=0, column=2)

        ttk.Label(frm, text="Тема:").grid(row=1, column=0, sticky="w", pady=5)
        self.theme_var = tk.StringVar(value=self.settings.get("theme", "light"))
        ttk.Combobox(frm, textvariable=self.theme_var, values=["light", "dark"], state="readonly", width=12).grid(
            row=1, column=1, sticky="w", padx=6
        )

        self.autosave_var = tk.BooleanVar(value=self.settings.get("autosave_logs", True))
        ttk.Checkbutton(frm, text="Авто-сохранение логов", variable=self.autosave_var).grid(
            row=2, column=1, sticky="w", padx=6, pady=5
        )

        ttk.Label(frm, text="VirusTotal API key:").grid(row=3, column=0, sticky="w", pady=5)
        self.vt_key_var = tk.StringVar(value=self.settings.get("virustotal_api_key", ""))
        ttk.Entry(frm, textvariable=self.vt_key_var, width=70, show="*").grid(row=3, column=1, sticky="ew", padx=6)

        ttk.Button(frm, text="Сохранить настройки", command=self.save_settings_from_ui).grid(row=4, column=1, sticky="w", pady=12)
        frm.columnconfigure(1, weight=1)

    def choose_log_dir(self):
        path = filedialog.askdirectory(title="Выберите папку для логов")
        if path:
            self.log_dir_var.set(path)

    def save_settings_from_ui(self):
        self.settings["log_dir"] = self.log_dir_var.get().strip() or self.settings["log_dir"]
        self.settings["theme"] = self.theme_var.get()
        self.settings["autosave_logs"] = bool(self.autosave_var.get())
        self.settings["virustotal_api_key"] = self.vt_key_var.get().strip()

        Path(self.settings["log_dir"]).mkdir(parents=True, exist_ok=True)
        self.current_log_file = Path(self.settings["log_dir"]) / f"session_{datetime.now():%Y%m%d_%H%M%S}.txt"

        self._save_settings()
        self._apply_theme(self.settings["theme"])
        self.log("Настройки сохранены", "clean")


def simple_prompt(parent, title, prompt):
    result = {"value": None}

    w = tk.Toplevel(parent)
    w.title(title)
    w.grab_set()
    w.resizable(False, False)

    ttk.Label(w, text=prompt).pack(padx=12, pady=(12, 4))
    var = tk.StringVar()
    entry = ttk.Entry(w, textvariable=var, width=40)
    entry.pack(padx=12, pady=4)
    entry.focus_set()

    def ok():
        result["value"] = var.get().strip()
        w.destroy()

    def cancel():
        w.destroy()

    bfrm = ttk.Frame(w)
    bfrm.pack(pady=10)
    ttk.Button(bfrm, text="OK", command=ok).pack(side="left", padx=5)
    ttk.Button(bfrm, text="Cancel", command=cancel).pack(side="left", padx=5)

    w.wait_window()
    return result["value"]


if __name__ == "__main__":
    app = SecurityCenterApp()
    app.mainloop()

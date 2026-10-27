# language: Python, file: antivirus.py
# Зависимости: yara-python, pefile
# Сборка: pyinstaller --noconsole --onefile --name KiwiAV antivirus.py
# Ключ проверяется по SHA-256 хешу, в коде ключа нет.

import hashlib
import math
import os
import threading
import tkinter as tk
from collections import Counter
from tkinter import filedialog, messagebox, scrolledtext

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

# ================= НАСТРОЙКИ =================
_SALT = b"KiwiAV_Salt_2026"
CORRECT_HASH = hashlib.sha256(_SALT + b"KIWI_121892").hexdigest()

QUARANTINE_DIR = os.path.join(os.environ.get("APPDATA", "."), "KiwiAV", "quarantine")
LOG_FILE = os.path.join(os.environ.get("APPDATA", "."), "KiwiAV", "scan.log")

# Подозрительные строки (в байтах: два бэкслеша = \\. в реальном файле)
SUSPICIOUS_STRINGS = [
    b"CreateRemoteThread",
    b"VirtualAllocEx",
    b"WriteProcessMemory",
    b"\\\\.\\PhysicalDrive0",
    b"bcdedit",
    b"vssadmin delete shadows",
    b"powershell -enc",
    b"powershell -encodedcommand",
    b"mimikatz",
    b"lsass.exe",
    b"sekurlsa",
    b"NetUserAdd",
    b"SetWindowsHookEx",
    b"keybd_event",
    b"GetAsyncKeyState",
    b"CurrentVersion\\Run",
]

# YARA-правила (встроенные, бэкслеши — по два)
YARA_RULES = r"""
rule Suspicious_Wiper_Strings {
    strings:
        $a = "\\\\.\\PhysicalDrive0" ascii wide
        $b = "bcdedit" ascii wide
        $c = "vssadmin delete shadows" ascii wide
        $d = "reagentc /disable" ascii wide
        $e = "NtRaiseHardError" ascii wide
    condition:
        2 of them
}

rule Suspicious_Injection {
    strings:
        $a = "CreateRemoteThread" ascii wide
        $b = "VirtualAllocEx" ascii wide
        $c = "WriteProcessMemory" ascii wide
        $d = "NtCreateThreadEx" ascii wide
    condition:
        2 of them
}

rule Suspicious_Keylogger {
    strings:
        $a = "SetWindowsHookEx" ascii wide
        $b = "GetAsyncKeyState" ascii wide
        $c = "keybd_event" ascii wide
        $d = "WH_KEYBOARD_LL" ascii wide
    condition:
        2 of them
}

rule Suspicious_Persistence {
    strings:
        $a = "CurrentVersion\\Run" ascii wide
        $b = "schtasks /create" ascii wide
        $c = "onlogon" ascii wide
    condition:
        2 of them
}

rule Packed_HighEntropy {
    condition:
        math.entropy(0, filesize) > 7.2 and filesize > 10000
}
"""


def ensure_dirs():
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


def log(msg: str):
    ensure_dirs()
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
    except Exception:
        pass


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    ent = 0.0
    for c in counts.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent


class Scanner:
    def __init__(self):
        self.rules = None
        if HAS_YARA:
            try:
                self.rules = yara.compile(source=YARA_RULES)
            except Exception as e:
                log(f"[YARA] compile error: {e}")

    def scan_file(self, path: str) -> dict:
        result = {"path": path, "verdict": "clean", "reasons": []}
        if not os.path.isfile(path):
            return result
        try:
            if os.path.getsize(path) == 0:
                return result
        except Exception:
            return result

        # 1. YARA
        if self.rules:
            try:
                matches = self.rules.match(path, timeout=10)
                for m in matches:
                    result["reasons"].append(f"YARA: {m.rule}")
                    result["verdict"] = "malicious"
            except Exception as e:
                log(f"[YARA] {path}: {e}")

        # 2. Эвристика по строкам
        data = b""
        try:
            with open(path, "rb") as f:
                data = f.read(2 * 1024 * 1024)
            for s in SUSPICIOUS_STRINGS:
                if s in data:
                    result["reasons"].append(f"String: {s.decode('utf-8', errors='ignore')}")
                    if result["verdict"] == "clean":
                        result["verdict"] = "suspicious"
        except Exception:
            pass

        # 3. Энтропия — только для файлов > 4 KB
        if data and len(data) > 4096:
            ent = entropy(data[:65536])
            if ent > 7.2:
                result["reasons"].append(f"High entropy: {ent:.2f}")
                if result["verdict"] == "clean":
                    result["verdict"] = "suspicious"

        # 4. PE-проверка
        if HAS_PEFILE and data[:2] == b"MZ":
            try:
                pe = pefile.PE(data=data, fast_load=True)
                pe.parse_data_directories(directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
                ])
                has_sig = hasattr(pe, "DIRECTORY_ENTRY_SECURITY")
                if not has_sig:
                    result["reasons"].append("PE: unsigned")
                pe.close()
            except Exception:
                pass

        return result

    def scan_path(self, path: str, callback=None) -> list:
        results = []
        if os.path.isfile(path):
            r = self.scan_file(path)
            results.append(r)
            if callback:
                callback(r)
            return results

        for root, _dirs, files in os.walk(path):
            for name in files:
                fp = os.path.join(root, name)
                r = self.scan_file(fp)
                results.append(r)
                if callback:
                    callback(r)
        return results


def quarantine_file(path: str) -> bool:
    ensure_dirs()
    try:
        name = os.path.basename(path)
        dest = os.path.join(QUARANTINE_DIR, f"{name}.quarantined")
        counter = 1
        while os.path.exists(dest):
            dest = os.path.join(QUARANTINE_DIR, f"{name}.{counter}.quarantined")
            counter += 1
        os.rename(path, dest)
        log(f"[QUARANTINE] {path} -> {dest}")
        return True
    except Exception as e:
        log(f"[QUARANTINE] fail {path}: {e}")
        return False


class AntivirusApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("KiwiAV — Antivirus")
        self.root.geometry("900x650")
        self.root.configure(bg="#1e1e1e")
        self.scanner = Scanner()
        self.found = []
        self.show_login()

    def show_login(self):
        for w in self.root.winfo_children():
            w.destroy()
        frame = tk.Frame(self.root, bg="#1e1e1e")
        frame.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(frame, text="KiwiAV", fg="#4CAF50", bg="#1e1e1e",
                 font=("Consolas", 36, "bold")).pack(pady=(0, 10))
        tk.Label(frame, text="Антивирус", fg="#888", bg="#1e1e1e",
                 font=("Consolas", 14)).pack(pady=(0, 40))
        tk.Label(frame, text="Введите ключ активации:", fg="#ccc", bg="#1e1e1e",
                 font=("Consolas", 12)).pack(pady=(0, 10))

        self.key_entry = tk.Entry(frame, bg="#2a2a2a", fg="#fff",
                                  insertbackground="#fff",
                                  font=("Consolas", 16), justify="center", width=25)
        self.key_entry.pack(pady=10)
        self.key_entry.focus()

        self.key_error = tk.Label(frame, text="", fg="#f44336", bg="#1e1e1e",
                                  font=("Consolas", 11))
        self.key_error.pack(pady=5)

        tk.Button(frame, text="ВОЙТИ", command=self.check_key,
                  bg="#4CAF50", fg="#fff", font=("Consolas", 14, "bold"),
                  bd=0, padx=40, pady=10, cursor="hand2").pack(pady=20)
        self.root.bind("<Return>", lambda e: self.check_key())

    def check_key(self):
        entered = self.key_entry.get().strip()
        h = hashlib.sha256(_SALT + entered.encode()).hexdigest()
        if h == CORRECT_HASH:
            self.root.unbind("<Return>")
            self.show_main_menu()
        else:
            self.key_error.config(text="❌ Неверный ключ")
            self.key_entry.delete(0, tk.END)

    def show_main_menu(self):
        for w in self.root.winfo_children():
            w.destroy()
        header = tk.Frame(self.root, bg="#4CAF50", height=60)
        header.pack(fill="x")
        tk.Label(header, text="KiwiAV — Активирован", fg="#fff", bg="#4CAF50",
                 font=("Consolas", 18, "bold")).pack(pady=15)

        btn_frame = tk.Frame(self.root, bg="#1e1e1e")
        btn_frame.pack(pady=20)
        buttons = [
            ("🔍 Сканировать систему", self.scan_system),
            ("📁 Сканировать папку", self.scan_folder),
            ("📄 Сканировать файл", self.scan_file),
            ("🧹 Полное сканирование", self.scan_full),
            ("📋 Логи", self.show_logs),
            ("🚪 Выход", self.root.destroy),
        ]
        for text, cmd in buttons:
            tk.Button(btn_frame, text=text, command=cmd,
                      bg="#2a2a2a", fg="#fff", font=("Consolas", 14),
                      bd=0, padx=20, pady=12, width=30, cursor="hand2",
                      activebackground="#3a3a3a", activeforeground="#fff").pack(pady=5)

        self.status_label = tk.Label(self.root, text="Готов к работе",
                                     fg="#888", bg="#1e1e1e", font=("Consolas", 11))
        self.status_label.pack(side="bottom", pady=10)

    def show_scan_window(self, title: str):
        for w in self.root.winfo_children():
            w.destroy()
        tk.Label(self.root, text=title, fg="#4CAF50", bg="#1e1e1e",
                 font=("Consolas", 18, "bold")).pack(pady=10)
        self.result_text = scrolledtext.ScrolledText(
            self.root, bg="#2a2a2a", fg="#ccc", font=("Consolas", 10),
            insertbackground="#fff", height=25)
        self.result_text.pack(fill="both", expand=True, padx=20, pady=10)
        self.progress_label = tk.Label(self.root, text="", fg="#888",
                                       bg="#1e1e1e", font=("Consolas", 11))
        self.progress_label.pack(pady=5)
        btn_frame = tk.Frame(self.root, bg="#1e1e1e")
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="← Назад", command=self.show_main_menu,
                  bg="#2a2a2a", fg="#fff", font=("Consolas", 12),
                  bd=0, padx=20, pady=8).pack()

    def append_result(self, r: dict):
        verdict = r["verdict"]
        color = {"clean": "#4CAF50", "suspicious": "#FFC107", "malicious": "#F44336"}[verdict]
        icon = {"clean": "✓", "suspicious": "⚠", "malicious": "✗"}[verdict]
        self.result_text.tag_config(verdict, foreground=color)
        self.result_text.insert("end", f"{icon} [{verdict.upper()}] {r['path']}\n", verdict)
        for reason in r["reasons"]:
            self.result_text.insert("end", f"    └ {reason}\n")
        if verdict != "clean":
            self.found.append(r)
        self.result_text.see("end")

    def scan_system(self):
        self._start_scan(os.environ.get("SystemDrive", "C:") + "\\", "Сканирование системы")

    def scan_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self._start_scan(folder, f"Сканирование: {folder}")

    def scan_file(self):
        file = filedialog.askopenfilename()
        if file:
            self._start_scan(file, f"Сканирование: {os.path.basename(file)}")

    def scan_full(self):
        self._start_scan(os.environ.get("SystemDrive", "C:") + "\\", "Полное сканирование")

    def _start_scan(self, path: str, title: str):
        self.found = []
        self.show_scan_window(title)
        self.progress_label.config(text="Сканирование...")

        def worker():
            try:
                self.scanner.scan_path(path, callback=self.append_result)
                self.root.after(0, self._scan_done)
            except Exception as e:
                self.root.after(0, lambda: self.progress_label.config(
                    text=f"Ошибка: {e}", fg="#F44336"))

        threading.Thread(target=worker, daemon=True).start()

    def _scan_done(self):
        threats = [r for r in self.found if r["verdict"] == "malicious"]
        suspicious = [r for r in self.found if r["verdict"] == "suspicious"]
        self.progress_label.config(
            text=f"Готово. Угроз: {len(threats)}, подозрительных: {len(suspicious)}",
            fg="#FFC107" if self.found else "#4CAF50")
        if threats:
            if messagebox.askyesno("Угрозы найдены",
                                   f"Найдено угроз: {len(threats)}.\n"
                                   f"Переместить в карантин?"):
                for r in threats:
                    quarantine_file(r["path"])

    def show_logs(self):
        for w in self.root.winfo_children():
            w.destroy()
        tk.Label(self.root, text="Логи сканирования", fg="#4CAF50", bg="#1e1e1e",
                 font=("Consolas", 18, "bold")).pack(pady=10)
        text = scrolledtext.ScrolledText(self.root, bg="#2a2a2a", fg="#ccc",
                                         font=("Consolas", 10), height=25)
        text.pack(fill="both", expand=True, padx=20, pady=10)
        try:
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r", encoding="utf-8") as f:
                    text.insert("1.0", f.read())
            else:
                text.insert("1.0", "Логов пока нет.")
        except Exception as e:
            text.insert("1.0", f"Ошибка чтения логов: {e}")
        text.config(state="disabled")
        tk.Button(self.root, text="← Назад", command=self.show_main_menu,
                  bg="#2a2a2a", fg="#fff", font=("Consolas", 12),
                  bd=0, padx=20, pady=8).pack(pady=10)


def main():
    ensure_dirs()
    log("=" * 50)
    log("KiwiAV запущен")
    root = tk.Tk()
    AntivirusApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

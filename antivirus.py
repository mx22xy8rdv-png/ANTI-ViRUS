# language: Python, file: antivirus.py
# Зависимости: yara-python, pefile, watchdog, cryptography, requests
# Сборка: pyinstaller --noconsole --onefile --name KiwiAV antivirus.py

import ctypes
import hashlib
import math
import os
import threading
import time
import tkinter as tk
from collections import Counter
from tkinter import filedialog, messagebox, scrolledtext, ttk

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

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

try:
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ================= НАСТРОЙКИ =================
_SALT = b"KiwiAV_Salt_2026"
CORRECT_HASH = hashlib.sha256(_SALT + b"KIWI_121892").hexdigest()

BASE_DIR = os.path.join(os.environ.get("APPDATA", "."), "KiwiAV")
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
LOG_FILE = os.path.join(BASE_DIR, "scan.log")
HASH_DB_FILE = os.path.join(BASE_DIR, "hashes.txt")
KEY_FILE = os.path.join(BASE_DIR, "quarantine.key")
YARA_EXTRA_FILE = os.path.join(BASE_DIR, "extra_rules.yar")

# Открытые источники (можно заменить на свои)
HASH_DB_URL = "https://raw.githubusercontent.com/advanced-threat-research/malware-hashes/main/hashes.txt"
YARA_RULES_URL = "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_AZORult.yar"

SUSPICIOUS_STRINGS = [
    b"CreateRemoteThread", b"VirtualAllocEx", b"WriteProcessMemory",
    b"\\\\.\\PhysicalDrive0", b"bcdedit", b"vssadmin delete shadows",
    b"powershell -enc", b"powershell -encodedcommand",
    b"mimikatz", b"lsass.exe", b"sekurlsa", b"NetUserAdd",
    b"SetWindowsHookEx", b"keybd_event", b"GetAsyncKeyState",
    b"CurrentVersion\\Run", b"schtasks /create", b"onlogon",
    b"NtRaiseHardError", b"ZwRaiseHardError", b"RtlAdjustPrivilege",
    b"CryptoAPI", b"CryptEncrypt", b"ransom", b"bitcoin",
]

YARA_RULES = r"""
rule Suspicious_Wiper_Strings {
    strings:
        $a = "\\\\.\\PhysicalDrive0" ascii wide
        $b = "bcdedit" ascii wide
        $c = "vssadmin delete shadows" ascii wide
        $d = "reagentc /disable" ascii wide
        $e = "NtRaiseHardError" ascii wide
    condition: 2 of them
}
rule Suspicious_Injection {
    strings:
        $a = "CreateRemoteThread" ascii wide
        $b = "VirtualAllocEx" ascii wide
        $c = "WriteProcessMemory" ascii wide
        $d = "NtCreateThreadEx" ascii wide
    condition: 2 of them
}
rule Suspicious_Keylogger {
    strings:
        $a = "SetWindowsHookEx" ascii wide
        $b = "GetAsyncKeyState" ascii wide
        $c = "keybd_event" ascii wide
        $d = "WH_KEYBOARD_LL" ascii wide
    condition: 2 of them
}
rule Suspicious_Persistence {
    strings:
        $a = "CurrentVersion\\Run" ascii wide
        $b = "schtasks /create" ascii wide
        $c = "onlogon" ascii wide
    condition: 2 of them
}
rule Suspicious_Ransomware {
    strings:
        $a = "CryptEncrypt" ascii wide
        $b = "CryptGenKey" ascii wide
        $c = "ransom" ascii wide
        $d = "bitcoin" ascii wide
        $e = "vssadmin delete shadows" ascii wide
    condition: 2 of them
}
rule Suspicious_PowerShell_Obfuscation {
    strings:
        $a = "powershell -enc" ascii wide
        $b = "powershell -encodedcommand" ascii wide
        $c = "FromBase64String" ascii wide
        $d = "IEX" ascii wide
        $e = "Invoke-Expression" ascii wide
    condition: 2 of them
}
rule Suspicious_AntiDebug {
    strings:
        $a = "IsDebuggerPresent" ascii wide
        $b = "CheckRemoteDebuggerPresent" ascii wide
        $c = "NtQueryInformationProcess" ascii wide
        $d = "OutputDebugString" ascii wide
    condition: 2 of them
}
rule Packed_HighEntropy {
    condition: math.entropy(0, filesize) > 7.2 and filesize > 10000
}
rule Suspicious_HiddenWindow {
    strings:
        $a = "ShowWindow" ascii wide
        $b = "SW_HIDE" ascii wide
        $c = "GetConsoleWindow" ascii wide
    condition: 2 of them
}
rule Suspicious_SelfDelete {
    strings:
        $a = "MoveFileEx" ascii wide
        $b = "DELAY_UNTIL_REBOOT" ascii wide
        $c = "cmd /c del" ascii wide
    condition: 2 of them
}
"""


# ================= УТИЛИТЫ =================
def ensure_dirs():
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    if not os.path.exists(KEY_FILE) and HAS_CRYPTO:
        with open(KEY_FILE, "wb") as f:
            f.write(Fernet.generate_key())


def log(msg: str):
    ensure_dirs()
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
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


def verify_signature(path: str) -> bool:
    """Проверка цифровой подписи через WinVerifyTrust."""
    try:
        class GUID(ctypes.Structure):
            _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                        ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]
        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [("cbStruct", ctypes.c_ulong), ("pcwszFilePath", ctypes.c_wchar_p),
                        ("hFile", ctypes.c_void_p), ("pgKnownSubject", ctypes.c_void_p)]
        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [("cbStruct", ctypes.c_ulong), ("pPolicyCallbackData", ctypes.c_void_p),
                        ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", ctypes.c_ulong),
                        ("fdwRevocationChecks", ctypes.c_ulong), ("dwUnionChoice", ctypes.c_ulong),
                        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)), ("dwStateAction", ctypes.c_ulong),
                        ("hWVTStateData", ctypes.c_void_p), ("pwszURLReference", ctypes.c_wchar_p),
                        ("dwProvFlags", ctypes.c_ulong), ("dwUIContext", ctypes.c_ulong)]
        action = GUID(0x00AAC56B, 0xCD44, 0x11d0, (ctypes.c_ubyte * 8)(0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee))
        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = path
        data = WINTRUST_DATA()
        data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        data.dwUIChoice = 2  # WTD_UI_NONE
        data.fdwRevocationChecks = 0  # WTD_REVOKE_NONE
        data.dwUnionChoice = 1  # WTD_CHOICE_FILE
        data.pFile = ctypes.pointer(file_info)
        data.dwStateAction = 0
        data.dwProvFlags = 0x00000010  # WTD_CACHE_ONLY_URL_RETRIEVAL
        ret = ctypes.windll.wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
        return ret == 0
    except Exception:
        return False


# ================= ДВИЖОК =================
class Scanner:
    def __init__(self):
        self.rules = None
        self.hash_db = set()
        self.load_yara()
        self.load_hashes()

    def load_yara(self):
        if not HAS_YARA:
            return
        try:
            sources = [YARA_RULES]
            if os.path.exists(YARA_EXTRA_FILE):
                try:
                    with open(YARA_EXTRA_FILE, "r", encoding="utf-8") as f:
                        sources.append(f.read())
                except Exception:
                    pass
            self.rules = yara.compile(source="\n".join(sources))
            log("[YARA] rules compiled")
        except Exception as e:
            log(f"[YARA] compile error: {e}")
            self.rules = None

    def load_hashes(self):
        if os.path.exists(HASH_DB_FILE):
            try:
                with open(HASH_DB_FILE, "r", encoding="utf-8") as f:
                    for line in f:
                        h = line.strip().lower()
                        if len(h) == 64:
                            self.hash_db.add(h)
                log(f"[HASH] loaded {len(self.hash_db)} hashes")
            except Exception as e:
                log(f"[HASH] load error: {e}")

    def update_from_github(self) -> bool:
        if not HAS_REQUESTS:
            return False
        ok = False
        try:
            r = requests.get(HASH_DB_URL, timeout=30)
            if r.status_code == 200 and r.text:
                with open(HASH_DB_FILE, "w", encoding="utf-8") as f:
                    f.write(r.text)
                self.hash_db = {l.strip().lower() for l in r.text.splitlines() if len(l.strip()) == 64}
                log(f"[HASH] updated, {len(self.hash_db)} hashes")
                ok = True
        except Exception as e:
            log(f"[HASH] update error: {e}")
        try:
            r = requests.get(YARA_RULES_URL, timeout=30)
            if r.status_code == 200 and r.text:
                with open(YARA_EXTRA_FILE, "w", encoding="utf-8") as f:
                    f.write(r.text)
                self.load_yara()
                ok = True
        except Exception as e:
            log(f"[YARA] update error: {e}")
        return ok

    def scan_file(self, path: str) -> dict:
        result = {"path": path, "verdict": "clean", "reasons": []}
        if not os.path.isfile(path):
            return result
        try:
            size = os.path.getsize(path)
            if size == 0:
                return result
        except Exception:
            return result

        # 1. Хеш
        h = sha256_file(path)
        if h and h in self.hash_db:
            result["verdict"] = "malicious"
            result["reasons"].append(f"Hash: {h[:16]}...")

        # 2. YARA
        if self.rules:
            try:
                matches = self.rules.match(path, timeout=15)
                for m in matches:
                    result["reasons"].append(f"YARA: {m.rule}")
                    result["verdict"] = "malicious"
            except Exception as e:
                log(f"[YARA] {path}: {e}")

        # 3. Эвристика строк
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

        # 4. Энтропия
        if data and len(data) > 4096:
            ent = entropy(data[:65536])
            if ent > 7.2:
                result["reasons"].append(f"High entropy: {ent:.2f}")
                if result["verdict"] == "clean":
                    result["verdict"] = "suspicious"

        # 5. PE-эвристика
        if HAS_PEFILE and data[:2] == b"MZ":
            try:
                pe = pefile.PE(data=data, fast_load=True)
                suspicious_sections = [b".packed", b".upx", b".aspack", b".petite"]
                for sec in pe.sections:
                    name = sec.Name.strip(b"\x00").lower()
                    for susp in suspicious_sections:
                        if susp in name:
                            result["reasons"].append(f"PE section: {name.decode(errors='ignore')}")
                            if result["verdict"] == "clean":
                                result["verdict"] = "suspicious"
                try:
                    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                    if ep == 0:
                        result["reasons"].append("PE: EntryPoint = 0")
                        if result["verdict"] == "clean":
                            result["verdict"] = "suspicious"
                except Exception:
                    pass
                pe.close()
            except Exception:
                pass

        # 6. Подпись (только для exe)
        if path.lower().endswith(".exe") and data[:2] == b"MZ":
            if not verify_signature(path):
                result["reasons"].append("PE: unsigned")
                if result["verdict"] == "clean":
                    result["verdict"] = "suspicious"

        return result

    def scan_path(self, path: str, callback=None, progress=None) -> list:
        results = []
        if os.path.isfile(path):
            r = self.scan_file(path)
            results.append(r)
            if callback:
                callback(r)
            return results
        total = sum(len(files) for _, _, files in os.walk(path))
        done = 0
        for root, _dirs, files in os.walk(path):
            for name in files:
                fp = os.path.join(root, name)
                r = self.scan_file(fp)
                results.append(r)
                if callback:
                    callback(r)
                done += 1
                if progress and total:
                    progress(done, total)
        return results


def encrypt_quarantine(path: str, dest: str) -> bool:
    if not HAS_CRYPTO:
        try:
            os.rename(path, dest)
            return True
        except Exception:
            return False
    try:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
        fernet = Fernet(key)
        with open(path, "rb") as f:
            data = f.read()
        encrypted = fernet.encrypt(data)
        with open(dest, "wb") as f:
            f.write(encrypted)
        os.remove(path)
        return True
    except Exception as e:
        log(f"[QUARANTINE] encrypt error: {e}")
        return False


def quarantine_file(path: str) -> bool:
    ensure_dirs()
    try:
        name = os.path.basename(path)
        dest = os.path.join(QUARANTINE_DIR, f"{name}.quarantined")
        counter = 1
        while os.path.exists(dest):
            dest = os.path.join(QUARANTINE_DIR, f"{name}.{counter}.quarantined")
            counter += 1
        ok = encrypt_quarantine(path, dest)
        if ok:
            log(f"[QUARANTINE] {path} -> {dest}")
        return ok
    except Exception as e:
        log(f"[QUARANTINE] fail {path}: {e}")
        return False


# ================= МОНИТОР =================
class MonitorHandler(FileSystemEventHandler):
    def __init__(self, scanner: Scanner, app):
        self.scanner = scanner
        self.app = app

    def on_created(self, event):
        if event.is_directory:
            return
        r = self.scanner.scan_file(event.src_path)
        if r["verdict"] != "clean":
            self.app.root.after(0, lambda: self.app.add_monitor_result(r))


class AntivirusApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("KiwiAV — Antivirus")
        self.root.geometry("1000x700")
        self.root.configure(bg="#1e1e1e")
        self.scanner = Scanner()
        self.found = []
        self.observer = None
        self.monitor_paths = []
        self.show_login()

    def show_login(self):
        for w in self.root.winfo_children():
            w.destroy()
        frame = tk.Frame(self.root, bg="#1e1e1e")
        frame.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(frame, text="KiwiAV", fg="#4CAF50", bg="#1e1e1e",
                 font=("Consolas", 36, "bold")).pack(pady=(0, 10))
        tk.Label(frame, text="Antivirus", fg="#888", bg="#1e1e1e",
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
        tk.Label(header, text="KiwiAV — Activated", fg="#fff", bg="#4CAF50",
                 font=("Consolas", 18, "bold")).pack(pady=15)
        btn_frame = tk.Frame(self.root, bg="#1e1e1e")
        btn_frame.pack(pady=20)
        buttons = [
            ("🔍 Сканировать систему", self.scan_system),
            ("📁 Сканировать папку", self.scan_folder),
            ("📄 Сканировать файл", self.scan_file),
            ("🧹 Полное сканирование", self.scan_full),
            ("👁 Монитор в реальном времени", self.toggle_monitor),
            ("🔄 Обновить базы", self.update_bases),
            ("📋 Логи", self.show_logs),
            ("🚪 Выход", self.root.destroy),
        ]
        for text, cmd in buttons:
            tk.Button(btn_frame, text=text, command=cmd,
                      bg="#2a2a2a", fg="#fff", font=("Consolas", 14),
                      bd=0, padx=20, pady=12, width=32, cursor="hand2",
                      activebackground="#3a3a3a", activeforeground="#fff").pack(pady=5)
        self.status_label = tk.Label(self.root,
                                     text=f"Готов. Хешей в базе: {len(self.scanner.hash_db)}",
                                     fg="#888", bg="#1e1e1e", font=("Consolas", 11))
        self.status_label.pack(side="bottom", pady=10)

    def show_scan_window(self, title: str):
        for w in self.root.winfo_children():
            w.destroy()
        tk.Label(self.root, text=title, fg="#4CAF50", bg="#1e1e1e",
                 font=("Consolas", 18, "bold")).pack(pady=10)
        self.result_text = scrolledtext.ScrolledText(
            self.root, bg="#2a2a2a", fg="#ccc", font=("Consolas", 10),
            insertbackground="#fff", height=22)
        self.result_text.pack(fill="both", expand=True, padx=20, pady=10)
        self.progress = ttk.Progressbar(self.root, orient="horizontal",
                                        length=800, mode="determinate")
        self.progress.pack(pady=5)
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

    def update_progress(self, done: int, total: int):
        if total:
            self.progress["value"] = done / total * 100
            self.progress_label.config(text=f"{done}/{total}")

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
                self.scanner.scan_path(path, callback=self.append_result,
                                       progress=self.update_progress)
                self.root.after(0, self._scan_done)
            except Exception as e:
                self.root.after(0, lambda: self.progress_label.config(
                    text=f"Ошибка: {e}", fg="#F44336"))

        threading.Thread(target=worker, daemon=True).start()

    def _scan_done(self):
        threats = [r for r in self.found if r["verdict"] == "malicious"]
        suspicious = [r for r in self.found if r["verdict"] == "suspicious"]
        self.progress["value"] = 100
        self.progress_label.config(
            text=f"Готово. Угроз: {len(threats)}, подозрительных: {len(suspicious)}",
            fg="#FFC107" if self.found else "#4CAF50")
        if threats:
            if messagebox.askyesno("Угрозы найдены",
                                   f"Найдено угроз: {len(threats)}.\n"
                                   f"Переместить в карантин?"):
                for r in threats:
                    quarantine_file(r["path"])

    def toggle_monitor(self):
        if self.observer is not None:
            self.observer.stop()
            self.observer.join()
            self.observer = None
            messagebox.showinfo("Монитор", "Монитор остановлен.")
            return
        if not HAS_WATCHDOG:
            messagebox.showerror("Монитор", "watchdog не установлен.")
            return
        paths = [
            os.path.join(os.environ.get("USERPROFILE", "."), "Downloads"),
            os.environ.get("TEMP", ""),
            os.path.join(os.environ.get("APPDATA", "."), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
            os.path.join(os.environ.get("USERPROFILE", "."), "Desktop"),
        ]
        self.observer = Observer()
        handler = MonitorHandler(self.scanner, self)
        for p in paths:
            if p and os.path.exists(p):
                self.observer.schedule(handler, p, recursive=True)
                log(f"[MONITOR] watch {p}")
        self.observer.start()
        messagebox.showinfo("Монитор", "Монитор запущен. Слежу за Downloads, Temp, Startup, Desktop.")

    def add_monitor_result(self, r: dict):
        messagebox.showwarning("Монитор",
                               f"Подозрительный файл:\n{r['path']}\n"
                               f"Вердикт: {r['verdict']}\n"
                               f"Причины: {', '.join(r['reasons'][:3])}")

    def update_bases(self):
        def worker():
            ok = self.scanner.update_from_github()
            self.root.after(0, lambda: messagebox.showinfo(
                "Обновление",
                f"Обновление {'успешно' if ok else 'не удалось'}.\n"
                f"Хешей: {len(self.scanner.hash_db)}"))
        threading.Thread(target=worker, daemon=True).start()

    def show_logs(self):
        for w in self.root.winfo_children():
            w.destroy()
        tk.Label(self.root, text="Логи", fg="#4CAF50", bg="#1e1e1e",
                 font=("Consolas", 18, "bold")).pack(pady=10)
        text = scrolledtext.ScrolledText(self.root, bg="#2a2a2a", fg="#ccc",
                                         font=("Consolas", 10), height=28)
        text.pack(fill="both", expand=True, padx=20, pady=10)
        try:
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r", encoding="utf-8") as f:
                    text.insert("1.0", f.read())
            else:
                text.insert("1.0", "Логов пока нет.")
        except Exception as e:
            text.insert("1.0", f"Ошибка: {e}")
        text.config(state="disabled")
        tk.Button(self.root, text="← Назад", command=self.show_main_menu,
                  bg="#2a2a2a", fg="#fff", font=("Consolas", 12),
                  bd=0, padx=20, pady=8).pack(pady=10)


def main():
    ensure_dirs()
    log("=" * 50)
    log("KiwiAV started")
    root = tk.Tk()
    AntivirusApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

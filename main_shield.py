import argparse
import ctypes
import os
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path

import cv2
import mss
import numpy as np
import pytesseract
import win32gui
import win32ui

from app_config import get_default_config_path, load_config
from vuln_words_dict import SynchronizedOCRDLP


user32 = ctypes.windll.user32

WPARAM = ctypes.c_ulonglong
LPARAM = ctypes.c_longlong
HWND = ctypes.c_void_p
LRESULT = ctypes.c_longlong

WNDPROCTYPE = ctypes.WINFUNCTYPE(LRESULT, HWND, ctypes.c_uint, WPARAM, LPARAM)

user32.DefWindowProcW.argtypes = [HWND, ctypes.c_uint, WPARAM, LPARAM]
user32.DefWindowProcW.restype = LRESULT
user32.SetWindowPos.argtypes = [HWND, HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_uint]
user32.SetLayeredWindowAttributes.argtypes = [HWND, ctypes.c_uint, ctypes.c_byte, ctypes.c_uint]
user32.SetWindowDisplayAffinity.argtypes = [HWND, ctypes.c_uint]
user32.DestroyWindow.argtypes = [HWND]
user32.DestroyWindow.restype = ctypes.c_bool


class WNDCLASSEX(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_uint),
        ("style", ctypes.c_uint),
        ("lpfnWndProc", WNDPROCTYPE),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", ctypes.c_void_p),
        ("hIcon", ctypes.c_void_p),
        ("hCursor", ctypes.c_void_p),
        ("hbrBackground", ctypes.c_void_p),
        ("lpszMenuName", ctypes.c_wchar_p),
        ("lpszClassName", ctypes.c_wchar_p),
        ("hIconSm", ctypes.c_void_p),
    ]


WS_POPUP = 0x80000000
WS_EX_LAYERED = 0x00080000
WS_EX_TRANSPARENT = 0x00000020
WS_EX_TOPMOST = 0x00000008
WS_EX_TOOLWINDOW = 0x00000080
LWA_ALPHA = 0x00000002
WDA_MONITOR = 0x00000001
SWP_NOACTIVATE = 0x0010
SWP_SHOWWINDOW = 0x0040

try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass


SETTINGS = {}
DLP_ENGINE = SynchronizedOCRDLP()
WHITELIST_WORDS = set()
BLACKLIST_WORDS = set()
ALLOWED_LEVELS = {3, 4, 5}

ACTIVE_THREATS = {}  # {hwnd: {"timestamp": float, "level": int, "words": list[str]}}
THREATS_LOCK = threading.Lock()
RUNNING = True
SHIELD_POOL_REF = []


def is_safescreen_title(title: str) -> bool:
    return "safescreen" in (title or "").lower()


def stdin_control_loop() -> None:
    global RUNNING

    try:
        while RUNNING:
            line = sys.stdin.readline()
            if line == "":
                break
            if line.strip().upper() == "STOP":
                print("[CTRL] Получена команда остановки.", flush=True)
                RUNNING = False
                break
    except Exception as exc:
        print(f"[ERR] stdin_control_loop: {exc}", flush=True)


def load_runtime_settings(config_path: Path | None = None) -> None:
    global SETTINGS, WHITELIST_WORDS, BLACKLIST_WORDS, ALLOWED_LEVELS

    SETTINGS = load_config(config_path)
    pytesseract.pytesseract.tesseract_cmd = SETTINGS["tesseract_cmd"]

    WHITELIST_WORDS = DLP_ENGINE.expand_custom_words(SETTINGS.get("whitelist_words", []))
    BLACKLIST_WORDS = DLP_ENGINE.expand_custom_words(SETTINGS.get("blacklist_words", []))

    protection_level = int(SETTINGS.get("protection_level", 3))
    min_dict_level = max(1, 6 - protection_level)
    ALLOWED_LEVELS = set(range(min_dict_level, 6))

    print(f"[CONFIG] Loaded config from: {config_path or get_default_config_path()}", flush=True)
    print(
        f"[CONFIG] protection_level={protection_level}, dict_levels={sorted(ALLOWED_LEVELS)}, recheck={SETTINGS['recheck_interval']}, "
        f"memory={SETTINGS['memory_duration']}, max_windows={SETTINGS['max_windows_to_check']}",
        flush=True,
    )


class WinApiShield:
    def __init__(self, id_num):
        self.hwnd = self._create_window(id_num)
        self.covering_hwnd = None
        if self.hwnd:
            user32.SetLayeredWindowAttributes(self.hwnd, 0, 1, LWA_ALPHA)
            try:
                user32.SetWindowDisplayAffinity(self.hwnd, WDA_MONITOR)
            except Exception:
                pass

    def _create_window(self, id_num):
        def wnd_proc(hwnd, msg, w_param, l_param):
            try:
                return user32.DefWindowProcW(hwnd, msg, w_param, l_param)
            except Exception:
                return 0

        self.wnd_proc = WNDPROCTYPE(wnd_proc)
        class_name = f"ShieldHyb_{id_num}"
        h_inst = ctypes.windll.kernel32.GetModuleHandleW(None)

        wnd_class = WNDCLASSEX()
        wnd_class.cbSize = ctypes.sizeof(WNDCLASSEX)
        wnd_class.style = 0
        wnd_class.lpfnWndProc = self.wnd_proc
        wnd_class.hInstance = h_inst
        wnd_class.lpszClassName = class_name
        user32.RegisterClassExW(ctypes.byref(wnd_class))

        return user32.CreateWindowExW(
            WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
            class_name,
            "Shield",
            WS_POPUP,
            -1000,
            -1000,
            10,
            10,
            None,
            None,
            h_inst,
            None,
        )

    def move(self, rect):
        if not self.hwnd:
            return
        x, y, w, h = rect
        padding = int(SETTINGS["shield_padding"])
        safe_x = x - padding
        safe_y = y - padding
        safe_w = w + (padding * 2)
        safe_h = h + (padding * 2)
        user32.SetWindowPos(
            self.hwnd,
            ctypes.c_void_p(-1),
            int(safe_x),
            int(safe_y),
            int(safe_w),
            int(safe_h),
            SWP_NOACTIVATE | SWP_SHOWWINDOW,
        )

    def set_transparent(self, transparent=True):
        if not self.hwnd:
            return
        if transparent:
            user32.SetLayeredWindowAttributes(self.hwnd, 0, 0, LWA_ALPHA)
        else:
            user32.SetLayeredWindowAttributes(self.hwnd, 0, 1, LWA_ALPHA)

    def hide(self):
        self.covering_hwnd = None
        if self.hwnd:
            user32.SetWindowPos(self.hwnd, 0, -5000, -5000, 0, 0, SWP_NOACTIVATE)

    def destroy(self):
        if self.hwnd:
            try:
                user32.DestroyWindow(self.hwnd)
            except Exception:
                pass
            self.hwnd = None


def capture_window_xray(hwnd):
    try:
        left, top, right, bottom = win32gui.GetWindowRect(hwnd)
        w = right - left
        h = bottom - top
        if w <= 0 or h <= 0:
            return None

        hwnd_dc = win32gui.GetWindowDC(hwnd)
        mfc_dc = win32ui.CreateDCFromHandle(hwnd_dc)
        save_dc = mfc_dc.CreateCompatibleDC()
        save_bitmap = win32ui.CreateBitmap()
        save_bitmap.CreateCompatibleBitmap(mfc_dc, w, h)
        save_dc.SelectObject(save_bitmap)

        result = ctypes.windll.user32.PrintWindow(hwnd, save_dc.GetSafeHdc(), 2)
        if result == 0:
            ctypes.windll.user32.PrintWindow(hwnd, save_dc.GetSafeHdc(), 0)

        bmp_info = save_bitmap.GetInfo()
        bmp_str = save_bitmap.GetBitmapBits(True)

        win32gui.DeleteObject(save_bitmap.GetHandle())
        save_dc.DeleteDC()
        mfc_dc.DeleteDC()
        win32gui.ReleaseDC(hwnd, hwnd_dc)

        img = np.frombuffer(bmp_str, dtype=np.uint8).reshape((bmp_info["bmHeight"], bmp_info["bmWidth"], 4))
        if np.sum(img) < 1000:
            return None
        return img[:, :, :3]
    except Exception:
        return None


def is_valid_window(hwnd):
    if not win32gui.IsWindowVisible(hwnd):
        return False
    if win32gui.IsIconic(hwnd):
        return False

    try:
        title = win32gui.GetWindowText(hwnd).lower()
    except Exception:
        return False

    if not title:
        return False
    try:
        class_name = win32gui.GetClassName(hwnd).lower()
    except Exception:
        return False
    try:
        rect = win32gui.GetWindowRect(hwnd)
        w = rect[2] - rect[0]
        h = rect[3] - rect[1]
        if w < 20 or h < 20:
            return False
    except Exception:
        return False

    return True


def get_window_title_safe(hwnd):
    try:
        return win32gui.GetWindowText(hwnd) or ""
    except Exception:
        return ""


def get_smart_windows():
    windows = []
    safescreen_windows = []

    def enum_cb(hwnd, _ctx):
        if not is_valid_window(hwnd):
            return

        title = get_window_title_safe(hwnd)
        if is_safescreen_title(title):
            safescreen_windows.append(hwnd)
            return

        if len(windows) < SETTINGS["max_windows_to_check"]:
            windows.append(hwnd)

    try:
        win32gui.EnumWindows(enum_cb, None)
    except Exception:
        pass

    return safescreen_windows + windows


def scan_window_for_hits(hwnd, sct):
    img = capture_window_xray(hwnd)

    if img is None:
        shield = None
        for item in SHIELD_POOL_REF:
            if item.covering_hwnd == hwnd:
                shield = item
                break

        if shield:
            shield.set_transparent(True)
            time.sleep(0.02)

        try:
            rect = win32gui.GetWindowRect(hwnd)
            w = rect[2] - rect[0]
            h = rect[3] - rect[1]
            monitor = {"top": rect[1], "left": rect[0], "width": w, "height": h}
            raw = np.array(sct.grab(monitor))
            img = cv2.cvtColor(raw, cv2.COLOR_BGRA2BGR)
        except Exception:
            if shield:
                shield.set_transparent(False)
            return []

        if shield:
            shield.set_transparent(False)

    try:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)[1]
        text = pytesseract.image_to_string(thresh, lang="rus+eng", config="--psm 6")
        return DLP_ENGINE.scan_text(
            text,
            language="all",
            allowed_levels=ALLOWED_LEVELS,
            whitelist=WHITELIST_WORDS,
            blacklist=BLACKLIST_WORDS,
        )
    except Exception:
        return []


def emit_event(hwnd, hits):
    if not hits:
        return

    level = max(hit["level"] for hit in hits)
    words = sorted({hit["word"] for hit in hits})[:6]

    try:
        title = win32gui.GetWindowText(hwnd)
    except Exception:
        title = "<unknown>"

    safe_title = title.replace("|", "/").replace("\n", " ").strip()
    safe_words = ",".join(word.replace("|", "/") for word in words)
    print(f"[EVENT]|kind=threat|level={level}|title={safe_title}|words={safe_words}", flush=True)


def emit_clear_event(hwnd, reason, info=None):
    try:
        title = win32gui.GetWindowText(hwnd)
    except Exception:
        title = "<unknown>"

    safe_title = title.replace("|", "/").replace("\n", " ").strip()
    level = 0
    words = ""
    if info:
        level = int(info.get("level", 0) or 0)
        words = ",".join(str(word).replace("|", "/") for word in info.get("words", [])[:6])
    print(
        f"[EVENT]|kind=clear|level={level}|title={safe_title}|words={words}|reason={reason}",
        flush=True,
    )


def make_threat_payload(hits):
    return {
        "timestamp": time.time(),
        "level": max(hit["level"] for hit in hits),
        "words": sorted({hit["word"] for hit in hits})[:8],
        "silent": False,
    }


def threat_signature(info):
    if not info:
        return None
    return (int(info.get("level", 0)), tuple(info.get("words", [])))


def scanner_loop():
    global ACTIVE_THREATS

    with mss.mss() as sct:
        print("--- СКАНЕР ЗАПУЩЕН ---", flush=True)

        while RUNNING:
            try:
                targets = get_smart_windows()
                current_time = time.time()
                targets_set = set(targets)

                for hwnd in targets:
                    title = get_window_title_safe(hwnd)
                    if is_safescreen_title(title):
                        with THREATS_LOCK:
                            ACTIVE_THREATS[hwnd] = {
                                "timestamp": current_time,
                                "level": 5,
                                "words": ["safescreen"],
                                "silent": True,
                            }
                        continue

                    with THREATS_LOCK:
                        threat_info = ACTIVE_THREATS.get(hwnd)

                    is_known_threat = threat_info is not None
                    time_elapsed = current_time - (threat_info["timestamp"] if threat_info else 0)
                    should_scan = (not is_known_threat) or (time_elapsed > SETTINGS["recheck_interval"])

                    if not should_scan:
                        continue

                    hits = scan_window_for_hits(hwnd, sct)

                    if hits:
                        new_info = make_threat_payload(hits)
                        should_emit = (not is_known_threat) or (threat_signature(threat_info) != threat_signature(new_info))
                        with THREATS_LOCK:
                            ACTIVE_THREATS[hwnd] = new_info
                        if should_emit:
                            emit_event(hwnd, hits)
                    elif is_known_threat and time_elapsed > SETTINGS["memory_duration"]:
                        with THREATS_LOCK:
                            removed = ACTIVE_THREATS.pop(hwnd, None)
                        if removed and not removed.get("silent"):
                            emit_clear_event(hwnd, "rescanned_clean", removed)

                with THREATS_LOCK:
                    stale_hwnds = []
                    for hwnd, info in ACTIVE_THREATS.items():
                        if (hwnd not in targets_set) or (not win32gui.IsWindow(hwnd)):
                            stale_hwnds.append(hwnd)
                    for hwnd in stale_hwnds:
                        removed = ACTIVE_THREATS.pop(hwnd, None)
                        if removed and not removed.get("silent"):
                            emit_clear_event(hwnd, "window_gone", removed)

            except Exception as exc:
                print(f"[ERR] scanner_loop: {exc}", flush=True)

            time.sleep(SETTINGS["scanner_sleep"])


def parse_args():
    parser = argparse.ArgumentParser(description="SafeScreen shield runtime")
    parser.add_argument("--config", type=str, default=None, help="Path to settings JSON")
    return parser.parse_args()


def resolve_config_path(arg_value: str | None) -> Path:
    if arg_value:
        return Path(arg_value).expanduser().resolve()
    from_env = os.environ.get("SAFESCREEN_CONFIG")
    if from_env:
        return Path(from_env).expanduser().resolve()
    return get_default_config_path()


if __name__ == "__main__":
    args = parse_args()
    config_path = resolve_config_path(args.config)
    load_runtime_settings(config_path)

    shield_pool = [WinApiShield(i) for i in range(SETTINGS["max_windows_to_check"])]
    SHIELD_POOL_REF = shield_pool

    scanner_thread = threading.Thread(target=scanner_loop, daemon=True)
    scanner_thread.start()
    control_thread = threading.Thread(target=stdin_control_loop, daemon=True)
    control_thread.start()

    print("--- ЗАЩИТА АКТИВНА ---", flush=True)
    print("Нажмите Ctrl+C для выхода.", flush=True)

    try:
        while RUNNING:
            with THREATS_LOCK:
                threat_hwnds = list(ACTIVE_THREATS.keys())

            for index, shield in enumerate(shield_pool):
                if index < len(threat_hwnds):
                    hwnd = threat_hwnds[index]
                    try:
                        if win32gui.IsWindow(hwnd):
                            rect = win32gui.GetWindowRect(hwnd)
                            w = rect[2] - rect[0]
                            h = rect[3] - rect[1]
                            shield.covering_hwnd = hwnd
                            shield.move((rect[0], rect[1], w, h))
                        else:
                            shield.hide()
                    except Exception:
                        shield.hide()
                else:
                    shield.hide()

            msg = wintypes.MSG()
            if user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 1):
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))

            time.sleep(0.02)

    except KeyboardInterrupt:
        print("\nВыход...", flush=True)
        RUNNING = False
    finally:
        for shield in shield_pool:
            shield.destroy()
        sys.exit(0)

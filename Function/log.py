
from __future__ import annotations
import re
import sys
import time
import os
import asyncio
import ctypes

_ANSI = re.compile(r'\x1b\[[0-9;]*m')

def _vlen(s: str) -> int:
    return len(_ANSI.sub('', s))

def _rpad(colored: str, width: int) -> str:
    return colored + ' ' * max(0, width - _vlen(colored))

class C:
    RESET = "\x1b[0m"
    DIM = "\x1b[2m"
    BOLD = "\x1b[1m"
    RED = "\x1b[38;5;203m"
    GREEN = "\x1b[38;5;82m"
    YELLOW = "\x1b[38;5;221m"
    BLUE = "\x1b[38;5;75m"
    CYAN = "\x1b[38;5;87m"
    MAGENTA = "\x1b[38;5;213m"
    GRAY = "\x1b[38;5;245m"
    ORANGE = "\x1b[38;5;215m"


if sys.platform == "win32":
    try:
        ctypes.windll.kernel32.SetConsoleMode(ctypes.windll.kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR") or os.environ.get("WT_SESSION") or os.environ.get("COLORTERM"):
        return True
    return sys.stdout.isatty()


_colors = _supports_color()
_retry_state: tuple[int, int, float] | None = None  # (attempt, max, elapsed)


def _c(code: str, s: str) -> str:
    if not _colors:
        return s
    return f"{code}{s}{C.RESET}"


def set_retry(attempt: int, max_attempts: int, elapsed: float) -> None:
    global _retry_state
    _retry_state = (attempt, max_attempts, elapsed)


def banner(title: str):
    os.system("cls" if os.name == "nt" else "clear")
    line = "━" * 60
    print()
    print(_c(C.CYAN, line))
    print(_c(C.BOLD + C.CYAN, f"  {title}"))
    if _retry_state:
        n, total, elapsed = _retry_state
        if n == 1:
            print(f"  {_c(C.DIM + C.GRAY, f'Intento {n}/{total}')}")
        else:
            print(f"  {_c(C.BOLD + C.RED, f'Reintento {n}/{total}  —  {elapsed:.0f}s')}")
    print(_c(C.CYAN, line))


def step(num: int | str, title: str):
    print()
    tag = _c(C.CYAN + C.BOLD, f"[{num}]")
    print(f"{tag} {_c(C.BOLD, title)}")


def info(msg: str, value: str = None):
    prefix = _c(C.DIM + C.GRAY, "│  ")
    if value is not None:
        print(f"{prefix}{_c(C.GRAY, msg.ljust(18))} {_c(C.CYAN, str(value))}")
    else:
        print(f"{prefix}{msg}")


def ok(msg: str):
    arrow = _c(C.GREEN, "✓")
    print(f"{_c(C.DIM + C.GRAY, '│  ')}{arrow} {msg}")


def warn(msg: str):
    arrow = _c(C.YELLOW, "!")
    print(f"{_c(C.DIM + C.GRAY, '│  ')}{arrow} {_c(C.YELLOW, msg)}")


def fail(msg: str):
    arrow = _c(C.RED, "✗")
    print(f"{_c(C.DIM + C.GRAY, '│  ')}{arrow} {_c(C.RED, msg)}")


def highlight(label: str, value: str, color: str = C.MAGENTA):
    print()
    print(f"  {_c(C.DIM, label)}: {_c(C.BOLD + color, value)}")
    print()


def success(msg: str):
    print()
    print(_c(C.BOLD + C.GREEN, f"  ★ {msg}"))
    print()


def error(msg: str):
    print()
    print(_c(C.BOLD + C.RED, f"  ✗ {msg}"))
    print()


def box(rows: list[tuple[str, str]], title: str = "") -> None:
    label_w = max((len(k) for k, _ in rows), default=0)
    val_w   = max((len(v) for _, v in rows), default=0)
    inner   = max(64, label_w + val_w + 8)

    if title:
        pad = (inner - len(title) - 2) // 2
        top = "─" * pad + f" {title} " + "─" * (inner - pad - len(title) - 2)
    else:
        top = "─" * inner

    print()
    print(_c(C.CYAN, f"┌{top}┐"))
    for k, v in rows:
        cell = f"  {_c(C.GRAY, k.ljust(label_w))} : {_c(C.YELLOW, v)}"
        print(f"{_c(C.CYAN, '│')}{_rpad(cell, inner)}{_c(C.CYAN, '│')}")
    print(_c(C.CYAN, f"└{'─' * inner}┘"))


def ok_kv(label: str, value: str) -> None:
    arrow = _c(C.GREEN, "✓")
    print(f"{_c(C.DIM + C.GRAY, '│  ')}{arrow} {_c(C.GREEN, label.ljust(14))} {_c(C.CYAN, value)}")


def cookie_summary(cookies: list) -> None:
    by_name = {c["name"]: c["value"] for c in cookies}
    rows = [
        ("session-id",    by_name.get("session-id", "-")),
        ("ubid-main",     by_name.get("ubid-main", "-")),
        ("session-token", (by_name.get("session-token", "-")[:60] + "…") if by_name.get("session-token") else "-"),
        ("Total cookies", f"{len(cookies)} guardadas"),
    ]
    box(rows, title="COOKIES (RESUMEN)")


def result_summary(email: str, password: str, estado: str, tiempo: str,
                   archivo: str, folder: str) -> None:
    summary_box(
        [("Email", email), ("Password", password), ("Estado", estado), ("Tiempo", tiempo)],
        [("Archivo", archivo), ("Cookies file", folder)],
    )


def summary_box(left: list[tuple[str, str]], right: list[tuple[str, str]]) -> None:
    lw    = max((len(k) for k, _ in left + right), default=0)
    col_l = 42
    col_r = 36
    n     = max(len(left), len(right))

    print()
    print(_c(C.CYAN, f"┌{'─' * col_l}┬{'─' * col_r}┐"))
    for i in range(n):
        lk, lv = left[i]  if i < len(left)  else ("", "")
        rk, rv = right[i] if i < len(right) else ("", "")
        lcell = f"  {_c(C.GRAY, lk.ljust(lw))} : {_c(C.GREEN, lv)}" if lk else ""
        rcell = f"  {_c(C.GRAY, rk.ljust(lw))} : {_c(C.CYAN, rv)}" if rk else ""
        print(f"{_c(C.CYAN, '│')}{_rpad(lcell, col_l)}{_c(C.CYAN, '│')}{_rpad(rcell, col_r)}{_c(C.CYAN, '│')}")
    print(_c(C.CYAN, f"└{'─' * col_l}┴{'─' * col_r}┘"))
    print()


class Timer:
    def __init__(self, label: str):
        self.label = label
        self.start = None

    def __enter__(self):
        self.start = time.time()
        return self

    def __exit__(self, *args):
        elapsed = time.time() - self.start
        info(self.label, f"{elapsed:.2f}s")


def dim(s: str) -> str:
    return _c(C.DIM + C.GRAY, s)


def cyan(s: str) -> str:
    return _c(C.CYAN, s)


def green(s: str) -> str:
    return _c(C.GREEN, s)


def yellow(s: str) -> str:
    return _c(C.YELLOW, s)


def magenta(s: str) -> str:
    return _c(C.MAGENTA, s)


class Loader:
    def __init__(self, desc="Procesando..."):
        self.desc = desc
        self.frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self._task = None

    async def _spin(self):
        idx = 0
        try:
            while True:
                f = self.frames[idx % len(self.frames)]
                sys.stdout.write(f"\r {_c(C.CYAN, f)} {_c(C.DIM + C.GRAY, self.desc)}")
                sys.stdout.flush()
                idx += 1
                await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            pass

    async def __aenter__(self):
        self._task = asyncio.create_task(self._spin())
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._task:
            self._task.cancel()
            try:

                await self._task
            except asyncio.CancelledError:
                pass
                
        sys.stdout.write("\r\033[K")
        
        if exc_type is not None:
            sys.stdout.write(f"\r {_c(C.RED, '✗')} {_c(C.RED, self.desc)}")
        else:
            sys.stdout.write(f"\r {_c(C.GREEN, '✓')} {_c(C.GREEN, self.desc)}")
            
        sys.stdout.flush()

        await asyncio.sleep(0.1)
        
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()

    def update(self, desc):
        self.desc = desc
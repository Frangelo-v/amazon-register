import asyncio
import time
from pathlib import Path

import Function.log as log
from Function.amazon import Outcome
from Function.amazonphone import run

MAX_ATTEMPTS    = 1
ATTEMPT_TIMEOUT = 90
OVERALL_BUDGET  = 900

_COOKIES_DIR = Path(__file__).resolve().parent / "cookies"


def _folders() -> set[str]:
    return {f.name for f in _COOKIES_DIR.iterdir() if f.is_dir()} if _COOKIES_DIR.exists() else set()


def _cookie_str(folder: str) -> str:
    p = _COOKIES_DIR / folder / "cookie-string.txt"
    return p.read_text(encoding="utf-8").strip() if p.exists() else ""


async def main():
    start   = time.time()
    before  = _folders()
    outcome = None

    for attempt in range(1, MAX_ATTEMPTS + 1):
        elapsed = time.time() - start

        if elapsed > OVERALL_BUDGET:
            log.warn(f"Budget agotado ({OVERALL_BUDGET}s)")
            break

        log.set_retry(attempt, MAX_ATTEMPTS, elapsed)

        try:
            outcome = await asyncio.wait_for(run(), timeout=ATTEMPT_TIMEOUT)
        except asyncio.TimeoutError:
            log.warn(f"Timeout {ATTEMPT_TIMEOUT}s — intento {attempt}/{MAX_ATTEMPTS}")
            continue
        except KeyboardInterrupt:
            log.warn("Interrumpido")
            return
        except Exception as e:
            log.warn(f"Intento {attempt}/{MAX_ATTEMPTS}: {e}")
            continue

        if outcome is Outcome.SUCCESS:
            break

        log.warn(f"Intento {attempt}/{MAX_ATTEMPTS} terminó: {outcome.name if outcome else '?'}")

    elapsed = time.time() - start

    if outcome is not Outcome.SUCCESS:
        log.error(f"Falló tras {attempt} intento(s) — {outcome.name if outcome else 'TIMEOUT'}  ({elapsed:.0f}s)")
        return

    new = _folders() - before
    if not new:
        log.error("SUCCESS pero sin carpeta de cookies nueva")
        return

    folder = sorted(new)[-1]
    cs     = _cookie_str(folder)

    if not cs:
        log.error(f"Sin cookie-string.txt en {folder}")
        return

    log.step("■", "Cookie string")
    log.info("email",   folder)
    log.info("tiempo",  f"{elapsed:.0f}s")
    log.info("tamaño",  f"{len(cs)} chars")
    print()
    print(f"cookie: {cs}")
    print()


if __name__ == "__main__":
    asyncio.run(main())

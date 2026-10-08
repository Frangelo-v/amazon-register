from __future__ import annotations

import os
import re
import json
import uuid
import time
import base64
import random
import asyncio
from enum import Enum, auto
from pathlib import Path
from typing import Callable, Awaitable
from urllib.parse import urljoin

from dotenv import load_dotenv
from curl_cffi import AsyncSession

import Function.log as log
from encrypt import gen_frc_cookie
from device import new_ios_device

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

_COOKIES_DIR = Path(__file__).resolve().parents[1] / "cookies"

AMAZON_DOMAIN = os.getenv("AMAZON_ENTRY", "www.amazon.com").strip() or "www.amazon.com"
AMAZON_BASE   = f"https://{AMAZON_DOMAIN}"

AUTH_COOKIES = frozenset({"at-main", "sess-at-main", "x-main", "at_main"})

NAV_HEADERS = {
    "content-type":    "application/x-www-form-urlencoded",
    "origin":          AMAZON_BASE,
    "accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "accept-language": "es-419,es;q=0.9",
    "accept-encoding": "gzip, deflate, br, zstd",
    "sec-fetch-site":  "same-origin",
    "sec-fetch-mode":  "navigate",
    "sec-fetch-dest":  "document",
    "priority":        "u=0, i",
}

_NET_ERRORS = frozenset(("proxy", "closed", "(97)", "(56)", "(52)", "(35)", "(28)",
                          "reset", "timeout", "connection", "eof"))

_PROXY_RE = re.compile(r"(https?://|socks5://)([^:]+):([^@]+)@(.+)")


class Outcome(Enum):
    SUCCESS    = auto()
    PHONE_GATE = auto()
    FAILED     = auto()


OtpCallable = Callable[[], Awaitable[str]]


def _resolve_proxy(proxy: str | None) -> str | None:
    if not proxy or not (m := _PROXY_RE.match(proxy)):
        return proxy or None

    scheme, user, pwd, host = m.groups()
    if "dataimpulse" in host.lower() and "sessid" not in user.lower():
        user += f";sessid-{uuid.uuid4().hex[:12]};sesstime-10"

    return f"{scheme}{user}:{pwd}@{host}"


def _patch_retrying(session: AsyncSession) -> None:
    orig = session.request

    async def _retrying(*args, **kwargs):
        kwargs.setdefault("timeout", 40)
        for attempt in range(6):
            try:
                return await orig(*args, **kwargs)
            except Exception as exc:
                if not any(t in str(exc).lower() for t in _NET_ERRORS):
                    raise
                log.warn(f"[NET] retry {attempt+1}/6  {str(exc).lower()[:50]}")
                await asyncio.sleep(attempt + 1)
        raise RuntimeError("Network failed after max retries")

    session.request = _retrying


def make_session() -> tuple[AsyncSession, dict]:
    dev = new_ios_device()
    try:    session = AsyncSession(impersonate=dev["tls_profile"])
    except: session = AsyncSession(impersonate="safari_ios")

    log.info(f"TLS  impersonate={session.impersonate}  ios={dev['ios_version']}")
    session.trust_env = False
    session.headers.update({
        "User-Agent":      dev["ua"],
        "accept":          NAV_HEADERS["accept"],
        "accept-language": dev["accept_language"],
        "accept-encoding": "gzip, deflate, br, zstd",
        "sec-fetch-mode":  "navigate",
        "sec-fetch-dest":  "document",
        "priority":        "u=0, i",
    })

    map_md = {
        "device_user_dictionary":   [],
        "device_registration_data": {"software_version": "2"},
        "app_identifier":           {"app_version": dev["app"]["version"], "bundle_id": dev["app"]["bundle"]},
    }
    frc, _ = gen_frc_cookie(device=dev)
    for name, val in {
        "frc":         frc,
        "map-md":      base64.b64encode(json.dumps(map_md, separators=(",", ":")).encode()).decode().rstrip("="),
        "amzn-app-id": "MAPiOSLib/6.0/ToHideRetailLink",
    }.items():
        session.cookies.set(name, val, domain=".amazon.com")

    if proxy := _resolve_proxy(os.getenv("REQ_PROXY")):
        session.proxies = {"http": proxy, "https": proxy}

    _patch_retrying(session)
    return session, dev


def form_inputs(form) -> dict:
    return {n["name"]: n.get("value", "") for n in form.find_all("input") if n.get("name")}


def form_action(form, base: str) -> str:
    url = form.get("action") or base
    return (url if url.startswith("http") else urljoin(base, url)).replace(":443/", "/")


def find_register_form(soup):
    return (soup.find("form", {"name": "ap_register_form"})
         or soup.find("form", {"id":   "ap_register_form"})
         or next((f for f in soup.find_all("form") if f.find("input", {"name": "customerName"})), None))


def find_login_email_form(soup):
    return (soup.find("form", {"id": "ap_login_form"})
         or soup.find("form", {"name": "signIn"})
         or next((f for f in soup.find_all("form")
                  if f.find("input", {"name": "email"}) and not f.find("input", {"name": "password"})), None))


def find_login_password_form(soup):
    for sel in ({"id": "ap_password_form"}, {"id": "auth-password-form"}, {"name": "signIn"}):
        if (f := soup.find("form", sel)) and f.find("input", {"name": "password"}):
            return f

    return next((f for f in soup.find_all("form") if f.find("input", {"name": "password"})), None)


def find_otp_form(soup):
    if f := (soup.find("form", {"id": "verification-code-form"})
          or soup.find("form", {"id": "cvf-input-code-form"})):
        return f

    for f in soup.find_all("form"):
        a = f.find("input", {"name": "action"})
        if f.find("input", {"name": "code"}) and a and a.get("value") == "code":
            return f

    return next((f for f in soup.find_all("form") if f.find("input", {"name": "code"})), None)


def is_otp_page(soup) -> bool:
    return (any(f.find("input", {"name": "code"}) and f.find("input", {"name": "verifyToken"})
                for f in soup.find_all("form"))
         or any(w in soup.get_text(" ", strip=True).lower() for w in (
                "verification code", "ingresa el código", "we sent a code",
                "código de seguridad", "one time password")))


def detect_challenge(html: str) -> str:
    if not any(k in html for k in ("cvf-aamation-challenge-form", "data-challenge-type")):
        return ""

    if m := re.search(r'data-challenge-type"?\s*[:=]\s*"([^"]+)"', html):
        c, u = m.group(1), m.group(1).upper()
        return f"WAF GRID [{c}]" if "GRID" in u else f"ARKOSE [{c}]" if "ARKOSE" in u else c

    return "ARKOSE" if "arkose" in html.lower() or "funcaptcha" in html.lower() else "Aamation Challenge"


def extract_error(soup) -> str:
    box = soup.find(id=re.compile("auth-error-message-box", re.I))
    if not box or "aok-hidden" in box.get("class", []):
        return ""

    for item in box.find_all(["li", "div"]):
        if len(t := item.get_text(" ", strip=True)) > 3 and "surgido un problema" not in t.lower():
            return t

    return ""


def wants_phone(soup) -> bool:
    return bool(
        soup.find("input", {"name": re.compile("phone|mobile", re.I),
                             "type": re.compile("tel|text|number", re.I)})
        or soup.find("form", {"id": re.compile(r"phone|cvf.*phone", re.I)})
    )


def export_cookies(session: AsyncSession, email: str, password: str) -> Path:
    cookies = [
        {
            "name":    c.name,
            "value":   c.value,
            "domain":  c.domain or ".amazon.com",
            "path":    c.path or "/",
            "secure":  bool(getattr(c, "secure", True)),
            "expires": getattr(c, "expires", None),
        }
        for c in session.cookies.jar
    ]

    folder     = _COOKIES_DIR / re.sub(r"[^A-Za-z0-9_.@-]", "_", email)
    folder.mkdir(parents=True, exist_ok=True)
    cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)

    (folder / "cookies.json").write_text(json.dumps(cookies, indent=2, ensure_ascii=False), encoding="utf-8")
    (folder / "cookie-string.txt").write_text(cookie_str, encoding="utf-8")
    (folder / "account.txt").write_text(
        "\n".join(["email: " + email, "password: " + password, "", "cookies:",
                   *[f"{c['name']}={c['value']}" for c in cookies]]),
        encoding="utf-8",
    )

    log.ok("Registro confirmado")
    log.info("[cookies] saved", str(folder))
    log.cookie_summary(cookies)

    return folder


class SmailProClient:
    _BASE    = "https://smailpro.com"
    _SITEKEY = "0x4AAAAAAABIS_gEec2IwOhI"
    _SONJJ   = "https://api.sonjj.com/v1/temp_gmail"
    _UA      = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36")
    _CH_UA   = '"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"'

    def __init__(self) -> None:
        base = {
            "accept":             "*/*",
            "accept-language":    "es-ES,es;q=0.9",
            "priority":           "u=1, i",
            "sec-fetch-dest":     "empty",
            "sec-fetch-mode":     "cors",
            "sec-ch-ua":          self._CH_UA,
            "sec-ch-ua-mobile":   "?0",
            "sec-ch-ua-platform": '"Windows"',
            "user-agent":         self._UA,
        }
        self._sh = {**base, "content-type": "application/json", "origin": self._BASE,
                    "referer": f"{self._BASE}/temporary-email", "sec-fetch-site": "same-origin"}
        self._jh = {**base, "origin": self._BASE, "referer": f"{self._BASE}/",
                    "sec-fetch-site": "cross-site"}

    async def create_account(self) -> tuple[str, str, int]:
        log.step(1, "Resolviendo Turnstile")
        async with log.Loader("Resolviendo captcha..."):
            token = await self._solve_turnstile()
        log.ok("Resuelto correctamente")

        async with AsyncSession(impersonate="chrome142") as s:
            s.headers.update(self._sh)
            data             = (await s.get(
                f"{self._BASE}/app/create",
                headers={"x-captcha": token},
                params={"username": "random", "type": "alias", "domain": "gmail.com", "server": "1"},
                timeout=30,
            )).json()
            address, key, ts = data["address"], data["key"], data["timestamp"]
            await s.get(f"{self._BASE}/app/protect/set/",
                        params={"name": "email", "last_updated": ts}, timeout=10)

        return address, key, ts

    async def wait_for_code(self, address: str, key: str, timestamp: int,
                             timeout: int = 180, seen_mids: set | None = None) -> str:
        loop        = asyncio.get_event_loop()
        deadline    = loop.time() + timeout
        current_key = key
        seen        = seen_mids if seen_mids is not None else set()

        ss = AsyncSession(impersonate="chrome142")
        js = AsyncSession(impersonate="chrome142")
        ss.headers.update(self._sh)
        js.headers.update(self._jh)

        try:
            while loop.time() < deadline:
                try:
                    r       = await ss.post(
                        f"{self._BASE}/app/inbox",
                        json=[{"address": address, "timestamp": timestamp, "key": current_key}],
                        timeout=20,
                    )
                    entries = r.json()

                    if entries:
                        entry       = entries[0]
                        current_key = entry.get("key", current_key)
                        payload     = entry.get("payload")

                        if payload:
                            msgs = (await js.get(
                                f"{self._SONJJ}/inbox",
                                params={"payload": payload},
                                timeout=20,
                            )).json().get("messages", [])

                            log.info("Inbox", f"{len(msgs)} mensajes en inbox")

                            for msg in msgs:
                                mid  = msg.get("mid", "")
                                subj = msg.get("textSubject", "")
                                log.info("Mensaje", f"[{msg.get('textFrom', '').strip()}] {subj} (mid={mid})")

                                if mid and mid in seen:
                                    continue

                                if m := re.search(r'\b(\d{6})\b', subj):
                                    if mid:
                                        seen.add(mid)
                                    return m.group(1)

                                if mid:
                                    body = self._strip_html((await js.get(
                                        f"{self._SONJJ}/message",
                                        params={"email": address, "mid": mid, "payload": payload},
                                        timeout=20,
                                    )).json().get("body", ""))

                                    if m := re.search(r'\b(\d{6})\b', body):
                                        seen.add(mid)
                                        return m.group(1)

                                    log.warn("Sin código de 6 dígitos en body")

                except Exception as exc:
                    log.warn(f"SmailPro  Poll error: {exc}")

                await asyncio.sleep(5)
        finally:
            await ss.close()
            await js.close()

        raise RuntimeError("SmailPro: OTP timeout")

    async def _solve_turnstile(self) -> str:
        if not (key := os.getenv("CAPSOLVER_KEY", "")):
            raise RuntimeError("CAPSOLVER_KEY no configurado en .env")

        task = {
            "clientKey": key,
            "task": {
                "type":       "AntiTurnstileTaskProxyLess",
                "websiteURL": f"{self._BASE}/temporary-email",
                "websiteKey": self._SITEKEY,
            },
        }

        async with AsyncSession(impersonate="chrome142") as s:
            tid = (await s.post("https://api.capsolver.com/createTask", json=task, timeout=20)).json()["taskId"]

            for _ in range(40):
                await asyncio.sleep(3)
                data = (await s.post("https://api.capsolver.com/getTaskResult",
                                     json={"clientKey": key, "taskId": tid}, timeout=15)).json()
                if data.get("status") == "ready":
                    return data["solution"]["token"]

        raise RuntimeError("SmailPro: Turnstile timeout")

    @staticmethod
    def _strip_html(html: str) -> str:
        text = re.sub(r"<style[^>]*>.*?</style>",  " ", html, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r"<script[^>]*>.*?</script>", " ", text, flags=re.DOTALL | re.IGNORECASE)
        return re.sub(r"<[^>]+>", " ", text)


class MailTmClient:
    _BASE = "https://api.mail.tm"

    def __init__(self) -> None:
        self._s = AsyncSession(impersonate="chrome142")
        self._s.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        self._token = ""

    @staticmethod
    def _members(payload) -> list:
        return payload if isinstance(payload, list) else payload.get("hydra:member", [])

    async def create_account(self) -> str:
        domains = self._members((await self._s.get(f"{self._BASE}/domains", timeout=20)).json())
        domain  = domains[0]["domain"]

        user     = uuid.uuid4().hex[:12]
        password = uuid.uuid4().hex[:16]
        address  = f"{user}@{domain}"

        r = await self._s.post(f"{self._BASE}/accounts",
                                json={"address": address, "password": password},
                                timeout=20)
        if r.status_code not in (200, 201):
            raise RuntimeError(f"MailTm: create_account failed [{r.status_code}] {r.text[:200]}")

        tok = await self._s.post(f"{self._BASE}/token",
                                  json={"address": address, "password": password},
                                  timeout=20)
        self._token = tok.json()["token"]
        self._s.headers.update({"Authorization": f"Bearer {self._token}"})

        return address

    async def wait_for_code(self, timeout: int = 180) -> str:
        loop     = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        seen: set[str] = set()

        while loop.time() < deadline:
            try:
                r    = await self._s.get(f"{self._BASE}/messages", timeout=20)
                msgs = self._members(r.json())

                for msg in msgs:
                    mid = msg.get("id", "")
                    if not mid or mid in seen:
                        continue
                    seen.add(mid)

                    subj = msg.get("subject", "")
                    log.info("Mensaje", f"[{msg.get('from', {}).get('address','')}] {subj}")

                    if m := re.search(r'\b(\d{6})\b', subj):
                        return m.group(1)

                    full = (await self._s.get(f"{self._BASE}/messages/{mid}", timeout=20)).json()
                    text = full.get("text", "").strip()
                    if text:
                        if m := re.search(r'\b(\d{6})\b', text):
                            return m.group(1)

                    html = full.get("html", "")
                    html = html[0] if isinstance(html, list) else html
                    html = re.sub(r"<style[^>]*>.*?</style>",  " ", html, flags=re.DOTALL | re.IGNORECASE)
                    html = re.sub(r"<script[^>]*>.*?</script>", " ", html, flags=re.DOTALL | re.IGNORECASE)
                    html = re.sub(r"<[^>]+>", " ", html)
                    if m := re.search(r'\b(\d{6})\b', html):
                        return m.group(1)

            except Exception as exc:
                log.warn(f"MailTm  Poll error: {exc}")

            await asyncio.sleep(4)

        raise RuntimeError("MailTm: OTP timeout")

    async def close(self):
        await self._s.close()


async def setup_email() -> tuple[str, str, OtpCallable]:
    provider = os.getenv("EMAIL_PROVIDER", "mailtm")

    if provider == "smailpro":
        client         = SmailProClient()
        addr, key, ts  = await client.create_account()
        seen: set[str] = set()
        async def otp(): return await client.wait_for_code(addr, key, ts, seen_mids=seen)
    elif provider == "mailtm":
        client = MailTmClient()
        addr   = await client.create_account()
        async def otp(): return await client.wait_for_code()
    else:
        addr = ""
        while not addr:
            addr = (await asyncio.to_thread(input, "\n >> Email: ")).strip()
        async def otp(): return (await asyncio.to_thread(input, "\n >> OTP: ")).strip()

    return provider, addr, otp

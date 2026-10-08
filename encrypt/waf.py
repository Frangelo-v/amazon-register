"""
AWS WAF Bot Control — minter del `aws-waf-token` en PYTHON PURO (sin browser,
sin Node, sin CapSolver). Reversado del challenge.js real (644KB ofuscado) del
`.chlz` de una sesión que registró sin captcha.

FLUJO (idéntico al navegador real):
  1. GET /            → 202 con window.gokuProps{key,iv,context} + challenge.js URL
  2. GET {base}/inputs  → {challenge:{input,hmac,region}, difficulty:1}
  3. POST {base}/mp_verify (multipart) → {"token": "..."}
  4. setear cookie aws-waf-token = token  → recargar / → 200 + session-id

EL POW (difficulty 1, challenge_type NetworkBandwidth) es TRIVIAL:
  - solution: null
  - solution_data: base64(1024 bytes en cero)
Lo único no-trivial es el signal "Zoey": un fingerprint cifrado.

ZOEY:
  - plaintext = "<CRC32(json) hex mayus>#<json>"
  - cifrado   = AES-256-GCM, IV 12 bytes random, tag 128 bits, SIN AAD
  - Present   = base64(iv) + "::" + hex(ciphertext+tag)
  - signal    = {"name":"Zoey","value":{"Present": Present}}
"""
import os
import re
import json
import time
import random
import asyncio
import uuid
import base64
import zlib

from Crypto.Cipher import AES

# buffer de instrumentación — el caller lo lee tras mint_aws_waf_token()
_DBG: list = []

def get_debug() -> list:
    return list(_DBG)

# Endpoint del WebACL de Amazon, SÓLO como último recurso.
#
# ⚠️ NO es estático, como se creyó al principio. Era idéntico en amazon.har,
# amazong.chlsj y nuevoamazong.chlsj porque las tres salieron del MISMO POP.
# Una corrida por proxy MX cayó en otro:
#     capturas     1c5c1ecf7303.c0b160fb.us-east-1.token.awswaf.com/…
#     proxy MX     1c5c1ecf7303.a481e94e.us-east-2.token.awswaf.com/…
# O sea el host lleva la REGIÓN del edge que te atendió. Usar esta base desde
# una salida que ruteó a otra región mintea contra un WebACL que no es el suyo,
# y esa incoherencia es peor que no tener token.
#
# Por eso el minteo en frío está apagado (MINT_WAF=0): cuando llega el 202, la
# base sale del stub y es la correcta para esa sesión.
_FALLBACK_BASE = ("https://1c5c1ecf7303.c0b160fb.us-east-1.token.awswaf.com"
                  "/1c5c1ecf7303/d6a7a58005ec/04c5ab18cd2d")

# --- Constantes reversadas del challenge.js ---
_ZOEY_KEY = bytes.fromhex(
    "6f71a512b1e035eaab53d8be73120d3fb68a0ca346b9560aab3e5cdf753d5e98"
)
_ZOEY_VERSION = "2.4.0"
# solution_data: buffer de 1024 bytes en cero (NetworkBandwidth, difficulty 1).
_SOLUTION_DATA = base64.b64encode(b"\x00" * 1024).decode("ascii")

# metrics de perfilado. Reconstruido del capture REAL nuevoamazong.chlsj tras
# diffear contra el navegador ganador (ronda cero-desafío).
#
# ⚠️ BUG CORREGIDO (revisión captura): el array anterior tenía DOS entradas
# {"name":"undefined"} y FALTABAN 113/114/115 — un error de mapeo al reversar.
# El valor real 108=1 había caído en un "undefined" y 113/114/115 se perdieron.
# Un metric llamado "undefined" es huella sintética instantánea. Además los
# timings estaban hardcodeados (idénticos en cada corrida = bot trivial).
#
# `_METRICS_BASE`: nombres/valores exactos del capture real.
#   · timings (float, unit "2"): names 0-6 → se JITTEREAN por sesión.
#   · counters (unit "4"): names 7,8 → fijos.
#   · feature counts (int, unit "2"): names 100-115 → fijos (reflejan el browser real).
_METRICS_BASE = [
    # timings en ms (se jitterean)
    ("0", 146.7, "2"), ("1", 58.1, "2"), ("2", 0.6, "2"), ("3", 1.2, "2"),
    ("4", 1.3, "2"), ("5", 0.3, "2"), ("6", 59.7, "2"),
    # counters
    ("7", 0, "4"), ("8", 1, "4"),
    # feature counts (fijos — son el fingerprint real del browser)
    ("100", 0, "2"), ("101", 0, "2"), ("102", 1, "2"), ("103", 10, "2"),
    ("104", 0, "2"), ("105", 0, "2"), ("106", 0, "2"), ("107", 0, "2"),
    ("108", 1, "2"), ("110", 0, "2"), ("111", 14, "2"), ("112", 0, "2"),
    ("113", 8, "2"), ("114", 18, "2"), ("115", 1, "2"),
]
# nombres de los timings que varían de corrida a corrida en un browser real
_METRIC_TIMINGS = {"0", "1", "2", "3", "4", "5", "6"}


def _build_metrics() -> list:
    """Arma el array metrics con los timings jittereados por sesión.

    Un browser real nunca repite los mismos ms exactos. Se aplica un factor de
    máquina compartido (simula un equipo más rápido/lento) + ruido por metric,
    conservando el orden relativo (name 0 = total, sigue siendo el mayor).
    """
    machine = random.uniform(0.82, 1.28)          # equipo lento vs rápido
    out = []
    for name, base, unit in _METRICS_BASE:
        if name in _METRIC_TIMINGS and isinstance(base, (int, float)):
            v = base * machine * random.uniform(0.90, 1.10)
            v = round(v, 4)
        else:
            v = base
        out.append({"name": name, "value": v, "unit": unit})
    return out

# Fingerprint estático (plugins/caps/math/automation/crypto) — idéntico a un
# Edge real en Windows; no varía por equipo.
_PLUGINS = [
    {"name": "PDF Viewer", "str": "PDF Viewer "},
    {"name": "Chrome PDF Viewer", "str": "Chrome PDF Viewer "},
    {"name": "Chromium PDF Viewer", "str": "Chromium PDF Viewer "},
    {"name": "Microsoft Edge PDF Viewer", "str": "Microsoft Edge PDF Viewer "},
    {"name": "WebKit built-in PDF", "str": "WebKit built-in PDF "},
]
_CAPABILITIES = {
    "css": {"textShadow": 1, "WebkitTextStroke": 1, "boxShadow": 1, "borderRadius": 1,
            "borderImage": 1, "opacity": 1, "transform": 1, "transition": 1},
    "js": {"audio": True, "geolocation": True, "localStorage": "supported",
           "touch": False, "video": True, "webWorker": True},
    "elapsed": 1,
}
_MATH = {"tan": "-1.4214488238747245", "sin": "0.8178819121159085",
         "cos": "-0.5753861119575491"}
_AUTOMATION = {"wd": {"properties": {"document": [], "window": [], "navigator": []}},
               "phantom": {"properties": {"window": []}}}
_CRYPTO = {"crypto": 1, "subtle": 1, "encrypt": True, "decrypt": True, "wrapKey": True,
           "unwrapKey": True, "sign": True, "verify": True, "digest": True,
           "deriveBits": True, "deriveKey": True, "getRandomValues": True, "randomUUID": True}


def parse_waf_stub(html: str) -> dict | None:
    """Extrae gokuProps{key,iv,context} y la base URL del challenge.js del HTML stub (202)."""
    m_goku = re.search(r"window\.gokuProps\s*=\s*(\{.*?\})\s*;", html, re.DOTALL)
    m_js = re.search(
        r'src="(https://[a-z0-9]+\.[a-z0-9]+\.[a-z0-9-]+\.token\.awswaf\.com/[a-z0-9]+/[a-z0-9]+/[a-z0-9]+)/challenge\.js"',
        html)
    if not (m_goku and m_js):
        return None
    try:
        goku = json.loads(m_goku.group(1))
    except Exception:
        return None
    return {"base": m_js.group(1), "goku_props": goku}


def _build_zoey_fingerprint(user_agent: str, device: dict | None = None) -> str:
    """Arma el JSON de fingerprint Zoey (version 2.4.0). device: {gpu_vendor,gpu_model,canvas}."""
    now = int(time.time() * 1000)
    if device:
        gpu_vendor = device["gpu_vendor"]
        gpu_model  = device["gpu_model"]
        gpu_ext    = device.get("gpu_extensions") or _GPU_EXTENSIONS
        canvas     = device["canvas"]
        screen     = device.get("screen_info", "1536-864-816-24-*-*-*")
    else:
        gpu_vendor, gpu_model, gpu_ext = _GPU_VENDOR, _GPU_MODEL, _GPU_EXTENSIONS
        canvas = {"hash": _CANVAS_HASH, "emailHash": None, "histogramBins": _CANVAS_BINS}
        screen = "1536-864-816-24-*-*-*"
    duped  = ("PDF Viewer Chrome PDF Viewer Chromium PDF Viewer Microsoft Edge "
              "PDF Viewer WebKit built-in PDF ||" + screen)
    payload = {
        # HALLAZGOS_CAPTURAS_2026-08-28.md §4 ya marcaba "stealth:1" como
        # sospechoso sin ejecutar el cambio. stealth=1 se contradice con
        # `automation` (abajo), que reporta arrays vacíos — "no until now, no
        # encontré nada raro". No se puede diffear contra un Zoey real (va
        # cifrado AES-GCM con clave del servidor), así que esto es hipótesis,
        # no hecho confirmado: 0 es internamente consistente con el resto del
        # payload, que se declara limpio.
        "metrics": {"fp2": 0, "browser": 1, "capabilities": 1, "gpu": 18, "dnt": 0,
                    "math": 0, "screen": 0, "navigator": 0, "auto": 0, "stealth": 0,
                    "subtle": 0, "canvas": 12, "formdetector": 0, "be": 0},
        "start": now,
        "flashVersion": None,
        "plugins": _PLUGINS,
        "dupedPlugins": duped,
        "screenInfo": screen,
        "referrer": "",
        "userAgent": user_agent,
        "location": "https://www.amazon.com/",
        "webDriver": False,
        "capabilities": _CAPABILITIES,
        "gpu": {"vendor": gpu_vendor, "model": gpu_model, "extensions": gpu_ext},
        "dnt": None,
        "math": _MATH,
        "automation": _AUTOMATION,
        "stealth": {"t1": 0, "t2": 0, "i": 1, "mte": 0, "mtd": False},
        "crypto": _CRYPTO,
        "canvas": canvas,
        "formDetected": False,
        "numForms": 0,
        "numFormElements": 0,
        "be": {"si": False},
        # 1ms fijo = el mismo bug ya arreglado en _METRICS_BASE (timing
        # hardcodeado idéntico en cada corrida). Un script real que mide GPU,
        # canvas y math tarda más, y variable. Jitter 15-60ms, mismo espíritu
        # que _build_metrics() para los timings del token externo.
        "end": now + random.randint(15, 60),
        "errors": [],
        "version": _ZOEY_VERSION,
        "id": str(uuid.uuid4()),
    }
    # separators sin espacios — el CRC32 debe calcularse sobre el JSON EXACTO enviado.
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def _encrypt_zoey(fingerprint_json: str):
    """Cifra el fingerprint -> 'base64(iv)::hex(ct+tag)'. AES-256-GCM, IV12, tag128, sin AAD."""
    checksum  = format(zlib.crc32(fingerprint_json.encode("utf-8")) & 0xFFFFFFFF, "08X")
    plaintext = f"{checksum}#{fingerprint_json}".encode("utf-8")
    iv        = os.urandom(12)
    cipher    = AES.new(_ZOEY_KEY, AES.MODE_GCM, nonce=iv, mac_len=16)
    ct, tag   = cipher.encrypt_and_digest(plaintext)
    present   = base64.b64encode(iv).decode("ascii") + "::" + (ct + tag).hex()
    return present, checksum


def build_mp_verify_body(challenge: dict, goku_props: dict, user_agent: str,
                         device: dict | None = None,
                         domain: str = "www.amazon.com"):
    """Construye el multipart del POST /mp_verify. Retorna (body, content_type, checksum).

    `domain` debe ser el host del mercado activo (www.amazon.com.mx, etc.). Iba
    fijo en www.amazon.com, lo que contradecía a la sesión en cualquier mercado
    que no fuera el de US.
    """
    fp_json          = _build_zoey_fingerprint(user_agent, device)
    present, checksum = _encrypt_zoey(fp_json)

    solution_metadata = {
        "challenge": challenge,          # {input, hmac, region} tal cual de /inputs
        "solution": None,                # difficulty 1 → sin hashcash
        "signals": [{"name": "Zoey", "value": {"Present": present}}],
        "checksum": checksum,
        "existing_token": None,
        "client": "Browser",
        "domain": domain,
        "metrics": _build_metrics(),   # timings jittereados por sesión
        "goku_props": goku_props,
    }
    meta_str = json.dumps(solution_metadata, separators=(",", ":"))

    boundary = "----WebKitFormBoundary" + uuid.uuid4().hex[:16]
    b = boundary.encode()
    body = (
        b"--" + b + b"\r\n"
        b'Content-Disposition: form-data; name="solution_metadata"\r\n\r\n'
        + meta_str.encode("utf-8") + b"\r\n"
        b"--" + b + b"\r\n"
        b'Content-Disposition: form-data; name="solution_data"\r\n\r\n'
        + _SOLUTION_DATA.encode() + b"\r\n"
        b"--" + b + b"--\r\n"
    )
    return body, f"multipart/form-data; boundary={boundary}", checksum


async def mint_aws_waf_token(session, home_html: str, user_agent: str,
                             device: dict | None = None,
                             site: str = "https://www.amazon.com") -> str | None:
    """
    Orquesta el minteo del aws-waf-token en PYTHON PURO desde nuestra propia IP.
      session: AsyncSession de curl_cffi (misma que usará el registro).
      home_html: HTML del 202 si lo hubo; si no, se usa la base estática.
      site: origen del mercado activo (https://www.amazon.com.mx, etc.).
    Retorna el token (str) o None. El caller lo setea como cookie aws-waf-token.

    OJO con los mercados no-US: `_FALLBACK_BASE` es el WebACL de amazon.com. Si
    el mercado activo es otro y la home no sirvió el 202, el token sale de un
    WebACL distinto al del dominio donde se va a usar. Queda registrado en el
    debug para poder verlo en la corrida en vez de suponerlo.
    """
    _DBG.clear()
    stub = parse_waf_stub(home_html)
    if stub:
        base = stub["base"]
        goku = stub["goku_props"]
        _DBG.append(f"stub base={base[:60]} goku_keys={list(goku.keys())}")
    else:
        # El 202 NO es un requisito. Verificado en vivo:
        #   · la URL base es la MISMA en amazon.har, amazong y nuevoamazong
        #     (sesiones y fechas distintas): es el endpoint estático del WebACL,
        #     no algo per-sesión;
        #   · GET /inputs responde 200 con challenge válido (difficulty 1) en
        #     frío, sin haber recibido nunca el interstitial;
        #   · POST /mp_verify con goku_props=None devuelve token de 322 ch.
        #     Con {} da 400, con valores basura da token: el WAF no valida su
        #     contenido, sólo que el campo no sea un objeto vacío.
        # Antes, si la home no servía el 202 el token era inalcanzable para toda
        # la corrida. Ahora siempre se puede mintear.
        base = _FALLBACK_BASE
        goku = None
        _DBG.append("sin stub 202 — minteando contra la base estática del WebACL")

    async def _retry(coro_factory, tries=4):
        last = None
        for i in range(tries):
            try:
                return await coro_factory()
            except Exception as e:
                last = e
                await asyncio.sleep(0.8 * (i + 1))
        raise last

    # 2) GET /inputs → challenge {input, hmac, region}
    r_in = await _retry(lambda: session.get(
        f"{base}/inputs",
        params={"client": "browser"},
        headers={"user-agent": user_agent, "accept": "*/*",
                 "referer": site + "/", "origin": site,
                 "sec-fetch-site": "cross-site", "sec-fetch-mode": "cors",
                 "sec-fetch-dest": "empty"},
        timeout=30))
    if r_in.status_code != 200:
        _DBG.append(f"/inputs status={r_in.status_code}")
        return None
    inp = r_in.json()
    challenge = inp.get("challenge")
    # INSTRUMENTACIÓN: ver qué dificultad/challenge sirvió el WAF de verdad.
    # Si difficulty>1 o el challenge_type no es NetworkBandwidth, nuestro
    # solution=null es INVÁLIDO → token de baja confianza.
    _DBG.append(f"/inputs difficulty={inp.get('difficulty')} "
                f"challenge_type={(challenge or {}).get('challenge_type') or inp.get('challenge_type')} "
                f"keys={list(inp.keys())}")
    if not challenge:
        return None

    # 3) POST /mp_verify multipart → {token}
    _dom = site.split("://", 1)[-1].rstrip("/")
    if not stub and _dom != "www.amazon.com":
        _DBG.append(f"AVISO: base estática es el WebACL de amazon.com "
                    f"pero el mercado es {_dom}")
    body, ctype, _ = build_mp_verify_body(challenge, goku, user_agent, device,
                                          domain=_dom)
    r_v = await _retry(lambda: session.post(
        f"{base}/mp_verify",
        data=body,
        headers={"user-agent": user_agent, "content-type": ctype, "accept": "*/*",
                 "referer": site + "/", "origin": site,
                 "sec-fetch-site": "cross-site", "sec-fetch-mode": "cors",
                 "sec-fetch-dest": "empty"},
        timeout=30))
    if r_v.status_code != 200:
        _DBG.append(f"/mp_verify status={r_v.status_code} body={r_v.text[:200]}")
        return None
    try:
        j = r_v.json()
        _DBG.append(f"/mp_verify OK keys={list(j.keys())} token_len={len(j.get('token',''))}")
        return j.get("token")
    except Exception as e:
        _DBG.append(f"/mp_verify parse fail: {e}")
        return None


# --- Fingerprint por defecto (la máquina real del .chlz, fingerprint conocido-bueno) ---
_GPU_VENDOR = "Google Inc. (Microsoft)"
_GPU_MODEL  = ("ANGLE (Microsoft, Microsoft Basic Render Driver (0x0000008C) "
               "Direct3D11 vs_5_0 ps_5_0, D3D11)")
_GPU_EXTENSIONS = ["ANGLE_instanced_arrays", "EXT_blend_minmax", "EXT_clip_control",
    "EXT_color_buffer_half_float", "EXT_depth_clamp", "EXT_float_blend", "EXT_frag_depth",
    "EXT_polygon_offset_clamp", "EXT_shader_texture_lod", "EXT_texture_compression_bptc",
    "EXT_texture_compression_rgtc", "EXT_texture_filter_anisotropic",
    "EXT_texture_mirror_clamp_to_edge", "EXT_sRGB", "KHR_parallel_shader_compile",
    "OES_element_index_uint", "OES_fbo_render_mipmap", "OES_standard_derivatives",
    "OES_texture_float", "OES_texture_float_linear", "OES_texture_half_float",
    "OES_texture_half_float_linear", "OES_vertex_array_object", "WEBGL_blend_func_extended",
    "WEBGL_color_buffer_float", "WEBGL_compressed_texture_s3tc",
    "WEBGL_compressed_texture_s3tc_srgb", "WEBGL_debug_renderer_info", "WEBGL_debug_shaders",
    "WEBGL_depth_texture", "WEBGL_draw_buffers", "WEBGL_lose_context", "WEBGL_multi_draw",
    "WEBGL_polygon_mode"]
_CANVAS_HASH = 1633749972
_CANVAS_BINS = [14371, 29, 46, 52, 33, 80, 49, 34, 57, 51, 46, 47, 36, 27, 41, 56, 53, 21,
    73, 36, 24, 31, 14, 20, 57, 60, 50, 20, 25, 22, 38, 38, 39, 42, 27, 16, 17, 28, 19, 69,
    31, 17, 13, 34, 11, 31, 14, 56, 18, 50, 25, 39, 70, 13, 28, 24, 10, 19, 20, 27, 42, 27,
    17, 17, 17, 19, 31, 8, 15, 14, 22, 16, 13, 18, 37, 18, 11, 30, 47, 55, 23, 21, 16, 9, 21,
    20, 16, 21, 15, 64, 21, 26, 20, 23, 20, 17, 54, 13, 76, 85, 52, 86, 461, 19, 23, 19, 13,
    14, 16, 22, 16, 32, 29, 21, 17, 25, 15, 42, 16, 32, 89, 21, 12, 16, 14, 13, 25, 17, 24,
    51, 20, 51, 16, 11, 23, 48, 38, 20, 78, 14, 36, 16, 21, 25, 22, 9, 21, 22, 12, 13, 15,
    41, 23, 89, 15, 34, 37, 20, 9, 29, 13, 16, 28, 30, 54, 31, 22, 14, 21, 9, 13, 21, 11, 30,
    17, 14, 24, 78, 13, 6, 19, 40, 10, 16, 13, 12, 16, 10, 43, 21, 17, 17, 9, 15, 56, 22, 16,
    23, 61, 16, 22, 28, 30, 52, 51, 59, 125, 39, 44, 22, 18, 14, 10, 15, 20, 36, 38, 25, 16,
    30, 30, 13, 81, 37, 69, 57, 31, 25, 40, 43, 28, 36, 18, 35, 31, 29, 31, 25, 25, 45, 125,
    39, 42, 39, 70, 31, 55, 97, 46, 37, 88, 40, 56, 47, 52, 13217]

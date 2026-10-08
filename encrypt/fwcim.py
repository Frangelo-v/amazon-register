import os
import re
import zlib
import json
import math
import time
import base64
import random
import struct

from device import new_ios_device as _nd

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# XXTEA Cipher
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_DELTA = 0x9E3779B9
_MASK  = 0xFFFFFFFF
_KEY   = [1888420705, 2576816180, 2347232058, 874813317]
_ID    = "ECdITeCs"


def _xxtea(plaintext: str) -> bytes:
    data = plaintext.encode("latin-1")
    n    = math.ceil(len(data) / 4)
    o    = []
    for i in range(n):
        b0 = data[4*i]   if 4*i   < len(data) else 0
        b1 = data[4*i+1] if 4*i+1 < len(data) else 0
        b2 = data[4*i+2] if 4*i+2 < len(data) else 0
        b3 = data[4*i+3] if 4*i+3 < len(data) else 0
        o.append(b0 + (b1 << 8) + (b2 << 16) + (b3 << 24))

    rounds = math.floor(6 + 52 / n)
    c = o[n - 1]
    d = 0
    for _ in range(rounds):
        d = (d + _DELTA) & _MASK
        h = (d >> 2) & 3
        for u in range(n):
            a    = o[(u + 1) % n]
            t1   = ((c >> 5) ^ ((a << 2) & _MASK)) & _MASK
            t2   = ((a >> 3) ^ ((c << 4) & _MASK)) & _MASK
            t4   = ((d ^ a)  + (_KEY[3 & u ^ h] ^ c)) & _MASK
            o[u] = (o[u] + ((t1 + t2) & _MASK ^ t4)) & _MASK
            c    = o[u]

    out = []
    for v in o:
        out += [v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF]
    return bytes(out)


def _encrypt(payload: dict) -> str:
    prefix    = os.urandom(4).hex().upper()
    encrypted = _xxtea(f"{prefix}#{json.dumps(payload, separators=(',', ':'), ensure_ascii=False)}")
    return f"{_ID}:{base64.b64encode(encrypted).decode('ascii')}"


def _unxxtea(data: bytes) -> str:
    """XXTEA inverso. El bucle va hacia atrás: z = v[p-1] y se actualiza
    y = v[p] DESPUÉS de decrementar."""
    n = len(data) // 4
    v = list(struct.unpack(f"<{n}I", data[:n * 4]))
    rounds = math.floor(6 + 52 / n)
    total  = (rounds * _DELTA) & 0xFFFFFFFF
    y = v[0]
    while rounds > 0:
        e = (total >> 2) & 3
        for p in range(n - 1, 0, -1):
            z  = v[p - 1]
            mx = (((z >> 5 ^ (y << 2 & 0xFFFFFFFF)) + (y >> 3 ^ (z << 4 & 0xFFFFFFFF))) ^
                  ((total ^ y) + (_KEY[(p & 3) ^ e] ^ z))) & 0xFFFFFFFF
            v[p] = (v[p] - mx) & 0xFFFFFFFF
            y = v[p]
        z  = v[n - 1]
        mx = (((z >> 5 ^ (y << 2 & 0xFFFFFFFF)) + (y >> 3 ^ (z << 4 & 0xFFFFFFFF))) ^
              ((total ^ y) + (_KEY[e] ^ z))) & 0xFFFFFFFF
        v[0] = (v[0] - mx) & 0xFFFFFFFF
        y = v[0]
        total = (total - _DELTA) & 0xFFFFFFFF
        rounds -= 1
    out = bytearray()
    for val in v:
        out += bytes((val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF, (val >> 24) & 0xFF))
    return out.rstrip(b"\x00").decode("latin-1", errors="replace")


def decrypt_metadata1(enc: str) -> dict:
    """Descifra un metadata1 propio (o del capture) al dict original."""
    enc = (enc or "").strip()
    if enc.startswith(_ID):
        enc = enc[len(_ID) + 1:]
    plain = _unxxtea(base64.b64decode(enc + "=="))
    return json.loads(plain[plain.index("#") + 1:])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Script Fingerprint
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_SCRIPT_BLOCK_RE = re.compile(r'<script[\s\S]*?>[\s\S]*?</script>', re.I)
_SCRIPT_SRC_RE   = re.compile(r'src="[\s\S]*?"')
_LOAD_JS_RE      = re.compile(r'\.load\.js\(\s*[\'"]([^\'"]+)[\'"]')

_SCRIPTS_US = [
    "https://images-na.ssl-images-amazon.com/images/I/215h87l68bL.js",
    "https://m.media-amazon.com/images/I/11I0WXrZVoL._RC|61xJcNKKLXL.js,11Y+5x+kkTL.js,51DFoGfFeXL.js,115zbyk371L.js,11GgN1+C7hL.js,01+z+uIeJ-L.js,01VRMV3FBdL.js,21NadQlXUWL.js,01vRf9id2EL.js,31on-La90vL.js,11a7qqY8xXL.js,11PZSUl3FLL.js,51C4kaFbiAL.js,11FhdH2HZwL.js,11wb9K3sw0L.js,11BrgrMAHUL.js,11GPhx42StL.js,210X-JWUe-L.js,01Svfxfy8OL.js,61lbT4bHNWL.js,01ikBbTAneL.js,31xywoXPfpL.js,01qXJuwGmxL.js,01WlsjNmqIL.js,11F929pmpYL.js,31Zn4S+IOkL.js,01rpauTep4L.js,31rqCOnXDNL.js,011FfPwYqHL.js,21P5VvHf-XL.js,01-E15R8CKL.js,21kN0q4IA-L.js,01VvIkYCafL.js,11vb6P5C5AL.js,01yeWhVNdxL.js_.js?AUIClients/AmazonUI",
    "https://m.media-amazon.com/images/I/21ZMwVh4T0L._RC|21OJDARBhQL.js,218GJg15I8L.js,31lucpmF4CL.js,21juQdw6GzL.js,61bZUY2Rk2L.js_.js?AUIClients/AuthenticationPortalAssets",
    "https://m.media-amazon.com/images/I/01wGDSlxwdL.js?AUIClients/AuthenticationPortalInlineAssets",
    "https://m.media-amazon.com/images/I/419OGYw2ijL.js?AUIClients/CVFAssets",
    "https://m.media-amazon.com/images/I/8150jbgvn9L.js?AUIClients/SiegeClientSideEncryptionAUI",
    "https://m.media-amazon.com/images/I/31jdfgcsPAL.js?AUIClients/AmazonUIFormControlsJS",
    "https://m.media-amazon.com/images/I/718zrbkrsfL.js?AUIClients/IdentityWebAuthnAssets",
    "https://m.media-amazon.com/images/I/51Jl74g24BL.js?AUIClients/IdentityJsCommonAssets",
    "https://m.media-amazon.com/images/I/81kfJmCRBCL.js?AUIClients/FWCIMAssets",
    "https://static.siege-amazon.com/prod/profiles/AuthenticationPortalSigninNA.js?v=4",
]
_INLINE_HASHES = [-314038750,-1746719145,250914967,976429854,1660743647,2146702782,4606827,347602589,-1788655209,585973559,-35109078,318224283,-464060506,204317253,-1611905557,1800521327,-1551718424,1708315875,-147667130,673482434]


def _crc32_signed(s: str) -> int:
    c = zlib.crc32(s.encode("utf-8", "surrogatepass")) & 0xFFFFFFFF
    return c - 0x100000000 if c >= 0x80000000 else c


def extract_page_scripts(html: str) -> dict:
    """Réplica de lo que ve FWCIM al enumerar los <script> del DOM.

    Amazon casi no usa src="" — inyecta sus bundles con
    `AmazonUIPageJS.load.js('url')` desde scripts inline, que crean elementos
    <script> reales en el DOM. Si sólo miramos src="" reportamos
    dynamicUrlCount=1 en una página que el servidor sabe que sirvió ~10-13
    bundles: contradicción verificable que marca el fingerprint como sintético.
    """
    dyn, inl = [], []
    for block in _SCRIPT_BLOCK_RE.findall(html or ""):
        m = _SCRIPT_SRC_RE.search(block)
        if m:
            c = m.group(0)
            dyn.append(c[5:len(c) - 1])
        else:
            inl.append(_crc32_signed(block))
            # Los load.js() de este bloque insertan <script> en el punto en que
            # el parser lo ejecuta → van en orden de documento, aquí mismo.
            dyn.extend(_LOAD_JS_RE.findall(block))
    return {"dynamicUrls": dyn, "inlineHashes": inl,
            "elapsed": random.randint(20, 55),
            "dynamicUrlCount": len(dyn), "inlineHashesCount": len(inl)}


def _resolve_scripts(page_html: str) -> dict:
    if page_html:
        return extract_page_scripts(page_html)
    return {"dynamicUrls": _SCRIPTS_US, "inlineHashes": _INLINE_HASHES,
            "elapsed": random.randint(4, 8),
            "dynamicUrlCount": len(_SCRIPTS_US), "inlineHashesCount": len(_INLINE_HASHES)}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Device Profile
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_GPU_EXTENSIONS = ["ANGLE_instanced_arrays","EXT_blend_minmax","EXT_clip_control","EXT_color_buffer_half_float","EXT_depth_clamp","EXT_float_blend","EXT_frag_depth","EXT_polygon_offset_clamp","EXT_shader_texture_lod","EXT_texture_compression_bptc","EXT_texture_compression_rgtc","EXT_texture_filter_anisotropic","EXT_texture_mirror_clamp_to_edge","EXT_sRGB","KHR_parallel_shader_compile","OES_element_index_uint","OES_fbo_render_mipmap","OES_standard_derivatives","OES_texture_float","OES_texture_float_linear","OES_texture_half_float","OES_texture_half_float_linear","OES_vertex_array_object","WEBGL_blend_func_extended","WEBGL_color_buffer_float","WEBGL_compressed_texture_s3tc","WEBGL_compressed_texture_s3tc_srgb","WEBGL_debug_renderer_info","WEBGL_debug_shaders","WEBGL_depth_texture","WEBGL_draw_buffers","WEBGL_lose_context","WEBGL_multi_draw","WEBGL_polygon_mode"]

# Lista COMPLETA de extensiones WebGL de Chrome desktop (real con EXT_disjoint_timer_query).
# Definida aquí para que known_good_device() pueda referenciarla.
_GPU_EXTENSIONS_DESKTOP = [
    "ANGLE_instanced_arrays","EXT_blend_minmax","EXT_clip_control","EXT_color_buffer_half_float",
    "EXT_depth_clamp","EXT_disjoint_timer_query","EXT_float_blend","EXT_frag_depth",
    "EXT_polygon_offset_clamp","EXT_shader_texture_lod","EXT_texture_compression_bptc",
    "EXT_texture_compression_rgtc","EXT_texture_filter_anisotropic","EXT_texture_mirror_clamp_to_edge",
    "EXT_sRGB","KHR_parallel_shader_compile","OES_element_index_uint","OES_fbo_render_mipmap",
    "OES_standard_derivatives","OES_texture_float","OES_texture_float_linear","OES_texture_half_float",
    "OES_texture_half_float_linear","OES_vertex_array_object","WEBGL_blend_func_extended",
    "WEBGL_color_buffer_float","WEBGL_compressed_texture_s3tc","WEBGL_compressed_texture_s3tc_srgb",
    "WEBGL_debug_renderer_info","WEBGL_debug_shaders","WEBGL_depth_texture","WEBGL_draw_buffers",
    "WEBGL_lose_context","WEBGL_multi_draw","WEBGL_polygon_mode",
]

_GPU_POOL = [
    ("Google Inc. (Intel)",  "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (Intel)",  "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (Intel)",  "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (Intel)",  "ANGLE (Intel, Intel(R) HD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3050 Laptop GPU Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (AMD)",    "ANGLE (AMD, AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (AMD)",    "ANGLE (AMD, AMD Radeon RX 6600 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
]

_DOMAIN_TZ = {
    "amazon.com": -5, "amazon.ca": -5, "amazon.com.mx": -6,
    "amazon.co.uk": 0, "amazon.de": 1,  "amazon.fr": 1,
    "amazon.it": 1,   "amazon.es": 1,  "amazon.com.au": 10,
    "amazon.co.jp": 9, "amazon.in": 5,
}

_LSUBID_RE = re.compile(r'^[X\d]\d{2}-\d{7}-\d{7}:\d+$')


def _fake_lsubid() -> str:
    # El ts debe ser la edad REAL de la sesión, no días. En el capture bueno
    # lsUbid ts = start - 102 s: el localStorage se creó al abrir amazon.com en
    # esta misma sesión. Si declaramos un ls-ubid de días, Amazon espera también
    # ubid-main/session-id viejas y la cookie ls-ubid — y mandamos una sesión
    # recién nacida sin esa cookie. Esa contradicción sube el score.
    x  = random.randint(10, 99)
    p1 = random.randint(1000000, 9999999)
    p2 = random.randint(1000000, 9999999)
    ts = int(time.time()) - random.randint(60, 300)
    return f"X{x}-{p1}-{p2}:{ts}"


def _resolve_lsubid(ls_ubid: str, device: dict) -> str:
    if ls_ubid and _LSUBID_RE.match(ls_ubid):
        return ls_ubid
    return device.get("lsubid") or _fake_lsubid()


# Canvas hash real del capture exitoso (HAR amazon_elrealsinotp).
# GPU: Intel UHD Graphics 0xA788. Determinístico en esa máquina/driver.
_REAL_CANVAS_HASH = 1241491791
_REAL_CANVAS_BINS = [
    14564,33,59,38,41,66,27,30,40,36,38,50,44,28,38,66,57,21,67,24,21,25,24,43,46,29,46,13,33,18,
    42,43,22,59,26,12,37,26,26,24,31,33,18,11,35,26,16,32,31,40,34,41,67,11,21,18,22,18,6,16,46,
    46,12,14,15,19,30,9,12,15,12,17,15,19,40,13,17,8,42,73,24,16,19,17,32,17,13,18,19,58,30,27,18,
    18,12,13,33,21,29,112,84,29,545,27,5,40,33,16,14,14,10,36,20,18,18,19,14,32,21,22,71,39,19,10,
    33,27,26,20,20,60,32,52,25,13,19,37,32,31,70,17,28,17,11,17,16,10,25,22,9,12,59,19,6,92,9,52,
    30,22,8,31,9,14,20,23,51,36,7,14,9,16,13,28,17,40,11,7,76,79,9,10,10,47,9,23,9,8,19,10,7,55,
    14,15,6,12,62,21,10,10,63,9,17,58,35,51,67,71,84,9,24,17,9,14,7,31,38,27,16,30,18,37,27,22,67,
    82,34,64,22,43,53,23,20,31,23,39,21,31,36,16,20,73,120,48,50,33,64,32,32,80,37,33,83,55,46,58,
    44,13176,
]

_REAL_GPU_VENDOR = "Google Inc. (Intel)"
_REAL_GPU_MODEL  = ("ANGLE (Intel, Intel(R) UHD Graphics (0x0000A788) "
                    "Direct3D11 vs_5_0 ps_5_0, D3D11)")


def known_good_device() -> dict:
    """Device con GPU+canvas del capture real exitoso (OTP-only, sin captcha)."""
    return {
        "gpu_vendor":    _REAL_GPU_VENDOR,
        "gpu_model":     _REAL_GPU_MODEL,
        "canvas":        {"hash": _REAL_CANVAS_HASH, "emailHash": None, "histogramBins": _REAL_CANVAS_BINS},
        "gpu_extensions": _GPU_EXTENSIONS_DESKTOP,
        "screen_info":   "1536-864-816-24-*-*-*",
    }


def _realistic_canvas() -> dict:
    bins  = [random.randint(13800, 14600)]
    bins += [random.randint(6, 95) for _ in range(254)]
    bins.append(random.randint(12400, 13800))
    return {"hash": random.randint(1_000_000_000, 2_000_000_000),
            "emailHash": None, "histogramBins": bins}


def _ios_canvas() -> dict:
    # Apple GPU canvas fingerprint — distinct from desktop ANGLE/Chrome values
    bins  = [random.randint(14400, 15300)]
    bins += [random.randint(0, 48) for _ in range(254)]
    bins.append(random.randint(11000, 12800))
    return {"hash": random.randint(1_750_000_000, 2_100_000_000),
            "emailHash": None, "histogramBins": bins}


def new_device() -> dict:
    vendor, model = random.choice(_GPU_POOL)
    return {"gpu_vendor": vendor, "gpu_model": model, "canvas": _realistic_canvas()}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Human Interaction
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _f32(x: float) -> float:
    return struct.unpack("f", struct.pack("f", float(x)))[0]


def _human_intervals(n: int) -> list:
    """Intervalos entre teclas DENTRO de un campo.

    En el capture bueno van de 67 a 422 ms, sin un solo pico. La pausa al
    cambiar de campo no se registra aquí, así que meter picos de 1-3 s era
    inventar un patrón que ningún tecleo real produce.
    """
    if n <= 0:
        return []
    vals = []
    for _ in range(n):
        r = random.random()
        if r < 0.15:
            vals.append(random.randint(65, 125))     # dígrafos rápidos
        elif r < 0.85:
            vals.append(random.randint(130, 290))    # ritmo normal
        else:
            vals.append(random.randint(300, 430))    # duda breve
    return vals


def _human_key_cycles(n: int) -> list:
    if n <= 0:
        return []
    return [random.randint(2, 4)] + [random.randint(50, 140) for _ in range(n - 1)]


def _fake_interaction(email_len: int = 18, is_ios: bool = True) -> dict:
    nclicks   = random.randint(3, 5)
    kp        = random.randint(18, 28)
    x         = random.randint(650, 800)
    y         = random.randint(170, 205)
    positions = []
    for _ in range(nclicks):
        positions.append(f"{x},{y}")
        x = max(400, x + random.randint(-70, 45))
        y += random.randint(45, 90)
    mcycles = [random.randint(70, 95) for _ in range(max(nclicks - 1, 1))]
    if random.random() < 0.5:
        mcycles.append(random.randint(300, 360))
    # iOS WKWebView: cada tap dispara touchstart/touchend además del click sintético.
    # Un iPhone (capabilities.touch=true) con touches=0 es una contradicción sintética
    # que dispara WAF_ADVERSARIAL_SYNTHETIC_GRID. touches ≈ taps, touchCycles poblado.
    touches     = nclicks if is_ios else 0
    touchcycles = [random.randint(45, 130) for _ in range(touches)] if is_ios else []
    return {
        "clicks": nclicks, "touches": touches, "keyPresses": kp,
        "cuts": 0, "copies": 0, "pastes": 0,
        "keyPressTimeIntervals": _human_intervals(random.randint(8, 10)),
        "mouseClickPositions":   positions,
        "keyCycles":             _human_key_cycles(random.randint(9, 11)),
        "mouseCycles":           mcycles,
        "touchCycles":           touchcycles,
    }


def _otp_interaction(code_len: int = 6) -> dict:
    kp      = code_len
    x, y    = random.randint(90, 200), random.randint(190, 330)
    x2, y2  = x + random.randint(-40, 40), y + random.randint(60, 120)
    return {
        "clicks": 2, "touches": 2, "keyPresses": kp,
        "cuts": 0, "copies": 0, "pastes": 0,
        "keyPressTimeIntervals": _human_intervals(max(kp - 1, 0)),
        "mouseClickPositions":   [f"{x},{y}", f"{x2},{y2}"],
        "keyCycles":             _human_key_cycles(kp),
        "mouseCycles":           [random.randint(1, 3) for _ in range(2)],
        "touchCycles":           [],
    }


def _fake_field(keypresses: int, width: int = 312, height: int = 32, is_ios: bool = True) -> dict:
    n = max(keypresses, 1)
    # iOS: enfocar un campo es un tap → 1 touchstart/touchend. touches=0 con touch=true
    # es un marcador sintético.
    touches     = 1 if is_ios else 0
    touchcycles = [random.randint(45, 130)] if is_ios else []
    return {
        "clicks": 1, "touches": touches, "keyPresses": n,
        "cuts": 0, "copies": 0, "pastes": 0,
        "keyPressTimeIntervals": _human_intervals(max(n - 1, 0)),
        "mouseClickPositions":   [f"{_f32(random.uniform(90, 180))},{_f32(random.uniform(5, 22))}"],
        "keyCycles":             _human_key_cycles(min(n + 1, 11)),
        "mouseCycles":           [random.randint(88, 93)],
        "touchCycles":           touchcycles,
        "width":                 width,
        "height":                height,
        "totalFocusTime":        random.randint(1200, 3800),
        "prefilled":             False,
    }


def _fake_form(customer_name: str = "", email: str = "") -> dict:
    name_kp  = len(customer_name.replace(" ", "")) or random.randint(8, 16)
    email_kp = len(email) if email else random.randint(12, 22)
    pw_kp    = random.randint(10, 18)
    return {
        "ap_customer_name":  _fake_field(name_kp),
        "email":             _fake_field(email_kp),
        "password":          _fake_field(pw_kp),
        "ap_password_check": _fake_field(pw_kp),
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Metadata Generation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def gen_metadata1(location: str, referrer: str, user_agent: str, ls_ubid: str = "",
                  domain: str = "amazon.com", customer_name: str = "", email: str = "",
                  device: dict = None, span_ms: int = None, page_html: str = None) -> str:
    if device is None:
        device = new_device()

    is_ios    = bool(device.get("ios_version") or device.get("gpu_vendor", "") == "Apple Inc.")
    now_ms    = int(time.time() * 1000)
    _span     = span_ms if (span_ms and span_ms > 0) else random.randint(7000, 12000)
    start     = now_ms - _span
    nav_start = start - random.randint(150, 400)
    screen    = device.get("screen_info", "1536-864-816-24-*-*-*")
    # WKWebView on iOS: navigator.plugins is empty — no PDF viewer entries
    plugins   = (f"||{screen}" if is_ios else
                 f"PDF Viewer Chrome PDF Viewer Chromium PDF Viewer Microsoft Edge PDF Viewer WebKit built-in PDF ||{screen}")
    touch     = True if is_ios else False
    canvas    = device.get("canvas") or (_ios_canvas() if is_ios else _realistic_canvas())
    # JavaScriptCore (iOS) vs V8 (Chrome) tan() differs at last digit
    math_tan  = "-1.4214488238747243" if is_ios else "-1.4214488238747245"

    return _encrypt({
        "metrics":      {"el":0,"script":0,"h":0,"batt":0,"perf":0,"auto":0,"tz":0,"fp2":0,"lsubid":0,"browser":0,"capabilities":0,"gpu":0,"dnt":0,"math":0,"tts":0,"input":0,"canvas":0,"captchainput":0,"pow":0},
        "start":        start,
        "interaction":  _fake_interaction(len(email) if email else 18, is_ios),
        "scripts":      _resolve_scripts(page_html),
        # Webview MAP recién abierto (signin→register): 1-3 entradas, no 5-9.
        "history":      {"length": random.randint(1, 3)},
        "battery":      {},
        "performance":  {"timing":{"connectStart":nav_start+30,"secureConnectionStart":0,"unloadEventEnd":nav_start+233,"domainLookupStart":nav_start+30,"domainLookupEnd":nav_start+30,"responseStart":nav_start+189,"connectEnd":nav_start+30,"responseEnd":nav_start+276,"requestStart":nav_start+35,"domLoading":nav_start+242,"redirectStart":0,"loadEventEnd":nav_start+865,"domComplete":nav_start+841,"navigationStart":nav_start,"loadEventStart":nav_start+841,"domContentLoadedEventEnd":nav_start+832,"unloadEventStart":nav_start+233,"redirectEnd":0,"domInteractive":nav_start+817,"fetchStart":nav_start+30,"domContentLoadedEventStart":nav_start+819}},
        "automation":   {"wd":{"properties":{"document":[],"window":[],"navigator":[]}},"phantom":{"properties":{"window":[]}}},
        "end":          now_ms,
        "timeZone":     device.get("tz_offset", device.get("timezone", _DOMAIN_TZ.get(domain, -5))),
        "flashVersion": None,
        "plugins":      plugins,
        "dupedPlugins": plugins,
        "screenInfo":   screen,
        "lsUbid":       _resolve_lsubid(ls_ubid, device),
        "referrer":     referrer,
        "userAgent":    user_agent,
        "location":     location,
        "webDriver":    False,
        "capabilities": {"css":{"textShadow":1,"WebkitTextStroke":1,"boxShadow":1,"borderRadius":1,"borderImage":1,"opacity":1,"transform":1,"transition":1},"js":{"audio":True,"geolocation":True,"localStorage":"supported","touch":touch,"video":True,"webWorker":True},"elapsed":0},
        "gpu":          {"vendor": device.get("gpu_vendor", "Apple Inc."), "model": device.get("gpu_model", "Apple GPU"),
                         "extensions": device.get("gpu_extensions") or _GPU_EXTENSIONS},
        "dnt":          None,
        "math":         {"tan": math_tan, "sin":"0.8178819121159085","cos":"-0.5753861119575491"},
        "form":         _fake_form(customer_name, email),
        "canvas":       canvas,
        "token":        {"isCompatible": True, "pageHasCaptcha": 0},
        "auth":         {"form": {"method": "post"}},
        "errors":       [],
        "version":      "4.0.0",
    })


def gen_metadata1_otp(location: str, referrer: str, user_agent: str, ls_ubid: str = "",
                      domain: str = "amazon.com", code_len: int = 6,
                      device: dict = None, span_ms: int = None, page_html: str = None) -> str:
    if device is None:
        device = _nd()

    now_ms    = int(time.time() * 1000)
    _span     = span_ms if (span_ms and span_ms > 0) else random.randint(9000, 20000)
    start     = now_ms - _span
    nav_start = start - random.randint(150, 400)
    screen    = device.get("screen_info", "393-852-852-24-*-*-*")
    # WKWebView on iOS has no navigator.plugins entries
    plugins   = f"||{screen}"

    return _encrypt({
        "metrics":      {"el":0,"script":0,"h":0,"batt":1,"perf":0,"auto":0,"tz":0,"fp2":0,"lsubid":0,"browser":0,"capabilities":0,"gpu":0,"dnt":0,"math":0,"tts":0,"input":0,"canvas":0,"captchainput":0,"pow":0},
        "start":        start,
        "interaction":  _otp_interaction(code_len),
        "scripts":      _resolve_scripts(page_html),
        "history":      {"length": random.randint(5, 8)},
        "battery":      {
            "level":           round(random.uniform(0.15, 0.97), 2),
            "charging":        random.random() < 0.25,
            "chargingTime":    None,
            "dischargingTime": random.randint(3600, 32400),
        },
        "performance":  {"timing":{"connectStart":nav_start,"secureConnectionStart":0,"unloadEventEnd":nav_start+627,"domainLookupStart":nav_start,"domainLookupEnd":nav_start,"responseStart":nav_start+604,"connectEnd":nav_start,"responseEnd":nav_start+604,"requestStart":nav_start+1,"domLoading":nav_start+632,"redirectStart":0,"loadEventEnd":nav_start+699,"domComplete":nav_start+697,"navigationStart":nav_start,"loadEventStart":nav_start+697,"domContentLoadedEventEnd":nav_start+651,"unloadEventStart":nav_start+627,"redirectEnd":0,"domInteractive":nav_start+651,"fetchStart":nav_start+2,"domContentLoadedEventStart":nav_start+651}},
        "automation":   {"wd":{"properties":{"document":[],"window":[],"navigator":[]}},"phantom":{"properties":{"window":[]}}},
        "end":          now_ms,
        "timeZone":     device.get("tz_offset", _DOMAIN_TZ.get(domain, -6)),
        "flashVersion": None,
        "plugins":      plugins,
        "dupedPlugins": plugins,
        "screenInfo":   screen,
        "lsUbid":       _resolve_lsubid(ls_ubid, device),
        "referrer":     referrer,
        "userAgent":    user_agent,
        "location":     location,
        "webDriver":    False,
        "capabilities": {"css":{"textShadow":1,"WebkitTextStroke":1,"boxShadow":1,"borderRadius":1,"borderImage":1,"opacity":1,"transform":1,"transition":1},"js":{"audio":True,"geolocation":True,"localStorage":"supported","touch":True,"video":True,"webWorker":True},"elapsed":0},
        "gpu":          {"vendor": device.get("gpu_vendor", "Apple Inc."),
                         "model":  device.get("gpu_model", "Apple GPU"),
                         "extensions": device.get("gpu_extensions") or _GPU_EXTENSIONS},
        "dnt":          None,
        "math":         {"tan":"-1.4214488238747243","sin":"0.8178819121159085","cos":"-0.5753861119575491"},
        "timeToSubmit": _span,
        "form":         {"code": _fake_field(code_len, width=280, height=44)},
        "canvas":       device.get("canvas") or _ios_canvas(),
        "token":        {"isCompatible": True, "pageHasCaptcha": 0},
        "auth":         {"form": {"method": "post"}},
        "errors":       [],
        "version":      "4.0.0",
    })


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Metadata Generation — canal RETAIL (amazon.com /ap/register)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Basado en el fingerprint REAL descifrado de una captura exitosa (solo OTP,
# sin captcha). Diferencias clave vs el canal MAP/iOS de arriba, que causaban
# "Internal Error" o el captcha GRID al reusar gen_metadata1() en retail:
#   · form = {ap_customer_name, password, ap_password_check}  — SIN campo email
#   · metrics.input = 1
#   · history.length ≈ 8   (navegador con historial, no webview recién abierto)
#   · performance.timing con unload/redirect/secureConnection en 0
#   · gpu.extensions completa (incluye EXT_disjoint_timer_query)
#   · desktop: touch=false, plugins con PDF viewers, math.tan de V8

def _retail_field(keypresses: int, width: int = 312, height: int = 32,
                  total_focus: int = None, clicks: int = 1) -> dict:
    n = max(keypresses, 1)
    positions = [f"{_f32(random.uniform(65, 100))},{_f32(random.uniform(-2, 30))}"
                 for _ in range(clicks)]
    return {
        "clicks": clicks, "touches": 0, "keyPresses": n,
        "cuts": 0, "copies": 0, "pastes": 0,
        "keyPressTimeIntervals": _human_intervals(max(n - 1, 0)),
        "mouseClickPositions":   positions,
        "keyCycles":             [random.randint(35, 130) for _ in range(n)],
        "mouseCycles":           [random.randint(50, 100) for _ in range(clicks)],
        "touchCycles":           [],
        "width":                 width,
        "height":                height,
        "totalFocusTime":        random.randint(2800, 4200) if total_focus is None else total_focus,
        "prefilled":             False,
    }


def _retail_interaction(name_kp: int, pw_kp: int) -> dict:
    clicks = random.randint(4, 6)
    total_kp = name_kp + pw_kp * 2
    # El capture bueno: x=680,676,702,702,686 (jitter en ambos sentidos, con un
    # click repetido en el mismo campo) y y=193,273,350,350,355. Nuestra versión
    # anterior hacía x e y monótonamente crecientes — escalera perfecta que
    # ningún mouse humano dibuja.
    x, y = random.randint(660, 710), random.randint(185, 210)
    positions = []
    repeat_at = random.randrange(1, clicks) if clicks > 2 else -1
    for i in range(clicks):
        positions.append(f"{x},{y}")
        if i == repeat_at:                      # segundo click en el mismo campo
            positions.append(f"{x},{y}")
        x += random.randint(-26, 26)            # jitter simétrico, sin deriva
        y += random.randint(48, 88)
    positions = positions[:clicks]
    return {
        "clicks": clicks, "touches": 0, "keyPresses": total_kp,
        "cuts": 0, "copies": 0, "pastes": 0,
        "keyPressTimeIntervals": _human_intervals(random.randint(8, 10)),
        "mouseClickPositions":   positions,
        "keyCycles":             [random.randint(40, 130) for _ in range(random.randint(9, 11))],
        "mouseCycles":           [random.randint(55, 95) for _ in range(clicks - 1)],
        "touchCycles":           [],
    }


def gen_metadata1_retail(location: str, referrer: str, user_agent: str, ls_ubid: str = "",
                         domain: str = "amazon.com", customer_name: str = "",
                         password: str = "", device: dict = None,
                         span_ms: int = None, page_html: str = None) -> str:
    """metadata1 para el registro RETAIL de amazon.com (/ap/register)."""
    if device is None:
        device = new_device()

    now_ms    = int(time.time() * 1000)
    _span     = span_ms if (span_ms and span_ms > 0) else random.randint(8000, 14000)
    start     = now_ms - _span
    nav       = start - random.randint(700, 1000)          # navigationStart
    screen    = device.get("screen_info", "1536-864-816-24-*-*-*")
    plugins   = (f"PDF Viewer Chrome PDF Viewer Chromium PDF Viewer Microsoft Edge PDF Viewer "
                 f"WebKit built-in PDF ||{screen}")
    canvas    = device.get("canvas") or _realistic_canvas()
    name_kp   = len(customer_name.replace(" ", "")) or random.randint(8, 14)
    pw_kp     = len(password) or random.randint(8, 14)

    # Tiempo de foco declarado por campo. Tiene dos techos y hay que respetar
    # ambos:
    #   1) no puede sumar más que el tramo real (_span): el servidor lo mide
    #      con su propio reloj entre que sirve el form y le llega el POST.
    #   2) no puede ser mucho mayor que lo que tarda TECLEAR esos caracteres:
    #      si la red se cuelga 3 min, _span se dispara y derivar el foco de él
    #      declararía dos minutos de foco en el campo de nombre — absurdo.
    # Un usuario que deja el form abierto y se distrae tiene span largo y foco
    # corto, así que el foco se deriva del tecleo y sólo se recorta por _span.
    _typing = (random.randint(420, 650) + name_kp * random.randint(95, 165)
               + random.randint(420, 650) + pw_kp * random.randint(95, 165))
    _focus_budget = min(_typing, int(_span * random.uniform(0.60, 0.76)))
    _focus_name   = int(_focus_budget * random.uniform(0.40, 0.52))
    _focus_pw     = _focus_budget - _focus_name

    # performance.timing: réplica de la estructura real (offsets vs navigationStart)
    def t(off): return nav + off
    timing = {
        "connectStart":               t(15), "secureConnectionStart": 0,
        "unloadEventEnd":             0,     "domainLookupStart":     t(15),
        "domainLookupEnd":            t(15), "responseStart":         t(random.randint(180, 210)),
        "connectEnd":                 t(15), "responseEnd":           t(random.randint(190, 220)),
        "requestStart":               t(18), "domLoading":            t(random.randint(198, 230)),
        "redirectStart":              0,     "loadEventEnd":          t(random.randint(440, 470)),
        "domComplete":                t(random.randint(430, 460)), "navigationStart": nav,
        "loadEventStart":             t(random.randint(430, 460)),
        "domContentLoadedEventEnd":   t(random.randint(315, 340)), "unloadEventStart": 0,
        "redirectEnd":                0,     "domInteractive":        t(random.randint(315, 340)),
        "fetchStart":                 t(15),
        "domContentLoadedEventStart": t(random.randint(315, 340)),
    }

    return _encrypt({
        # metrics: 1 = campo recolectado exitosamente. Debe ser coherente con los datos
        # incluidos — si enviamos gpu/canvas/script data pero metrics.gpu=0, Amazon
        # ve la contradicción y clasifica el fingerprint como sintético.
        "metrics":      {"el":0,"script":0,"h":0,"batt":0,"perf":0,"auto":0,"tz":0,"fp2":0,"lsubid":0,"browser":0,"capabilities":0,"gpu":0,"dnt":0,"math":0,"tts":0,"input":1,"canvas":0,"captchainput":0,"pow":0},
        "start":        start,
        "interaction":  _retail_interaction(name_kp, pw_kp),
        "scripts":      _resolve_scripts(page_html),
        "history":      {"length": random.randint(7, 9)},
        "battery":      {},
        "performance":  {"timing": timing},
        "automation":   {"wd":{"properties":{"document":[],"window":[],"navigator":[]}},"phantom":{"properties":{"window":[]}}},
        "end":          now_ms,
        "timeZone":     device.get("tz_offset", _DOMAIN_TZ.get(domain, -6)),
        "flashVersion": None,
        "plugins":      plugins,
        "dupedPlugins": plugins,
        "screenInfo":   screen,
        "lsUbid":       _resolve_lsubid(ls_ubid, device),
        "referrer":     referrer,
        "userAgent":    user_agent,
        "location":     location,
        "webDriver":    False,
        "capabilities": {"css":{"textShadow":1,"WebkitTextStroke":1,"boxShadow":1,"borderRadius":1,"borderImage":1,"opacity":1,"transform":1,"transition":1},"js":{"audio":True,"geolocation":True,"localStorage":"supported","touch":False,"video":True,"webWorker":True},"elapsed":0},
        "gpu":          {"vendor": device.get("gpu_vendor", "Google Inc. (Intel)"),
                         "model":  device.get("gpu_model", "ANGLE (Intel, Intel(R) UHD Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"),
                         "extensions": device.get("gpu_extensions") or _GPU_EXTENSIONS_DESKTOP},
        "dnt":          None,
        "math":         {"tan":"-1.4214488238747245","sin":"0.8178819121159085","cos":"-0.5753861119575491"},
        "form":         {
            "ap_customer_name": _retail_field(name_kp, total_focus=_focus_name),
            "password":         _retail_field(pw_kp,   total_focus=_focus_pw),
            "ap_password_check": _retail_field(pw_kp, total_focus=0, clicks=random.randint(1, 2)),
        },
        "canvas":       canvas,
        "token":        {"isCompatible": True, "pageHasCaptcha": 0},
        "auth":         {"form": {"method": "post"}},
        "errors":       [],
        "version":      "4.0.0",
    })

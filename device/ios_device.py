import random
import time


def _gen_ubid() -> str:
    # ubid-main: identificador de dispositivo permanente en Amazon
    # formato real: ddd-ddddddd-ddddddd  (prefijo 3 dígitos + dos bloques 7)
    prefix = random.choice([132, 135, 146, 162, 167, 172, 183, 191, 192])
    return f"{prefix}-{random.randint(1000000, 9999999)}-{random.randint(1000000, 9999999)}"


# ──────────────────────────────────────────────────────────────────
# Base de datos real de iPhones
#   logical  : puntos CSS (screen.width/height en Safari)
#   native   : píxeles físicos (UIScreen.nativeBounds → lo que reporta
#              la app de Amazon en el fingerprint frc)
#   ios      : (major_min, major_max) de iOS que el chip soporta
# ──────────────────────────────────────────────────────────────────
_IPHONES = [
    # modelo_generico  id            nombre_display         logical    dpr  native       ios
    ("iPhone",  "iPhone11,8", "iPhone XR",          (414, 896), 2, (828, 1792),  (17, 18)),
    ("iPhone",  "iPhone12,1", "iPhone 11",           (414, 896), 2, (828, 1792),  (17, 26)),
    ("iPhone",  "iPhone12,8", "iPhone SE (2nd gen)", (375, 667), 2, (750, 1334),  (17, 26)),
    ("iPhone",  "iPhone14,6", "iPhone SE (3rd gen)", (375, 667), 2, (750, 1334),  (17, 26)),
    ("iPhone",  "iPhone13,2", "iPhone 12",           (390, 844), 3, (1170, 2532), (17, 26)),
    ("iPhone",  "iPhone13,3", "iPhone 12 Pro",       (390, 844), 3, (1170, 2532), (17, 26)),
    ("iPhone",  "iPhone14,5", "iPhone 13",           (390, 844), 3, (1170, 2532), (17, 26)),
    ("iPhone",  "iPhone14,2", "iPhone 13 Pro",       (390, 844), 3, (1170, 2532), (17, 26)),
    ("iPhone",  "iPhone14,7", "iPhone 14",           (390, 844), 3, (1170, 2532), (17, 26)),
    ("iPhone",  "iPhone14,8", "iPhone 14 Plus",      (428, 926), 3, (1284, 2778), (17, 26)),
    ("iPhone",  "iPhone14,3", "iPhone 13 Pro Max",   (428, 926), 3, (1284, 2778), (17, 26)),
    ("iPhone",  "iPhone15,2", "iPhone 14 Pro",       (393, 852), 3, (1179, 2556), (17, 26)),
    ("iPhone",  "iPhone15,4", "iPhone 15",           (393, 852), 3, (1179, 2556), (17, 26)),
    ("iPhone",  "iPhone16,1", "iPhone 15 Pro",       (393, 852), 3, (1179, 2556), (17, 26)),
    ("iPhone",  "iPhone15,3", "iPhone 14 Pro Max",   (430, 932), 3, (1290, 2796), (17, 26)),
    ("iPhone",  "iPhone15,5", "iPhone 15 Plus",      (430, 932), 3, (1290, 2796), (17, 26)),
    ("iPhone",  "iPhone16,2", "iPhone 15 Pro Max",   (430, 932), 3, (1290, 2796), (17, 26)),
    ("iPhone",  "iPhone17,3", "iPhone 16",           (393, 852), 3, (1179, 2556), (18, 26)),
    ("iPhone",  "iPhone17,4", "iPhone 16 Plus",      (430, 932), 3, (1290, 2796), (18, 26)),
    ("iPhone",  "iPhone17,1", "iPhone 16 Pro",       (402, 874), 3, (1206, 2622), (18, 26)),
    ("iPhone",  "iPhone17,2", "iPhone 16 Pro Max",   (440, 956), 3, (1320, 2868), (18, 26)),
]

# major iOS → perfil TLS curl_cffi + versiones puntuales reales.
# Solo iOS ≥18.7: el UA del webview va congelado en "18_7" (ver _build_ua), y ese
# valor solo lo reporta un dispositivo en 18.7 o superior. Un perfil TLS de iOS 17
# con UA 18_7 sería una combinación que no existe.
_IOS_BY_MAJOR = {
    18: [("safari184_ios", ["18.7", "18.7.1", "18.7.2"])],
    26: [("safari260_ios", ["26.0", "26.0.1", "26.1", "26.2", "26.5", "26.5.1", "26.5.2"])],
}
_IOS_MAJOR_WEIGHTS = {18: 35, 26: 65}

_WEBKIT = "605.1.15"
_MOBILE = "15E148"


# Apple CONGELÓ el token de OS en el UA de WebKit: un iPhone en iOS 26.5.2 sigue
# reportando "18_7" en el webview. Verificado sobre 1037/1037 requests reales de
# dos teléfonos distintos (iPhone17,2 iOS 26.5.2 · iPhone15,3 iOS 26.5): el UA es
# SIEMPRE este string, byte por byte. Randomizar la versión aquí (17_5_1, 26_0_1…)
# produce un UA que no existe en tráfico MAP real → fingerprint sintético.
_UA_FROZEN_OS = "18_7"


def _build_ua(ios_version: str) -> str:
    # WKWebView in-app (app Prime Video): SIN los tokens Version/ ni Safari/604.1
    # — así lo manda el webview real de MAP. Verificado en captura HAR.
    # ios_version se ignora a propósito: el token va congelado (ver arriba).
    return (
        f"Mozilla/5.0 (iPhone; CPU iPhone OS {_UA_FROZEN_OS} like Mac OS X) "
        f"AppleWebKit/{_WEBKIT} (KHTML, like Gecko) Mobile/{_MOBILE}"
    )


_IOS_GPU_VENDOR = "Apple Inc."
_IOS_GPU_MODEL  = "Apple GPU"

_IOS_GPU_EXTENSIONS = [
    "ANGLE_instanced_arrays", "EXT_blend_minmax", "EXT_clip_control",
    "EXT_color_buffer_half_float", "EXT_depth_clamp", "EXT_frag_depth",
    "EXT_polygon_offset_clamp", "EXT_shader_texture_lod",
    "EXT_texture_filter_anisotropic", "EXT_texture_mirror_clamp_to_edge", "EXT_sRGB",
    "KHR_parallel_shader_compile", "OES_element_index_uint", "OES_fbo_render_mipmap",
    "OES_standard_derivatives", "OES_texture_float", "OES_texture_half_float",
    "OES_texture_half_float_linear", "OES_vertex_array_object",
    "WEBGL_blend_func_extended", "WEBGL_color_buffer_float",
    "WEBGL_compressed_texture_astc", "WEBGL_compressed_texture_etc",
    "WEBGL_compressed_texture_etc1", "WEBGL_compressed_texture_pvrtc",
    "WEBKIT_WEBGL_compressed_texture_pvrtc", "WEBGL_debug_renderer_info",
    "WEBGL_debug_shaders", "WEBGL_depth_texture", "WEBGL_draw_buffers",
    "WEBGL_lose_context", "WEBGL_multi_draw", "WEBGL_polygon_mode",
]


def _gen_lsubid() -> str:
    ts = int(time.time()) - random.randint(3 * 86400, 20 * 86400)
    return (f"X{random.randint(10, 99)}-{random.randint(1000000, 9999999)}"
            f"-{random.randint(1000000, 9999999)}:{ts}")


# App anfitriona: Amazon Prime Video (canal AIV). El bundle, la versión y
# el ApplicationName del frc + map-md describen SIEMPRE la misma app, coherente
# con assoc_handle=amzn_aiv_ios_us y pageId=amzn_dv_ios_blue del flujo PKCE.
_AIV_NAME    = "Amazon Prime Video"
_AIV_BUNDLE  = "com.amazon.aiv.AIVApp"
_AIV_VERSIONS = [
    "10.17", "10.18", "10.19",
    "11.0", "11.1", "11.2", "11.3", "11.4", "11.5",
    "12.0", "12.1", "12.2", "12.3",
]

# País · idioma Amazon · Accept-Language · idioma de dispositivo · timezone · moneda.
# TODAS US: los proxies son 100% de EE.UU. Declarar MX/CO/GT sobre una IP de USA
# crea un geo-mismatch que dispara el WAF GRID de Amazon. País declarado == geo-IP.
# Timezones reales de USA (Eastern/Central/Mountain/Pacific) para coherencia.
_LOCALES = [
    (30, {"country": "US", "language": "en_US", "accept_language": "en-US,en;q=0.9",                         "device_language": "en-US", "timezone": "-05:00", "currency": "USD"}),  # Eastern
    (22, {"country": "US", "language": "en_US", "accept_language": "en-US,en;q=0.9",                         "device_language": "en-US", "timezone": "-06:00", "currency": "USD"}),  # Central
    (10, {"country": "US", "language": "en_US", "accept_language": "en-US,en;q=0.9",                         "device_language": "en-US", "timezone": "-08:00", "currency": "USD"}),  # Pacific
    (20, {"country": "US", "language": "es_US", "accept_language": "es-US,es-419;q=0.9,es;q=0.8,en;q=0.7", "device_language": "es-US", "timezone": "-06:00", "currency": "USD"}),  # US Hispano Central
    (10, {"country": "US", "language": "es_US", "accept_language": "es-US,es-419;q=0.9,es;q=0.8,en;q=0.7", "device_language": "es-US", "timezone": "-05:00", "currency": "USD"}),  # US Hispano Eastern
    ( 8, {"country": "US", "language": "es_US", "accept_language": "es-US,es-419;q=0.9,es;q=0.8,en;q=0.7", "device_language": "es-US", "timezone": "-08:00", "currency": "USD"}),  # US Hispano Pacific
]


def new_ios_device() -> dict:
    name, model_id, display_name, (lw, lh), dpr, (nw, nh), (imin, imax) = random.choice(_IPHONES)

    # Elegir iOS major con peso real de adopción (agosto 2026). Solo 18/26: el UA
    # congelado en 18_7 exige un dispositivo en 18.7+.
    candidates = [m for m in (18, 26) if imin <= m <= imax]
    major_weights = [_IOS_MAJOR_WEIGHTS[m] for m in candidates]
    major       = random.choices(candidates, weights=major_weights, k=1)[0]
    tls_profile, versions = random.choice(_IOS_BY_MAJOR[major])
    ios_version = random.choice(versions)

    weights, choices = zip(*_LOCALES)
    locale = random.choices(choices, weights=weights, k=1)[0]

    return {
        "tls_profile":     tls_profile,
        "ios_version":     ios_version,
        "ua":              _build_ua(ios_version),
        "model_id":        model_id,
        "iphone":          {"name": name, "display_name": display_name, "w": str(nw), "h": str(nh)},
        "dpr":             dpr,
        "screen_info":     f"{lw}-{lh}-{lh}-24-*-*-*",                   # web → puntos CSS (availH = H en iOS)
        "tz_offset":       int(locale["timezone"].split(":")[0]),          # metadata1 → offset entero
        "app":             {"name": _AIV_NAME, "bundle": _AIV_BUNDLE, "version": random.choice(_AIV_VERSIONS)},
        "gpu_vendor":      _IOS_GPU_VENDOR,
        "gpu_model":       _IOS_GPU_MODEL,
        "gpu_extensions":  _IOS_GPU_EXTENSIONS,
        "lsubid":          _gen_lsubid(),
        "ubid":            _gen_ubid(),            # ubid-main: identidad permanente de dispositivo
        "country":         locale["country"],
        "language":        locale["language"],
        "accept_language": locale["accept_language"],
        "device_language": locale["device_language"],
        "timezone":        locale["timezone"],
        "i18n_currency":   locale["currency"],     # i18n-prefs cookie → currency=USD/MXN/...
    }

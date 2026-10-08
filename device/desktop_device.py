import random
import re

import ua_generator
from ua_generator.options import Options
from ua_generator.data.version import VersionRange


# Majors de Chrome que curl_cffi puede impersonar a nivel TLS/HTTP2.
# ua-generator produce UA + client hints de esa MISMA versión, así el
# perfil TLS, el User-Agent y los Sec-CH-UA quedan alineados.
# 124 y 131 sacados del pool (HALLAZGOS_CAPTURAS_2026-08-28.md, Gap menor):
# builds de 2024 que los WAFs ya flaggean; los winners eran Chrome 150/151.
# curl_cffi ofrece chrome145/146 (más cerca del real), pero no hay build
# completo verificado para _FULL_VERSION todavía — agregar sólo con dato real.
_CURL_CHROME = [133, 136, 142]

_PROFILE = {133: "chrome133a", 136: "chrome136", 142: "chrome142"}

# Builds reales por major. sec-ch-ua-full-version-list lleva la versión
# completa, no el "136.0.0.0" reducido que va en el User-Agent: un Chrome real
# nunca reporta ceros ahí, así que copiar el UA sería una señal en sí misma.
_FULL_VERSION = {
    133: "133.0.6943.142",
    136: "136.0.7103.114",
    142: "142.0.7444.176",
}

# Chrome en Win11 22H2+ reporta "15.0.0"; en 24H2 "19.0.0".
_PLATFORM_VERSIONS = ["15.0.0", "19.0.0"]


def _full_version_list(brands: list, major: int) -> str:
    """Mismas marcas y orden que sec-ch-ua, pero con la versión completa."""
    full = _FULL_VERSION.get(major, f"{major}.0.0.0")
    out = []
    for b in brands:
        v = "99.0.0.0" if "rand" in b["brand"].lower() else full
        out.append(f'"{b["brand"]}";v="{v}"')
    return ", ".join(out)

# Chrome >=110 sólo corre en Win10/11 (NT 10.0). Forzamos combo real x64.
_WIN_RE = re.compile(r"Windows NT [\d.]+(; (?:Win64; x64|WOW64|Win64))?")


def new_desktop_device() -> dict:
    major = random.choice(_CURL_CHROME)
    opts  = Options(version_ranges={"chrome": VersionRange(major, major)})
    ua    = ua_generator.generate(device="desktop", platform="windows", browser="chrome", options=opts)

    text     = _WIN_RE.sub("Windows NT 10.0; Win64; x64", ua.text, count=1)
    brand_l  = ua.ch.get_brands()
    brands   = ", ".join(f'"{b["brand"]}";v="{b["version"]}"' for b in brand_l)

    return {
        "tls_profile": _PROFILE[major],
        "ua":          text,
        "headers": {
            "sec-ch-ua":          brands,
            "sec-ch-ua-mobile":   "?0",
            "sec-ch-ua-platform": '"Windows"',
            # Amazon los pide vía Accept-CH y Chrome real los manda en el POST
            # de /ap/register. Faltaban en el nuestro.
            "sec-ch-ua-full-version-list": _full_version_list(brand_l, major),
            "sec-ch-ua-platform-version":  f'"{random.choice(_PLATFORM_VERSIONS)}"',
            # Client-hints de BAJA ENTROPÍA. Chrome real los echa en el POST de
            # /ap/register tras el Accept-CH del server; sin ellos, el cliente
            # "recibió Accept-CH y no respondió" = no es Chrome real.
            # Valores consistentes con el screen fijo 1536x864 de metadata1/Zoey.
            # (⚠️ si algún día screen/gpu/canvas se generan por sesión, estos
            #  DEBEN generarse en el mismo bloque para no divergir.)
            "device-memory":          "8",
            "sec-ch-device-memory":   "8",
            "dpr":                    "1.25",
            "sec-ch-dpr":             "1.25",
            "viewport-width":         "1536",
            "sec-ch-viewport-width":  "1536",
            "sec-ch-viewport-height": "729",
            "rtt":                    "50",
            "downlink":               "10",
            "ect":                    "4g",
        },
    }

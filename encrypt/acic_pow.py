"""Resolutor del desafío ACIC PROOF_OF_WORK (aamation) de Amazon.

Cuando /ap/register responde con un desafío, el tipo importa: ARKOSE_LEVEL_*
es un captcha visual (irresolvible por código), pero PROOF_OF_WORK_LEVEL_1 es
un hashcash clásico que se resuelve en milisegundos.

El reto se sirve en un iframe:
    GET /aaut/verify/<refId>?context=<ctx>&options=<opts>
y esa página trae los parámetros EN TEXTO PLANO:
    encryptedString, requiredBits, minRequiredBits, minChainCount, probeConfig

El algoritmo (leído del bundle AUIClients/ACICAssets, función
calculateProofOfWork) es:

    nonce = 0
    while True:
        hash = sha256(encryptedString + str(nonce))     # hex
        if countLeadingZeroBits(hash) >= requiredBits: break
        nonce += 1

En el flujo M2 (isM2Flow) el cliente calibra su propia dificultad con un probe
de velocidad y reporta chosenBits/chosenChainCount; el servidor recomputa los
hashes, por eso el payload no los incluye. Los mínimos que acepta son
minRequiredBits / minChainCount, así que reportar esos es legítimo: es lo que
hace el propio cliente cuando el probe falla.
"""

import re
import json
import time
import random
import hashlib
from urllib.parse import unquote, urlencode

__all__ = ["parse_acic_setup", "parse_challenge", "solve_pow", "build_answer",
           "challenge_url", "answer_url", "MAX_CHAINS"]

MAX_CHAINS = 10

# ── setupACIC({...}) embebido en la página CVF ───────────────────────────────
_ACIC_STR_KEYS = ("data-ref-id", "data-challenge-type", "data-locale",
                  "data-external-id", "data-host-config")


def parse_acic_setup(html: str) -> dict:
    """Lee los data-* del bloque acic.setupACIC de la página /ap/cvf/request."""
    out = {}
    for k in _ACIC_STR_KEYS:
        m = re.search(rf'"{re.escape(k)}"\s*:\s*"([^"]*)"', html or "")
        if m:
            out[k] = m.group(1)
    m = re.search(r'"data-context"\s*:\s*\'([^\']*)\'', html or "")
    if m:
        out["data-context"] = m.group(1)
    return out


def is_proof_of_work(setup: dict) -> bool:
    return "PROOF_OF_WORK" in (setup.get("data-challenge-type") or "")


# ── página del reto ──────────────────────────────────────────────────────────
_ENC_RE   = re.compile(r"encryptedStringEncoded\s*=\s*'([^']+)'")
_INT_RE   = lambda k: re.compile(rf"\b{k}\s*=\s*(\d+)")
_PROBE_RE = re.compile(r"probeConfig\s*=\s*JSON\.parse\('([^']+)'\)")


def _int(html: str, key: str, default: int) -> int:
    m = _INT_RE(key).search(html or "")
    return int(m.group(1)) if m else default


def parse_challenge(html: str) -> dict:
    """Extrae los parámetros del PoW de la página /aaut/verify/."""
    m = _ENC_RE.search(html or "")
    if not m:
        return {}
    probe = {}
    mp = _PROBE_RE.search(html or "")
    if mp:
        try:
            probe = json.loads(mp.group(1).replace('\\"', '"'))
        except Exception:
            probe = {}
    return {
        "encryptedString": unquote(m.group(1)),
        "requiredBits":    _int(html, "requiredBits", 13),
        "minRequiredBits": _int(html, "minRequiredBits", 11),
        "minChainCount":   _int(html, "minChainCount", 1),
        "targetDurationMs": _int(html, "targetDurationMs", 1000),
        "clientTimeoutMs": _int(html, "clientTimeoutMs", 60000),
        "isM2Flow":        "isM2Flow = true" in (html or ""),
        "probeConfig":     probe,
    }


def _count_leading_zero_bits(hex_digest: str) -> int:
    """Réplica exacta de countLeadingZeroBits del bundle: cuenta sobre el hex."""
    n = 0
    for ch in hex_digest:
        v = int(ch, 16)
        if v == 0:
            n += 4
        else:
            n += 4 - v.bit_length()
            break
    return n


def solve_pow(encrypted_string: str, required_bits: int,
              timeout_s: float = 30.0) -> tuple:
    """Busca el nonce. Devuelve (nonce, hash_hex, ms). (None, None, ms) si expira."""
    t0 = time.perf_counter()
    deadline = t0 + timeout_s
    nonce = 0
    base = encrypted_string.encode()
    while True:
        h = hashlib.sha256(base + str(nonce).encode()).hexdigest()
        if _count_leading_zero_bits(h) >= required_bits:
            return nonce, h, (time.perf_counter() - t0) * 1000
        nonce += 1
        if (nonce & 0x3FF) == 0 and time.perf_counter() > deadline:
            return None, None, (time.perf_counter() - t0) * 1000


def solve_chain(ch: dict, timeout_s: float = 30.0) -> dict:
    """Resuelve la cadena completa y arma el payload que espera el servidor.

    Con minChainCount=1 hay un solo eslabón. Para cadenas más largas cada
    eslabón toma como entrada el hash del anterior.
    """
    bits   = max(ch.get("minRequiredBits", 11), 1)
    chains = max(ch.get("minChainCount", 1), 1)
    chains = min(chains, MAX_CHAINS)

    start_ms = int(time.time() * 1000)
    t0 = time.perf_counter()
    nonces, timestamps = [], []
    cur = ch["encryptedString"]
    for _ in range(chains):
        n, h, _ms = solve_pow(cur, bits, timeout_s=timeout_s)
        if n is None:
            return {}
        nonces.append(n)
        timestamps.append(int(time.time() * 1000))
        cur = h
    total = int((time.perf_counter() - t0) * 1000)

    payload = {
        "encryptedString": ch["encryptedString"],
        "nonces":          nonces,
        "timestamps":      timestamps,
        "startTime":       start_ms,
        "totalTime":       total,
        "chosenBits":      bits,
        "chosenChainCount": chains,
    }
    # El cliente real mide su hash rate con un probe antes de calibrar. Lo
    # reportamos coherente con el tiempo que de verdad tardamos.
    if ch.get("isM2Flow") and ch.get("probeConfig"):
        pb = ch["probeConfig"].get("probeDifficultyBits", 9)
        rate = max(int((2 ** bits * chains) / max(total / 1000, 0.001)), 1)
        payload["probeResult"] = {
            "probeBits":  pb,
            "probeCount": ch["probeConfig"].get("probeCount", 5),
            "hashRate":   rate,
        }
    return payload


# ── URLs ─────────────────────────────────────────────────────────────────────
def _options(setup: dict) -> str:
    """El `options` que manda ACIC, copiado del capture (amazonphone2).

    Es un JSON serializado donde `clientData` es a su vez el data-context
    serializado. La versión anterior mandaba otra estructura inventada
    ({challengeType, externalId, locale, hostConfig}) y el servicio la
    rechazaba con 400.
    """
    return json.dumps({
        "clientData":            setup.get("data-context", ""),
        "challengeType":         setup.get("data-challenge-type"),
        "locale":                setup.get("data-locale", "en-US"),
        "externalId":            setup.get("data-external-id"),
        "enableHeaderFooter":    False,
        "enableBypassMechanism": False,
        "enableModalView":       False,
        "eventTrigger":          None,
        "aaExternalToken":       None,
        "forceJsFlush":          False,
        "aamationToken":         None,
    }, separators=(",", ":"))


def challenge_request(base: str, setup: dict) -> tuple:
    """(url, body) del POST que pide el reto. En el capture:

        POST /aaut/verify/<refId>?options=<json>
        content-type: application/json
        {"context":null,"options":"<json>","fwcimBlob":null}
    """
    ref  = setup.get("data-ref-id", "cvf")
    opts = _options(setup)
    url  = f"{base}/aaut/verify/{ref}?{urlencode({'options': opts})}"
    return url, {"context": None, "options": opts, "fwcimBlob": None}


def answer_request(base: str, setup: dict, payload: dict,
                   session_token: str, client_context: str) -> tuple:
    """(url, body) del POST que envía la respuesta. En el capture:

        POST /aaut/verify/<refId>/<sessionToken>?context=&options=&response=
        content-type: application/json
        {"context":"<clientSideContext>","options":"<json>","response":"<json>"}

    Los tres parámetros van EN LA QUERY y TAMBIÉN en el body.
    """
    ref  = setup.get("data-ref-id", "cvf")
    opts = _options(setup)
    resp = user_response(setup, payload)
    q    = {"context": client_context, "options": opts, "response": resp}
    url  = f"{base}/aaut/verify/{ref}/{session_token}?{urlencode(q)}"
    return url, {"context": client_context, "options": opts, "response": resp}


# El resultado de ACIC NO viaja en el body: viene en esta cabecera, como JSON
# {sessionToken, clientSideContext, actionType}. En el bundle:
#     this.addResult(xhr.getResponseHeader(ACIC.AAMATION_SERVICE_RESPONSE_HEADER))
# El body es siempre la página del iframe, por eso parecía que nos rechazaban.
AAMATION_HEADER = "amz-aamation-resp"


def parse_aamation_header(resp) -> dict:
    """Lee el resultado ACIC de la cabecera amz-aamation-resp."""
    raw = None
    try:
        raw = resp.headers.get(AAMATION_HEADER)
    except Exception:
        pass
    if not raw:
        return {}
    try:
        j = json.loads(raw)
    except Exception:
        return {}
    return j if isinstance(j, dict) else {}


def challenge_url(base: str, setup: dict) -> str:
    """GET de la página del reto (lo que ACIC carga en el iframe)."""
    ref = setup.get("data-ref-id", "cvf")
    q = {"context": setup.get("data-context", ""), "options": _options(setup)}
    return f"{base}/aaut/verify/{ref}?{urlencode(q)}"


def user_response(setup: dict, payload: dict) -> str:
    """El objeto ACICUserResponse serializado, que es lo que espera `response`.

    Del bundle:
        function ACICUserResponse(challengeType, data) {
            this.challengeType = challengeType;
            this.data = data;              // JSON.stringify(userResponseData)
        }
        ... response: JSON.stringify(this.currentUserResponse)

    O sea: envoltorio con el payload YA serializado como string en `data`.
    Mandar el payload pelado da 400.
    """
    return json.dumps({
        "challengeType": setup.get("data-challenge-type", "PROOF_OF_WORK_LEVEL_1"),
        "data": json.dumps(payload),
    })


def answer_url(base: str, setup: dict, payload: dict,
               session_token: str = "", client_context: str = "") -> str:
    """URL de envío de la respuesta (createUserAnswerRequestURL del bundle):

        path        = refId + '/' + currentAAmationResult.sessionTokenValue
        queryParams = {context: clientSideContextValue, options, response}

    OJO: `context` NO es el data-context de la página, sino el
    clientSideContext que devolvió la cabecera amz-aamation-resp del reto.
    """
    ref = setup.get("data-ref-id", "cvf")
    path = f"{ref}/{session_token}" if session_token else f"{ref}/"
    q = {"context": client_context or setup.get("data-context", ""),
         "options": _options(setup),
         "response": user_response(setup, payload)}
    return f"{base}/aaut/verify/{path}?{urlencode(q)}"


def build_answer(base: str, cvf_html: str, challenge_html: str) -> tuple:
    """Atajo: de la página CVF + la del reto a (url_de_respuesta, payload)."""
    setup = parse_acic_setup(cvf_html)
    ch = parse_challenge(challenge_html)
    if not ch:
        return None, {}
    payload = solve_chain(ch)
    if not payload:
        return None, {}
    return answer_url(base, setup, payload), payload

import os
import time
import base64
import random
import hashlib
import capsolver

from urllib.parse import urlencode, quote
from faker import Faker
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from curl_cffi import AsyncSession
import Function.amazon as amazon
from Function.amazon import Outcome, NAV_HEADERS, AUTH_COOKIES, AMAZON_BASE, AMAZON_DOMAIN, make_session, export_cookies, setup_email
from device import new_desktop_device
from encrypt.fwcim import gen_metadata1_otp
from test.frc_ios import gen_frc_ios
from test.api_register import exchange_code, parse_success as parse_exchange
import Function.log as log

load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))
capsolver.api_key = os.getenv("CAPSOLVER_KEY")

_FAKER_LOCALE = {
    "US": "en_US", "MX": "es_MX", "CO": "es_CO", "CL": "es_CL",
    "SG": "en_US", "HK": "en_US", "GB": "en_GB", "CA": "en_CA", "AU": "en_AU",
    "IE": "en_IE", "NZ": "en_NZ", "IN": "en_IN", "PH": "en_US", "MY": "en_US",
    "DE": "de_DE", "AT": "de_AT", "CH": "de_CH", "NL": "nl_NL", "BE": "nl_BE",
    "FR": "fr_FR", "ES": "es_ES", "IT": "it_IT", "PT": "pt_PT", "BR": "pt_BR",
    "PL": "pl_PL", "SE": "sv_SE", "NO": "no_NO", "DK": "da_DK", "FI": "fi_FI",
    "JP": "ja_JP", "KR": "ko_KR", "TR": "tr_TR", "AR": "es_AR", "PE": "es_ES",
}

_DEVICE_TYPE = "AK6OCP5ZLUJI1"   # iOS Prime Video — fijo de las capturas reales

def _build_pkce(dev: dict):
    """
    Retorna (params_dict, secrets_dict).
    params_dict  → urlencode para GET /ap/signin
    secrets_dict → device_serial, client_id, code_verifier para el token exchange
    """
    verifier       = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    device_serial  = os.urandom(16).hex().upper()
    client_id      = "device:" + (device_serial + "#" + _DEVICE_TYPE).encode("ascii").hex()
    params = {
        "openid.return_to":                 f"{AMAZON_BASE}/ap/maplanding",
        "openid.oa2.code_challenge_method": "S256",
        "openid.assoc_handle":              "amzn_aiv_ios_us",
        "openid.identity":                  "http://specs.openid.net/auth/2.0/identifier_select",
        "pageId":                           "amzn_dv_ios_blue",
        "accountStatusPolicy":              "P1",
        "openid.claimed_id":                "http://specs.openid.net/auth/2.0/identifier_select",
        "openid.mode":                      "checkid_setup",
        "countryCode":                      dev["country"],
        "openid.ns.oa2":                    f"http://{AMAZON_DOMAIN}/ap/ext/oauth/2",
        "openid.oa2.client_id":             client_id,
        "language":                         dev["language"],
        "openid.ns.pape":                   "http://specs.openid.net/extensions/pape/1.0",
        "openid.oa2.code_challenge":        code_challenge,
        "openid.oa2.scope":                 "device_auth_access",
        "openid.ns":                        "http://specs.openid.net/auth/2.0",
        "openid.pape.max_auth_age":         "0",
        "openid.oa2.response_type":         "code",
    }
    secrets = {
        "device_serial": device_serial,
        "client_id":     client_id,
        "code_verifier": verifier,
    }
    return params, secrets


async def run() -> Outcome:
    #----------------------------------------------------------------------------------#
    #------------------------------------SETUP INICIAL---------------------------------#
    #  nombre · contraseña · email · sesión iOS MAP
    #----------------------------------------------------------------------------------#
    session, dev = make_session()
    faker    = Faker(_FAKER_LOCALE.get(dev["country"], "es_MX"))
    name     = f"{faker.first_name()} {faker.last_name()}"
    _digits  = "".join(random.choices("0123456789", k=random.randint(4, 6)))
    _letters = "".join(random.choices("abcdefghijkmnpqrstuvwxyz", k=random.randint(3, 5)))
    _upper   = random.choice("ABCDEFGHJKLMNPQRSTUVWXYZ")
    _pw_list = list(_digits + _letters + _upper)
    random.shuffle(_pw_list)
    password = "".join(_pw_list)
    t0       = time.time()

    log.banner("AMAZON iOS (canal MAP)")
    print(f"  {log.dim('Datos:')} {log.magenta(name)}  {log.dim('·')}  {log.magenta(f'pwd={password}')}")

    provider, email, get_otp = await setup_email()

    log.step(2, "Creando cuenta")
    log.info("email", email)
    log.info("TLS", f"impersonate={session.impersonate}  ios={dev['ios_version']}")
    log.info("Locale", f"{dev['country']}  ·  {dev['language']}")
    log.info("Proxy", "Sticky enabled" if os.getenv("REQ_PROXY") else "No proxy")
    log.ok("Datos listos")

    #----------------------------------------------------------------------------------#
    #---------------------------------REQUEST NUMERO 1---------------------------------#
    #                     GET  /ap/signin  ·  PKCE setup  ·  canal MAP iOS
    #----------------------------------------------------------------------------------#
    log.step(3, "Registro (iOS)")

    # SIN warmup de retail. El app MAP real (captura Charles) jamás toca la homepage
    # ni /gp/css: su PRIMERA request a amazon.com es GET /ap/signin, llevando solo
    # 3 cookies (frc, map-md, amzn-app-id), y esa misma respuesta emite session-id.
    # Navegar el retail antes dejaba en el jar cookies de tienda (session-token,
    # sst-main, ubid-main, lc-main, i18n-prefs, sp-cdn) que un webview MAP recién
    # abierto NUNCA tiene — contradicción de cliente que dispara el GRID.
    try:
        # Headers exactos de la 1ra navegación del webview MAP (captura Charles):
        # el app la lanza con accept-charset y un accept-encoding/language mínimos,
        # distintos de los que usa el webview ya cargado.
        _pkce_params, _pkce_secrets = _build_pkce(dev)
        async with log.Loader("Cargando /ap/signin..."):
            r = await session.get(
                f"{AMAZON_BASE}/ap/signin?" + urlencode(_pkce_params),
                headers={
                    "accept":          NAV_HEADERS["accept"],
                    "cache-control":   "no-store",
                    "sec-fetch-site":  "none",
                    "accept-charset":  "utf-8",
                    "sec-fetch-mode":  "navigate",
                    "accept-language": "en-US",
                    "accept-encoding": "gzip",
                    "sec-fetch-dest":  "document",
                    "priority":        "u=0, i",
                },
            )

        soup = BeautifulSoup(r.text, "lxml")
        form = amazon.find_register_form(soup)

        if not form:
            log.error("[iOS] No apareció ap_register_form")
            return Outcome.FAILED

    except Exception as e:
        log.error(f"An unexpected error occurred in request 01. Details: {e}.")
        return Outcome.FAILED

    # session-id lo emite /ap/signin (no un warmup). Sin él la sesión no es válida.
    jar = {c.name for c in session.cookies.jar}
    if not {"session-id", "session-id-time"} <= jar:
        log.error("[iOS] /ap/signin no emitió session-id — proxy sin conexión, abortando")
        return Outcome.FAILED
    log.info("Sesión", f"OK: session-id={ {c.name: c.value for c in session.cookies.jar}.get('session-id','?') }")

    # Cookies que pone el JS de la página de signin ya cargada. En el app real
    # aparecen a partir del POST de registro, con csm-hit en formato MAP
    # ({RID}+s-{RID}|{ms}), no el formato retail (tb:s-...&adb:adblk_no).
    try:
        _ms  = int(time.time() * 1000)
        _rid = r.headers.get("x-amz-rid", "")
        session.cookies.set("id_pk",   "eyJuIjoiMSJ9", domain=".amazon.com")
        session.cookies.set("id_pkel", "n1",           domain=".amazon.com")
        if _rid:
            session.cookies.set("csm-hit", f"{_rid}+s-{_rid}|{_ms}", domain=".amazon.com")
    except Exception as _e:
        log.warn(f"[signin] cookies JS: {_e}")

    # Coherencia geo. El device se declara US; si el proxy sale por otro país Amazon
    # lo delata en las cookies que acaba de emitir. Los params PKCE ya viajaron con
    # locale US, así que un exit no-US deja la sesión incoherente → abortar.
    _ck  = {c.name: str(c.value) for c in session.cookies.jar}
    _geo = _ck.get("sp-cdn", "").strip('"').split(":")[-1].upper()
    if _geo and _geo != dev["country"]:
        log.error(f"[geo] Exit por {_geo} pero la sesión se abrió como {dev['country']} — abortando")
        return Outcome.FAILED
    log.info("Geo", f"{dev['country']}  ·  {dev['i18n_currency']}  ·  {dev['timezone']}")

    #----------------------------------------------------------------------------------#
    #---------------------------------REQUEST NUMERO 2---------------------------------#
    #                    POST /ap/register  ·  Send Register
    #----------------------------------------------------------------------------------#
    try:
        referer    = str(r.url)
        action  = amazon.form_action(form, referer)
        data    = amazon.form_inputs(form)
        # Campos que el usuario llena. Todo lo demás (appActionToken, prevRID,
        # workflowState, anti-csrftoken-a2z, webAuthn*, openid.return_to) ya viene
        # del form nativo vía form_inputs — se manda tal cual, como el app real.
        # password va en PLAINTEXT (el app nativo confía en TLS; no encripta con SICE).
        # NO se manda metadata1: el registro nativo MAP nunca lo incluye.
        data.update({
            "appAction":                  "REGISTER",
            "customerName":               name,
            "email":                      email,
            "password":                   password,
            "showPasswordChecked":        "false",
            "shouldShowPersistentLabels": "true",
        })
        for stale in ("encryptedPwd", "encryptedPwdCheck", "encryptedPasswordExpected",
                      "passwordCheck", "metadata1"):
            data.pop(stale, None)

        async with log.Loader("Enviando registro..."):
            r = await session.post(action, data=data, headers={**NAV_HEADERS, "accept-language": dev["accept_language"], "referer": referer}, allow_redirects=False)

        # Seguir los 302 manualmente con headers de navegación (no de POST).
        # El auto-follow arrastraba content-type/origin del form → Amazon devolvía 404.
        _loc_302 = r.headers.get("location", "-")
        log.info("POST register", f"[{r.status_code}] loc={_loc_302[:90]}")

        from urllib.parse import urlsplit, parse_qsl, urlunsplit

        _cvf_arb = ""
        hop_referer = referer
        for _hop in range(1, 7):
            if r.status_code not in (301, 302, 303, 307, 308):
                break
            loc = r.headers.get("location", "")
            if not loc:
                break
            nxt = loc if loc.startswith("http") else f"{AMAZON_BASE}{loc}"

            # Para CVF: quitar el param &language=xx que Amazon añade al Location
            # pero que el origin rechaza. Solo mantener ?arb=...
            if "/ap/cvf/" in nxt:
                _sp  = urlsplit(nxt)
                _arb = dict(parse_qsl(_sp.query)).get("arb", "")
                if _arb:
                    nxt = urlunsplit((_sp.scheme, _sp.netloc, _sp.path, f"arb={_arb}", ""))

            # Orden y set de headers idéntico al hop CVF del app real (captura Charles):
            # accept, sec-fetch-site, priority, sec-fetch-mode, UA, accept-language,
            # sec-fetch-dest, referer, accept-encoding. amzn-app-id va SOLO como cookie.
            _hop_hdrs = {
                "accept":          NAV_HEADERS["accept"],
                "sec-fetch-site":  "same-origin",
                "priority":        "u=0, i",
                "sec-fetch-mode":  "navigate",
                "accept-language": dev["accept_language"],
                "sec-fetch-dest":  "document",
                "referer":         hop_referer,
            }

            r = await session.get(nxt, headers=_hop_hdrs, allow_redirects=False)
            log.info(f"  hop{_hop}", f"[{r.status_code}] {nxt[:100]}")
            hop_referer = nxt

            # Si CVF GET devuelve 404 → arb inválido (GRID) o bloqueo Akamai.
            # Guardar arb y salir del loop; el paso OTP hará POST directo a /ap/cvf/verify.
            if r.status_code == 404 and "/ap/cvf/" in nxt:
                _cvf_arb = dict(parse_qsl(urlsplit(nxt).query)).get("arb", "")
                log.warn(f"[iOS] CVF GET 404 — POST directo a /ap/cvf/verify" +
                         (f" (arb={_cvf_arb[:12]}…)" if _cvf_arb else " [sin arb]"))
                break

        log.info("Forma", "register")
        log.info("Página de registro", f"[{r.status_code}] {str(r.url)[:80]}")

    except Exception as e:
        log.error(f"An unexpected error occurred in request 02. Details: {e}.")
        return Outcome.FAILED

    #----------------------------------------------------------------------------------#
    #---------------------------------REQUEST NUMERO 3---------------------------------#
    #                        CHECK  challenge / OTP detection
    #----------------------------------------------------------------------------------#
    try:
        challenge = amazon.detect_challenge(r.text)

        if challenge or "setupACIC" in r.text:
            log.warn(f"[iOS] Reto: {challenge or 'aamation'} — sesión marcada, abortando intento")
            return Outcome.FAILED

    except Exception as e:
        log.error(f"An unexpected error occurred in request 03. Details: {e}.")
        return Outcome.FAILED

    soup = BeautifulSoup(r.text, "lxml")

    if not _cvf_arb:
        if not amazon.is_otp_page(soup):
            if "register-mase-inlineerror" in r.text or "ap_mase_back_to_signin" in r.text or "Ya existe una cuenta" in r.text:
                log.error("[iOS] Email ya registrado (duplicado)")
                return Outcome.FAILED

            if amazon.wants_phone(soup):
                log.error("[iOS] Amazon pide teléfono — dominio de correo bloqueado o IP quemada")
                return Outcome.PHONE_GATE

            tier = amazon.detect_challenge(r.text)
            if tier:
                log.error(f"[iOS] Captcha: {tier}")
                return Outcome.FAILED

            if not amazon.find_otp_form(soup):
                title     = soup.find("title")
                page_text = soup.get_text(" ", strip=True)[:220]
                log.error(f"[iOS] Página inesperada  title='{title.text.strip() if title else '?'}'")
                log.error(f"[iOS] Contenido: {page_text}")
                try:
                    import os as _os
                    _dbg = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), "debug")
                    _os.makedirs(_dbg, exist_ok=True)
                    _fn = f"cvf_ok_{time.strftime('%H%M%S')}.html"
                    with open(_os.path.join(_dbg, _fn), "w", encoding="utf-8", errors="ignore") as _f:
                        _f.write(r.text or "")
                    log.info("Debug", f"debug/{_fn}")
                except Exception:
                    pass
                return Outcome.FAILED
            log.warn("[iOS] OTP form detectado por fallback")

        log.ok(f"Registro form OK ({r.status_code})")


    #----------------------------------------------------------------------------------#
    #-----------------------------------OTP SETUP-------------------------------------#
    #                         Check Form · Send OTP · Follow Redirects
    #----------------------------------------------------------------------------------#
    log.step(4, "OTP por Email")
    if _cvf_arb:
        # Flujo MAP nativo: nunca cargamos /ap/cvf/request (origin 404 = arb quemado por GRID).
        # POST directo a /ap/cvf/verify con el arb del Location header.
        url      = f"{AMAZON_BASE}/ap/cvf/request?arb={_cvf_arb}"
        otp_html = ""
        action   = f"{AMAZON_BASE}/ap/cvf/verify"
        data     = {
            "arb":                         _cvf_arb,
            "action":                      "code",
            "autoReadStatus":              "manual",
            "verificationPageContactType": "email",
        }
    else:
        url      = str(r.url)
        otp_html = r.text
        form     = amazon.find_otp_form(soup)
        if not form:
            log.error("[iOS] Sin formulario OTP")
            return Outcome.FAILED
        action   = amazon.form_action(form, url)
        data     = amazon.form_inputs(form)

    for attempt in range(1, 4):
        try:
            if provider == "manual":
                (log.info if attempt == 1 else log.warn)(f"[OTP] Intento {attempt}/3 — Teclea el código:")
                code = await get_otp()
            else:
                log.info("Inbox", f"esperando código en {email}...")
                async with log.Loader("Revisando bandeja de entrada..."):
                    code = await get_otp()

            if not code:
                return Outcome.FAILED

            log.ok_kv("OTP recibido", code)
            log.ok_kv("Código", code)
            data.update({
                "code":                        code,
                "action":                      "code",
                "autoReadStatus":              "manual",
                "verificationPageContactType": "email",
                "metadata1":                   gen_metadata1_otp(url, url, dev["ua"], domain="amazon.com",
                                                                 code_len=len(code), device=dev, page_html=otp_html),
            })
            if csrf := soup.find("input", {"name": "anti-csrftoken-a2z"}):
                data["anti-csrftoken-a2z"] = csrf.get("value", "")

            #------------------------------------------------------------------------#
            #---------------------------REQUEST NUMERO 4-----------------------------#
            #                POST /ap/cvf/verify  ·  submit OTP
            #------------------------------------------------------------------------#
            async with log.Loader("Verificando código..."):
                r = await session.post(
                    action, data=data,
                    headers={**NAV_HEADERS, "referer": url},
                    allow_redirects=False,
                )

            log.info("CVF verify", f"[{r.status_code}] loc={r.headers.get('location', '-')[:80]}")
            if _cvf_arb and r.status_code not in (301, 302, 303, 307, 308):
                try:
                    import os as _os
                    _dbg = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), "debug")
                    _os.makedirs(_dbg, exist_ok=True)
                    _st = time.strftime("%H%M%S")
                    _fn = f"verify_{_st}.html"
                    with open(_os.path.join(_dbg, _fn), "w", encoding="utf-8", errors="ignore") as _f:
                        _f.write(r.text or "")
                    log.info("Debug", f"debug/{_fn}  [{r.status_code}]")
                except Exception as _e:
                    log.warn(f"[debug verify] {_e}")

            #------------------------------------------------------------------------#
            #---------------------------REDIRECT CHAIN-------------------------------#
            #      cvf/verify → /ap/register?claimToken → /ap/maplanding
            #      El at-main se setea en el salto del claimToken, misma sesión iOS
            #------------------------------------------------------------------------#
            referer = f"{AMAZON_BASE}/ap/cvf/verify"
            for _ in range(5):
                if r.status_code not in (301, 302, 303, 307, 308):
                    break
                loc = r.headers.get("location", "")
                if not loc:
                    break
                nxt = loc if loc.startswith("http") else f"{AMAZON_BASE}{loc}"
                r = await session.get(
                    nxt,
                    headers={
                        "accept":          NAV_HEADERS["accept"],
                        "accept-language": dev["accept_language"],
                        "sec-fetch-site":  "same-origin",
                        "sec-fetch-mode":  "navigate",
                        "sec-fetch-dest":  "document",
                        "priority":        "u=0, i",
                        "referer":         referer,
                    },
                    allow_redirects=False,
                )
                referer = nxt

            final, jar = str(r.url), {c.name for c in session.cookies.jar}

        except Exception as e:
            log.error(f"[OTP] Error intento {attempt}: {e}")
            return Outcome.FAILED
        #------------------------------------------------------------------------#
        #---------------------------Create IF-------------------------------#
        #                   claimToken hop  ·  Reload Redirect
        #------------------------------------------------------------------------#
        auth   = jar & AUTH_COOKIES
        landed = "/ap/maplanding" in final and "authorization_code" in final

        if auth or landed:
            log.ok_kv("Código válido", code)

            log.step(5, "Token exchange (api.amazon.com)")
            if landed:
                from urllib.parse import urlsplit, parse_qs
                _auth_code = parse_qs(urlsplit(final).query).get("authorization_code", [""])[0]
                if _auth_code:
                    try:
                        _frc = gen_frc_ios(
                            _pkce_secrets["device_serial"],
                            dev["app"]["version"],
                            dev["ios_version"],
                        )
                        _proxy = os.getenv("REQ_PROXY") or None
                        _api   = exchange_code(
                            authorization_code = _auth_code,
                            client_id          = _pkce_secrets["client_id"],
                            code_verifier      = _pkce_secrets["code_verifier"],
                            device_serial      = _pkce_secrets["device_serial"],
                            frc                = _frc,
                            ios_version        = dev["ios_version"],
                            proxy              = _proxy,
                        )
                        _parsed = parse_exchange(_api)
                        if not _parsed.get("error"):
                            log.ok("Token exchange OK")
                            log.info("bearer", _parsed["access_token"][:20] + "…")
                            log.info("cookies", str(list(_parsed["website_cookies"].keys())))
                            # Inyectar website_cookies en la sesión para que export_cookies las guarde
                            for _cn, _cv in _parsed["website_cookies"].items():
                                session.cookies.set(_cn, _cv, domain=".amazon.com")
                        else:
                            log.warn(f"[exchange] error: {_parsed['error'].get('_http_error')} "
                                     f"— {str(_parsed['error'])[:120]}")
                    except Exception as _ex:
                        log.warn(f"[exchange] excepción: {_ex}")
                else:
                    log.warn("[exchange] no se encontró authorization_code en URL de maplanding")

            log.step(6, "Confirmación de Registro")
            folder = export_cookies(session, email, password)

            log.step(7, "Resultado")
            log.success("Cuenta creada exitosamente")
            log.result_summary(email, password, "✓ Cuenta creada",
                               f"{time.time() - t0:.0f}s",
                               str(folder / "account.txt"), str(folder))
            return Outcome.SUCCESS

        soup   = BeautifulSoup(r.text, "lxml")
        reg    = "/ap/register" in final and r.status_code == 200 and amazon.find_register_form(soup)

        ei, ni = (reg.find("input", {"name": "email"}), reg.find("input", {"name": "customerName"})) if reg else (None, None)


        #------------------------------------------------------------------------#
        #---------------------------INIT VARS-----------------------------#
        #                   jar auth  ·  MAP register pre-filled
        #------------------------------------------------------------------------#
        if reg and (ei and ei.get("value") or ni and ni.get("value")):
            log.ok("OTP recibido: código válido (MAP register pre-filled)")

            wdev  = new_desktop_device()
            _hdrs = {
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "accept-language": dev["accept_language"], "sec-fetch-site": "same-origin",
                "sec-fetch-mode": "navigate", "sec-fetch-dest": "document", "upgrade-insecure-requests": "1",
                **wdev["headers"],
            }

            ws           = AsyncSession(impersonate=wdev["tls_profile"])
            ws.trust_env = False
            ws.headers.update({"User-Agent": wdev["ua"]})
            if proxy := os.getenv("REQ_PROXY"):
                ws.proxies = {"http": proxy, "https": proxy}
            ws_auth = set()
            ws_pw   = password

                
            #------------------------------------------------------------------------#
            #---------------------------REQUEST NUMERO 5-----------------------------#
            #                  GET  /ap/signin  ·  Login web (post-OTP)
            #------------------------------------------------------------------------#
            try:
                _return_to = quote(f"{AMAZON_BASE}/?ref_=nav_signin", safe="")
                wr = await ws.get(
                    f"{AMAZON_BASE}/ap/signin?openid.pape.max_auth_age=0"
                    f"&openid.return_to={_return_to}"
                    "&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select"
                    "&openid.assoc_handle=usflex&openid.mode=checkid_setup"
                    "&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select"
                    "&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0",
                    headers=_hdrs,
                )
                log.info("[web_login] R5", f"{wr.status_code} → {str(wr.url)[:80]}")
                wsoup      = BeautifulSoup(wr.text, "lxml")
                email_form = amazon.find_login_email_form(wsoup)

                if not email_form:
                    raise RuntimeError("No form de email en R5")

            #------------------------------------------------------------------------#
            #---------------------------REQUEST NUMERO 6-----------------------------#
            #               POST /ap/signin  ·  Send email (pre-login)
            #------------------------------------------------------------------------#
                wd          = amazon.form_inputs(email_form)
                wd["email"] = email

                wr    = await ws.post(amazon.form_action(email_form, str(wr.url)), data=wd, allow_redirects=True, headers={**_hdrs, "referer": str(wr.url), "content-type": "application/x-www-form-urlencoded", "origin": AMAZON_BASE})
                log.info("[web_login] R6", f"{wr.status_code} → {str(wr.url)[:80]}")
                wsoup = BeautifulSoup(wr.text, "lxml")

                if "/ap/forgotpassword/reverification" in str(wr.url):
                    log.warn("[web_login] reverification detectada")
                    sf = wsoup.find("form")

                    if sf:
                        wr    = await ws.post(amazon.form_action(sf, str(wr.url)), data=amazon.form_inputs(sf), allow_redirects=True, headers={**_hdrs, "referer": str(wr.url), "content-type": "application/x-www-form-urlencoded", "origin": AMAZON_BASE})
                        log.info("[web_login] reverif POST", f"{wr.status_code} → {str(wr.url)[:80]}")
                        wsoup = BeautifulSoup(wr.text, "lxml")

                    if amazon.is_otp_page(wsoup):
                        log.warn("[web_login] reverif pide OTP")
                        of      = amazon.find_otp_form(wsoup)
                        rv_code = await get_otp()

                        if of and rv_code:
                            rd         = amazon.form_inputs(of)
                            rd["code"] = rv_code

                            if csrf := wsoup.find("input", {"name": "anti-csrftoken-a2z"}):
                                rd["anti-csrftoken-a2z"] = csrf.get("value", "")

                            wr    = await ws.post(amazon.form_action(of, str(wr.url)), data=rd, allow_redirects=True, headers={**_hdrs, "referer": str(wr.url), "content-type": "application/x-www-form-urlencoded", "origin": AMAZON_BASE})
                            log.info("[web_login] reverif OTP", f"{wr.status_code} → {str(wr.url)[:80]}")
                            wsoup = BeautifulSoup(wr.text, "lxml")
                    else:
                        log.info("[web_login] reverif sin OTP", f"url={str(wr.url)[:60]}")

                ws_auth = {c.name for c in ws.cookies.jar} & AUTH_COOKIES
                log.info("[web_login] cookies post-R6", f"{', '.join(ws_auth) or 'ninguna'}")

            #------------------------------------------------------------------------#
            #---------------------------REQUEST NUMERO 7-----------------------------#
            #                POST /ap/signin  ·  Send password (login)
            #------------------------------------------------------------------------#
                if not ws_auth:
                    pw_form  = amazon.find_login_password_form(wsoup)
                    is_reset = pw_form and "passwordCheck" in amazon.form_inputs(pw_form)
                    log.info("[web_login] R7", f"pw_form={'sí' if pw_form else 'no'}  is_reset={is_reset}")

                    if pw_form:
                        wd             = amazon.form_inputs(pw_form)
                        wd["email"]    = email
                        wd["password"] = password

                        if is_reset:
                            wd["passwordCheck"] = password

                        wr      = await ws.post(amazon.form_action(pw_form, str(wr.url)), data=wd, allow_redirects=True, headers={**_hdrs, "referer": str(wr.url), "content-type": "application/x-www-form-urlencoded", "origin": AMAZON_BASE})
                        ws_auth = {c.name for c in ws.cookies.jar} & AUTH_COOKIES
                        log.info("[web_login] R7 resp", f"{wr.status_code} → {str(wr.url)[:80]}  cookies={', '.join(ws_auth) or 'ninguna'}")

                        if not ws_auth and is_reset:
                            wsoup          = BeautifulSoup(wr.text, "lxml")
                            try_pw         = str(random.randint(100000, 99999999)) + "Aa1"
                            pw_form        = amazon.find_login_password_form(wsoup) or pw_form

                            wd["password"] = try_pw
                            wd["passwordCheck"] = try_pw

                            wr      = await ws.post(amazon.form_action(pw_form, str(wr.url)), data=wd, allow_redirects=True, headers={**_hdrs, "referer": str(wr.url), "content-type": "application/x-www-form-urlencoded", "origin": AMAZON_BASE})
                            ws_auth = {c.name for c in ws.cookies.jar} & AUTH_COOKIES
                            log.info("[web_login] R7 retry-pw", f"{wr.status_code} → {str(wr.url)[:80]}  cookies={', '.join(ws_auth) or 'ninguna'}")

                            if ws_auth:
                                ws_pw = try_pw

            except Exception as e:
                log.error(f"[web_login] {e}")

            log.ok(f"web_login ({','.join(ws_auth)})") if ws_auth else log.warn("[web_login] Sin at-main, exportando MAP")

            log.step(5, "Confirmación de Registro")
            folder = export_cookies(ws if ws_auth else session, email, ws_pw if ws_auth else password)
            await ws.close()

            log.step(6, "Resultado")
            log.success("Cuenta creada exitosamente")
            log.result_summary(email, ws_pw if ws_auth else password, "✓ Cuenta creada",
                               f"{time.time() - t0:.0f}s",
                               str(folder / "account.txt"), str(folder))
            return Outcome.SUCCESS
        #------------------------------------------------------------------------#
        #---------------------------Algoritmo Finally-----------------------------#
        #                otp no verify failed  ·  check register form
        #------------------------------------------------------------------------#
        if amazon.wants_phone(soup):
            log.error("[OTP] Requiere teléfono (SMS)")
            return Outcome.PHONE_GATE

        if err := amazon.extract_error(soup):
            log.warn(f"[OTP] {err[:120]}")

        if not (form := amazon.find_otp_form(soup)):
            log.error("[OTP] Sin formulario OTP y sin éxito real (sin at-main)")
            return Outcome.FAILED

        action = amazon.form_action(form, final)
        data   = amazon.form_inputs(form)

    log.error("[OTP] No se verificó el código.")
    return Outcome.FAILED



# amazon-register

Script para automatizar el registro de cuentas en Amazon usando el flujo MAP (el mismo que usa la app móvil), incluyendo el paso de verificación por teléfono.

## Qué hace

- Genera una sesión con TLS fingerprint de iOS (curl_cffi)
- Arma las cookies `frc`, `map-md` y `amzn-app-id` igual que el app real
- Resuelve el registro completo: `ap/register` → verificación de teléfono → código OTP
- Soporta emails temporales (mail.tm / SmailPro) para el paso de verificación
- Exporta las cookies de sesión al terminar (`cookies.json`, `cookie-string.txt`, `account.txt`)

## Estructura

```
Function/
  amazon.py        # sesión, parsing de forms, cookies, clientes de email
  amazonphone.py   # flujo de registro + verificación de teléfono
  log.py           # logging con formato
device/
  ios_device.py    # generación de fingerprints de dispositivo iOS
encrypt/
  frc.py           # generación del cookie frc (AES-CBC + HMAC, igual que el app)
  waf.py / fwcim.py / acic_pow.py / siege.py   # desafíos anti-bot de Amazon
gencookie.py        # entry point, corre el flujo y guarda las cookies
```

## Uso

```bash
pip install -r requirements.txt
python gencookie.py
```

Configurar `.env` con las variables necesarias (proxy, API key de capsolver, proveedor de email, etc).

## Notas

El cookie `frc` se deriva con PBKDF2-SHA256 (1000 iteraciones) a partir de un serial aleatorio, igual que lo hace el cliente iOS real — está verificado contra capturas de tráfico del app.

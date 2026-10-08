import base64
import gzip
import hashlib
import hmac as _hmac
import json
import os
import random
import time
import uuid
from io import BytesIO

from Crypto.Cipher import AES

from device import new_ios_device

_SERIAL_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _rand_serial() -> str:
    return "".join(random.choices(_SERIAL_CHARS, k=32))


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    n = block_size - len(data) % block_size
    return data + bytes([n] * n)


def gen_frc_cookie(device: dict | None = None) -> tuple[str, str]:
    dev     = device or new_ios_device()
    os_ver  = dev["ios_version"]
    app     = dev["app"]
    app_ver = app["version"]
    iphone  = dev["iphone"]
    tz      = dev["timezone"]
    serial  = _rand_serial()

    payload = {
        "DeviceData": {
            "ApplicationVersion": app_ver,
            "DeviceLanguage": dev["device_language"],
            "DeviceFingerprintTimestamp": str(int(time.time() * 1000)),
            "DeviceOSVersion": f"iOS/{os_ver}",
            "DeviceName": iphone.get("display_name", iphone["name"]),
            "ScreenHeightPixels": iphone["h"],
            "ThirdPartyDeviceId": str(uuid.uuid4()).upper(),
            "TimeZone": tz,
            "ApplicationName": app["name"],
            "ScreenWidthPixels": iphone["w"],
            "DeviceJailbroken": False,
        },
        "AppUserAgent": f"AmazonWebView/{app['name']}/{app_ver}/iOS/{os_ver}/iPhone",
        "WebUserAgent": dev.get("ua", ""),
        "Serial": serial,
    }

    json_bytes = json.dumps(payload, separators=(",", ":")).encode()

    buf = BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(json_bytes)
    compressed = buf.getvalue()

    enc_key  = hashlib.pbkdf2_hmac("sha256", serial.encode(), b"AES/CBC/PKCS7Padding", 1000, dklen=16)
    hmac_key = hashlib.pbkdf2_hmac("sha256", serial.encode(), b"HmacSHA256",           1000, dklen=32)

    iv         = os.urandom(16)
    cipher     = AES.new(enc_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(_pkcs7_pad(compressed))

    mac = _hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()[:8]

    frc_bytes = bytes([0]) + mac + iv + ciphertext
    return base64.b64encode(frc_bytes).decode(), serial

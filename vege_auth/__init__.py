import hmac
from base64 import b64decode
from hashlib import sha256
from json import dumps, loads
from random import choice
from string import digits, ascii_letters
from sys import argv
from typing import Optional

from requests import Session
from rsa import PrivateKey, decrypt

from vege_auth.hwid import hwid


class AuthResponse:
    license_type: str
    license_expiration: str
    variables: dict

    def __init__(self, license_type: str, license_expiration: str, variables: dict):
        self.license_type = license_type
        self.license_expiration = license_expiration
        self.variables = variables


class AuthError(Exception):
    pass


class AuthClient:
    aid: str
    api_key: str
    secret: bytes
    session: Session
    hwid: str
    rsa_private_key: Optional[PrivateKey]

    def __init__(self, aid: str, api_key: str, client_secret: str, rsa_private_key: Optional[str]):
        self.aid = aid
        self.api_key = api_key
        self.secret = client_secret.encode()

        self.session = Session()
        self.session.trust_env = False

        self.hwid = hwid()

        if rsa_private_key:
            self.rsa_private_key = PrivateKey.load_pkcs1(rsa_private_key.encode())
        else:
            self.rsa_private_key = None

    def authenticate(self, username: str, password: str):
        nonce = nonce_gen()

        payload = {
            "username": username,
            "password": password,
            "hwid": self.hwid,
            "aid": self.aid,
            "key": self.api_key,
            "nonce": nonce,
            "hash": get_hash()
        }

        h = hmac.new(self.secret, dumps(payload).encode("utf-8"), digestmod=sha256).hexdigest()

        try:
            s = self.session.post(
                "https://auth.vegetables.inc/api/v4/authenticate",
                json=payload,
                headers={"x-vege-signature": h}
            )
        except Exception as ex:
            raise AuthError("failed to connect to authentication server: " + str(repr(ex)))

        r = loads(s.text)

        if r["success"] and r["nonce"] == nonce:
            if verify_hmac(s.text.encode(), s.headers["x-vege-signature"], self.secret):
                if not r["license_info"]["expired"]:
                    v = r["variables"]

                    if self.rsa_private_key:
                        for key in v.keys():
                            decrypted = decrypt_variable(v[key], self.rsa_private_key)
                            v[key] = decrypted

                    return AuthResponse(r["license_info"]["type"], r["license_info"]["expiration"], v)
                else:
                    raise AuthError("license has expired")
            else:
                raise AuthError("invalid hmac")
        else:
            if r["errorDetails"]["type"] == "credentials":
                raise AuthError("invalid username or password")
            elif r["errorDetails"]["type"] == "hwid":
                raise AuthError("invalid HWID. reset it")
            elif r["errorDetails"]["type"] == "hash":
                raise AuthError("invalid program hash. please download the latest version of the tool")
            else:
                raise AuthError(r["errorDetails"]["type"])

    def register(self, username: str, password: str, contact: str, license_key: str):
        payload = {
            "username": username,
            "password": password,
            "hwid": self.hwid,
            "aid": self.aid,
            "key": self.api_key,
            "license": license_key,
            "contact": contact
        }

        h = hmac.new(self.secret, dumps(payload).encode("utf-8"), digestmod=sha256).hexdigest()

        try:
            s = self.session.post(
                "https://auth.vegetables.inc/api/v4/register",
                json=payload,
                headers={"x-vege-signature": h}
            )
        except Exception as ex:
            return 'failed to connect to authentication server: ' + str(repr(ex))

        r = loads(s.text)

        if r["success"]:
            if verify_hmac(s.text.encode(), s.headers["x-vege-signature"], self.secret):
                return "success"
            else:
                return "invalid hmac"
        else:
            if r["errorDetails"]["type"] == "invalid license":
                return "invalid registration key"
            else:
                return r["errorDetails"]["type"]

    def reset(self, username: str, password: str, hwid_reset_key: str):
        payload = {
            "username": username,
            "password": password,
            "hwid": self.hwid,
            "aid": self.aid,
            "key": self.api_key,
            "reset_key": hwid_reset_key
        }

        h = hmac.new(self.secret, dumps(payload).encode("utf-8"), digestmod=sha256).hexdigest()

        try:
            s = self.session.post(
                url=f'https://auth.vegetables.inc/api/v4/reset',
                json=payload,
                headers={"x-vege-signature": h}
            )
        except Exception as ex:
            return 'failed to connect to authentication server: ' + str(repr(ex))

        r = loads(s.text)

        if r["success"]:
            if verify_hmac(s.text.encode(), s.headers["x-vege-signature"], self.secret):
                return "success"
            else:
                return "invalid hmac"
        else:
            if r["errorDetails"]["type"] == "invalid key":
                return "invalid reset key"
            elif r["errorDetails"]["type"] == "reseting too fast":
                return "reset hwid in last 24 hours"
            else:
                return r["errorDetails"]["type"]


def verify_hmac(raw_body: bytes, client_signature: str, hmac_secret: bytes) -> bool:
    computed_sha = hmac.new(hmac_secret, raw_body, digestmod=sha256).hexdigest()
    return computed_sha == client_signature


def nonce_gen() -> str:
    return ''.join(choice(ascii_letters + digits) for _ in range(30))


def get_hash() -> str:
    try:
        return sha256(open(argv[0], "rb").read()).hexdigest()
    except:
        return 'error'


def decrypt_variable(variable: str, key: PrivateKey) -> str:
    decoded = b64decode(variable)

    decrypted_bytes = decrypt(decoded, key)

    return decrypted_bytes.decode('utf8')

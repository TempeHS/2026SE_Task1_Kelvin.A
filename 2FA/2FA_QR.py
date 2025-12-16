import pyotp
import time
import qrcode


def gen_key():
    return pyotp.random_base32()


def gen_url(key):
    return pyotp.totp.TOTP(key).provisioning_uri(name="bob", issuer_name="2FA App")


def verify_code(key: str, code: str):
    totp = pyotp.TOTP(key)
    return totp.verify(code)


key = gen_key()

totp = pyotp.TOTP(key)

uri = gen_url(key)

qe.make(uri).save("NCode.png")

while True:
    code = input("enter code: ")
    print(verify_code(key, code))

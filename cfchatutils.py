import asyncio
import json
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
from jblob import JBlob

#FOR GUI VERSION ONLY, NOT COMPATIBLE WITH OOB OR ONE FILE VERSIONS!

def empty_queue(q: asyncio.Queue):
    #Empties Queue
    while not q.empty():
        try:
            item = q.get_nowait()
            print(f"Discarded item: {item}")
        except asyncio.QueueEmpty:
            break

def ratchet(key: bytes, info: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        salt=None,
        info=info,
        length=32,
    ).derive(key)

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )

    return kdf.derive(password.encode('utf-8'))

#These basic functions encrypt or decrypt stuff
def encrypt(key: bytes, plaintext: bytes) -> bytes:
    aead = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ciphertext = aead.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ciphertext

def decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aead = ChaCha20Poly1305(key)
    plaintext = aead.decrypt(nonce, ciphertext, associated_data=None)

    return plaintext

def check_password(password: str, account: JBlob):
    salt = bytes.fromhex(account.opt_data['salt'])
    key = derive_key(password, salt)

    try:
        account.try_decrypt(key)
    except InvalidTag:
        return False
    return True

def load_account(username):
    try:
        with open(f"{username}.act", 'r') as f:
            account = json.load(f)
        return account
    except:
        return False

def get_key_by_value(dict: dict, search_value):
    for key, value in dict.items():
        if value == search_value:
            return key

if __name__ == "__main__":
    pass
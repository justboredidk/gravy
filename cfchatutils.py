import asyncio
import json
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidTag, InvalidSignature
from cryptography.hazmat.primitives import serialization
from getpass import getpass
from prompt_toolkit import print_formatted_text
from jblob import JBlob

#FOR GUI VERSION ONLY, NOT COMPATIBLE WITH OOB OR ONE FILE VERSIONS!

def empty_queue(q: asyncio.Queue):
    #Empties Queue
    while not q.empty():
        try:
            item = q.get_nowait()
            print_formatted_text(f"Discarded item: {item}")
        except asyncio.QueueEmpty:
            break

def load_identities(account: dict) -> dict:
    try:
        with open(f'{account["username"]}.id', 'r') as f:
            id_list = json.load(f)
    except:
        return None

    return id_list

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

def login(account):
    while 1:
        password = getpass("Password: ")
        if check_password(password, account):
            break
        else:
            print_formatted_text("Password Incorrect :(")
    
    salt = bytes.fromhex(account['salt'])
    key = derive_key(password, salt)
    nonce = bytes.fromhex(account['blob'][0])
    ciphertext = bytes.fromhex(account['blob'][1])

    decrypted_blob_bytes = decrypt(key, nonce, ciphertext)
    decrypted_blob = json.loads(decrypted_blob_bytes.decode('utf-8'))

    #print(f"Priv: {decrypted_blob['priv_bytes']}, Pub: {decrypted_blob['pub_bytes']}")
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(decrypted_blob['priv_bytes']))
    public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(decrypted_blob['pub_bytes']))

    test_sig = private_key.sign(b'test')
    try:
        public_key.verify(test_sig, b'test')
        print_formatted_text("Keys matched!")
    except InvalidSignature:
        print_formatted_text("Keys did not match!")

    print_formatted_text(f'Logged in as {account["username"]}')

    return key, private_key, public_key, account

def check_password(password: str, account: JBlob):
    salt = bytes.fromhex(account.opt_data['salt'])
    key = derive_key(password, salt)

    try:
        account.try_decrypt(key)
    except InvalidTag:
        return False
    return True

def make_account(username):
    while True:
        password = getpass("Password: ")
        password_v = getpass("Confirm Password: ")
        if password != password_v:
            print_formatted_text("Passwords do not match!")
        else:
            break
    
    check = os.urandom(32)
    salt = os.urandom(16)

    key = derive_key(password, salt)
    del password, password_v

    nonce, encrypted_check = encrypt(key, check)
    #decrypted_check = decrypt(key, encrypted_check["nonce"], encrypted_check["ciphertext"])

    account = {
        'username': username,
        'salt': salt.hex(),
        'ec_nonce': nonce.hex(),
        'ec_ciphertext': encrypted_check.hex(),
        'blob': None
    }

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    blob = {
        "priv_bytes": private_key.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption()).hex(),
        "pub_bytes": public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()
    }

    blob_bytes = json.dumps(blob).encode('utf-8')
    blob_nonce, blob_data = encrypt(key, blob_bytes)

    account['blob'] = (blob_nonce.hex(), blob_data.hex())

    with open(f"{username}.act", 'w') as f:
        json.dump(account, f)
    
    print("Account Created!")

def load_account(username):
    try:
        with open(f"{username}.act", 'r') as f:
            account = json.load(f)
        return account
    except:
        return False

if __name__ == "__main__":
    pass
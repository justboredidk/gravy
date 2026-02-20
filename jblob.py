from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
import os
import json

class jblob:
    def __init__(self, filename=None):
        self.filename = filename
        self.data = {}
        self.nonce = None
        self.encrypted = None

    def decrypt(self, key: bytes):
        aead = ChaCha20Poly1305(key)
        decrypted_blob = aead.decrypt(self.nonce, self.encrypted, associated_data=None)
        self.data = json.loads(decrypted_blob.decode('utf-8'))

        return self.data
    
    def encrypt(self, key: bytes):
        aead = ChaCha20Poly1305(key)
        nonce = os.urandom(12)

        blob = json.dumps(self.data).encode('utf-8')
        encrypted_blob = aead.encrypt(nonce, blob, associated_data=None)

        self.nonce = nonce
        self.encrypted = encrypted_blob

        return nonce, encrypted_blob
    
    def load(self, filename=None):
        if self.filename != None:
            filename = self.filename
        else:
            self.filename = filename
        
        with open(filename, 'r') as f:
            contents = json.load(f)
        
        self.encrypted = bytes.fromhex(contents["encrypted"])
        self.nonce = bytes.fromhex(contents["nonce"])

        return
    
    def save(self, filename=None):
        if self.filename != None:
            filename = self.filename
        else:
            self.filename = filename

        contents = {"nonce": self.nonce.hex(), "encrypted": self.encrypted.hex()}
        
        with open(filename, 'w') as f:
            json.dump(contents, f)

if __name__ == "__main__":
    key = os.urandom(32)
    data = {"name": "john", "age": 21}

    gov_database = jblob()
    gov_database.data = data
    gov_database.encrypt(key)
    gov_database.save("database.dat")
    print(gov_database.nonce.hex())

    gov_database.data = {}
    gov_database.encrypted = None
    gov_database.nonce = None

    gov_database.load("database.dat")
    gov_database.decrypt(key)
    print(gov_database.nonce.hex())

    print(data)
    print(gov_database.data)
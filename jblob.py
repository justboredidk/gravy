from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
from xxhash import xxh64
import os
import json

class JBlob:
    def __init__(self, filename=None):
        self.filename = filename
        self.data = {}
        self.opt_data = {}
        self.nonce = None
        self.encrypted = None
        self.hash: xxh64 = None

    def decrypt(self, key: bytes):
        aead = ChaCha20Poly1305(key)
        try:
            decrypted_blob = aead.decrypt(self.nonce, self.encrypted, associated_data=None)
        except InvalidTag:
            raise InvalidTag
        self.data = json.loads(decrypted_blob.decode('utf-8'))

        return self.data
    
    def try_decrypt(self, key: bytes):
        aead = ChaCha20Poly1305(key)
        try:
            aead.decrypt(self.nonce, self.encrypted, associated_data=None)
        except InvalidTag:
            raise InvalidTag
    
    def encrypt(self, key: bytes):
        aead = ChaCha20Poly1305(key)
        nonce = os.urandom(12)

        blob = json.dumps(self.data, sort_keys=True).encode('utf-8')
        self.hash = xxh64(blob).hexdigest()
        encrypted_blob = aead.encrypt(nonce, blob, associated_data=None)
        del blob

        self.nonce = nonce
        self.encrypted = encrypted_blob

        return nonce, encrypted_blob
    
    def is_dirty(self) -> bool:
        current_hash = xxh64(json.dumps(self.data, sort_keys=True).encode('utf-8')).hexdigest()
        if current_hash == self.hash:
            return False
        else:
            return True
    
    def load(self, filename=None):
        if self.filename != None:
            filename = self.filename
        else:
            self.filename = filename
        
        try:
            with open(filename, 'r') as f:
                contents = json.load(f)
        except:
            return False
        
        self.encrypted = bytes.fromhex(contents["encrypted"])
        self.nonce = bytes.fromhex(contents["nonce"])
        self.opt_data = contents["opt_data"]

        return True
    
    def save(self, filename=None):
        if self.filename != None:
            filename = self.filename
        else:
            self.filename = filename

        contents = {"opt_data": self.opt_data, "nonce": self.nonce.hex(), "encrypted": self.encrypted.hex()}
        try:
            with open(filename, 'w') as f:
                json.dump(contents, f)
        except:
            return False
        
        return True

if __name__ == "__main__":
    key = os.urandom(32)
    data = {"name": "john", "age": 21}

    gov_database = JBlob()
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
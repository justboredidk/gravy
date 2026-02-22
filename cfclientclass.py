import asyncio
import websockets
import itertools
import shlex
import traceback
import os
import cfchatutils as cfu
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidTag, InvalidSignature
import json
#import jblob
from getpass import getpass
from prompt_toolkit import PromptSession, print_formatted_text

class Client:
    def __init__(self):
        self.server_id = None
        self.inbound = asyncio.Queue()
        self.outbound = asyncio.Queue()
        self.inbound_usr = asyncio.Queue()
        self.outbound_usr = asyncio.Queue()
        self.encryption = asyncio.Queue()
        self.log = []
        self.stop_event = asyncio.Event()
        self.STOP = object()
    
    async def exit(self):
        self.stop_event.set()
        await self.log_event("Client Exiting")
        await self.inbound.put(self.STOP)
        await self.outbound.put(self.STOP)
        await self.inbound_usr.put(self.STOP)
        await self.outbound_usr.put(self.STOP)
        await self.encryption.put((self.STOP, None))
        return

    async def client_router(self, websocket):
        while not self.stop_event.is_set():
            try:
                data = await asyncio.wait_for(self.outbound.get(), timeout=0.5)
            except asyncio.TimeoutError:
                continue  # check stop_event again

            if data == self.STOP:
                continue

            try:
                await websocket.send(json.dumps(data))
            except websockets.ConnectionClosed:
                await self.log_event("Connection to server closed")
                await self.exit()
                break


    async def client_reciever(self, websocket):
        while not self.stop_event.is_set():
            try:
                data = await asyncio.wait_for(websocket.recv(), timeout=0.5)
                await self.encryption.put(('server', json.loads(data)))
            except asyncio.TimeoutError:
                # No message this time, check self.stop_event again
                continue
            except asyncio.CancelledError:
                # forced shutdown
                break
            except websockets.ConnectionClosed:
                await self.log_event('Server disconnect')
                await self.exit()
                break
            except Exception as e:
                await self.log_event(f'Exception {e} in client_reciever')
                break
    
    async def send(self,cmd):
        try:
            await self.encryption.put(("usr", cmd))
        except websockets.ConnectionClosed:
            await self.log_event("Server disconnected")

    async def recv(self):
        usr_msg = await self.inbound_usr.get()
        if usr_msg == self.STOP:
            return None
        else:
            return usr_msg

    async def recv_stream(self):
        while not self.stop_event.is_set():
            usr_msg = await self.inbound_usr.get()
            if usr_msg == self.STOP:
                break
            yield usr_msg
    
    async def client_encryption(self, server_id: str, ed_private_key):
        try:
            #send server the public key
            my_private_key = X25519PrivateKey.generate()
            my_public_key = my_private_key.public_key()

            await self.outbound.put({
                'type': 'pub_key',
                'contents': my_public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                ).hex()
                })

            #print_formatted_text('Beginning Encryption Loop')
            while not self.stop_event.is_set():
                #print_formatted_text('Awaiting messages')
                msg_type, data = await self.encryption.get()
                if msg_type == self.STOP:
                    continue
                
                #print_formatted_text(f'{msg_type} {data}')

                if msg_type == 'server' and data['type'] == 'pub_key':
                    peer_public_key = X25519PublicKey.from_public_bytes(bytes.fromhex(data['contents']))
                    shared_secrect  = my_private_key.exchange(peer_public_key)

                    #identity verification
                    random = os.urandom(32)
                    challenge = (
                        peer_public_key.public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw
                        ) + 
                        my_public_key.public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw
                        ) +
                        random
                    )
                    await self.log_event(f"challenge i made (server+client+random) {challenge.hex()}")               
                    signature = ed_private_key.sign(challenge)

                    await self.outbound.put({
                        'type': 'signed',
                        'random': random.hex(),
                        'signature': signature.hex()
                        })
                    
                    await self.log_event(f"Signature i made {signature.hex()}")
                    
                    #Wait until message with signature is recieved
                    while 1:
                        ed_msg_type, ed_data = await self.encryption.get()
                        if ed_data['type'] == 'signed':
                            break
                        self.encryption.put((ed_msg_type, ed_data))
                    
                    random = bytes.fromhex(ed_data['random'])
                    signature = bytes.fromhex(ed_data['signature'])

                    challenge = (
                        peer_public_key.public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw
                        ) + 
                        my_public_key.public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw
                        ) +
                        random
                    )

                    await self.log_event(f"challenge recieved (server+client+random) {challenge.hex()}")
                    await self.log_event(f"Signature i recieved {signature.hex()}")

                    unpacked_server_id = Ed25519PublicKey.from_public_bytes(bytes.fromhex(server_id))
                    
                    try:
                        unpacked_server_id.verify(signature, challenge)
                    except InvalidSignature:
                        await self.log_event('Server identity could not be verified, exiting')
                        await self.exit()
                        continue

                    await self.log_event('Server Identity Verified')

                    #sets up server_key (sent by server), and client_key (sent by client)
                    #region
                    root_key = HKDF(
                        algorithm=hashes.SHA256(),
                        salt=None,
                        info=b'root',
                        length=32,
                    ).derive(shared_secrect)

                    server_key = HKDF(
                        algorithm=hashes.SHA256(),
                        salt=None,
                        info=b'server',
                        length=32,
                    ).derive(root_key)

                    client_key = HKDF(
                        algorithm=hashes.SHA256(),
                        salt=None,
                        info=b'client',
                        length=32,
                    ).derive(root_key)
                    
                    del root_key
                    #endregion

                    #print_formatted_text(shared_secrect.hex())

                elif msg_type == 'usr':
                    #print_formatted_text('usr sending msg')
                    nonce, message = cfu.encrypt(client_key, data.encode('utf-8'))

                    #Ratchet the key
                    #print_formatted_text('ratcheting key')
                    client_key = cfu.ratchet(client_key, b'client')

                    #print_formatted_text(f'Sent server {message.hex()}')
                    await self.outbound.put({
                        'type': 'enc_msg',
                        'nonce': nonce.hex(),
                        'contents': message.hex(),
                    })

                
                elif msg_type == 'server' and data['type'] == 'enc_msg':
                    #If its a message send to user
                    #Decrypt Message
                    nonce = bytes.fromhex(data['nonce'])
                    contents = bytes.fromhex(data['contents'])

                    message = cfu.decrypt(server_key, nonce, contents).decode('utf-8')
                    server_key = cfu.ratchet(server_key, b'server')

                    await self.inbound_usr.put(message)
        except Exception as e:
            full_traceback = traceback.format_exc()
            await self.log_event(f"Unable to connect to server on, exception {full_traceback}")

    async def start_client(self, url, server_id, ed_private_key):
        cfu.empty_queue(self.inbound)
        cfu.empty_queue(self.inbound_usr)
        cfu.empty_queue(self.outbound)
        cfu.empty_queue(self.outbound_usr)
        cfu.empty_queue(self.encryption)

        self.server_id = server_id

        async with websockets.connect(url) as websocket:
            
            tasks = [
                asyncio.create_task(self.client_reciever(websocket)),
                asyncio.create_task(self.client_router(websocket)),
                asyncio.create_task(self.client_encryption(server_id, ed_private_key)),
            ]

            try:
                await asyncio.wait(
                    tasks, 
                    return_when=asyncio.FIRST_EXCEPTION
                )
            finally:
                self.stop_event.set()  # signal all tasks to stop
                for t in tasks:
                    t.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                await websocket.close()

    async def log_event(self, event: str):
        print_formatted_text(event)
        self.log.append(event)
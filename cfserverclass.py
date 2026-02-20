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

class Server:
    def __init__(self):
        self.clients = {}
        self.client_keys = {}
        self.client_counter = itertools.count()
        self.inbound = asyncio.Queue()
        self.outbound = asyncio.Queue()
        self.inbound_usr = asyncio.Queue()
        self.outbound_usr = asyncio.Queue()
        self.encryption = asyncio.Queue()
        self.log = []
        self.stop_event = asyncio.Event()
        self.STOP = object()

    async def log_event(self, event: str):
        print_formatted_text(event)
        self.log.append(event) 

    async def handler(self, websocket):
        client_id = next(self.client_counter)
        websocket.client_id = client_id
        self.clients[client_id] = websocket
        self.client_keys[client_id]= {'tunnel_established': False}
        await self.log_event(f"Client {client_id} connected!")

        try:
            async for message in websocket:
                await self.encryption.put(("client", client_id, json.loads(message)))
        except websockets.ConnectionClosed:
            pass
        finally:
            await self.log_event(f"Client {client_id} disconnected!")
            self.clients.pop(client_id, None)

    async def kick(self, client_id, reason):
        client_id = int(client_id)

        #await self.log_event(self.clients)
        try:
            websocket = self.clients.pop(client_id, None)
            self.client_keys.pop(client_id, None)
        except ValueError:
            await self.log_event(f"Client {client_id} not found!")
            return
        #await self.log_event(self.clients)

        if websocket:
            await self.log_event(f"Kicking client {client_id}: {reason}")
            try:
                await asyncio.wait_for(websocket.close(code=1008, reason=reason), timeout=1.0)  # 1008 = policy violation
            except Exception as e:
                await self.log_event(f"Error closing client {client_id}: {e}")
        else:
            await self.log_event(f"Client {client_id} not found??")

    async def server_router(self, stop_server):
        while not stop_server.is_set():
            client_id, data = await self.outbound.get() #Parse tuple of id and data
            if client_id == self.STOP:
                continue

            if not client_id in self.clients:
                await self.log_event(f"Client {client_id} does not exist")
                continue
            
            websocket = self.clients[client_id]
            if websocket is None:
                await self.log_event(f"Client {client_id} does not exist or has disconnected")
                continue
            
            try:
                await websocket.send(json.dumps(data))
            except websockets.ConnectionClosed:
                await self.log_event("Client Disconnected, Handler Disconnect")
                continue

    #unused
    #region            
    async def server_prompt(self, stop_server):
        while not stop_server.is_set():
            cmd = await self.session.prompt_async("S> ")

            if cmd == "exit":
                await self.log_event("Shutting down server")
                stop_server.set()
                await self.inbound.put((self.STOP, None))
                await self.outbound.put((self.STOP, None))
                await self.inbound_usr.put((self.STOP, None))
                await self.outbound_usr.put((self.STOP, None))
                await self.encryption.put((self.STOP, None, None))
                return
            
            if not self.clients: #check if empty
                await self.log_event(f"No client connected!")
                continue

            client_id = next(iter(self.clients.keys())) #first client_id in dictionary
            
            try:
                await self.encryption.put(("usr", client_id, cmd))
            except websockets.ConnectionClosed:
                await self.log_event("Client disconnected")

    async def server_display(self, stop_server):
        while not stop_server.is_set():
            client_id, data = await self.inbound_usr.get() #wait to recieve a message
            if client_id == self.STOP:
                continue
            print_formatted_text(f"[{client_id}] {data}")
    #endregion
    
    async def send(self, client_id, cmd):
        try:
            await self.encryption.put(("usr", client_id, cmd))
        except websockets.ConnectionClosed:
            await self.log_event("Client disconnected")

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

    async def server_encryption(self, stop_server: asyncio.Event, ed_private_key: Ed25519PrivateKey, account: dict):
        try:
            while not stop_server.is_set():
                #print_formatted_text('Awaiting messages')
                msg_type, client_id, data = await self.encryption.get()
                #print_formatted_text(f'{msg_type} {client_id} {data}')
                if msg_type == self.STOP:
                    continue

                if msg_type == "client" and data['type'] == 'pub_key':
                    my_private_key = X25519PrivateKey.generate()
                    my_public_key = my_private_key.public_key()
                    peer_public_key = X25519PublicKey.from_public_bytes(bytes.fromhex(data['contents']))

                    #print_formatted_text("sending public key")
                    await self.outbound.put((client_id, {
                        'type': 'pub_key',
                        'contents': my_public_key.public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw
                        ).hex()
                        }))
                    
                    #print_formatted_text("sent public key")
                    shared_secrect  = my_private_key.exchange(peer_public_key)

                    #identity verification
                    random = os.urandom(32)
                    challenge = (
                        my_public_key.public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw
                        ) + 
                        peer_public_key.public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw
                        ) +
                        random
                    )

                    await self.log_event(f"challenge i made (server+client+random) {challenge.hex()}")

                    signature = ed_private_key.sign(challenge)

                    await self.outbound.put((client_id, {
                        'type': 'signed',
                        'random': random.hex(),
                        'signature': signature.hex()
                        }))
                    
                    await self.log_event(f"Signature i made {signature.hex()}")
                    
                    #Wait until message with signature is recieved
                    while 1:
                        ed_msg_type, ed_client_id, ed_data = await self.encryption.get()
                        if ed_client_id == client_id and ed_data['type'] == 'signed':
                            break
                        await self.encryption.put((ed_msg_type, ed_client_id, ed_data))
                    
                    random = bytes.fromhex(ed_data['random'])
                    signature = bytes.fromhex(ed_data['signature'])

                    challenge = (
                        my_public_key.public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw
                        ) + 
                        peer_public_key.public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw
                        ) +
                        random
                    )

                    await self.log_event(f"challenge server made (server+client+random) {challenge.hex()}")
                    await self.log_event(f"Signature i recieved {signature.hex()}")

                    known_ids = cfu.load_identities(account)
                    matched_us = None
                    matched_key = None

                    if not known_ids:
                        await self.log_event("No registered IDs")
                    else:
                        for username, key in known_ids.items():
                            unpacked_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key))
                            try:
                                unpacked_key.verify(signature, challenge)
                                matched_us = username
                                matched_key = unpacked_key
                            except InvalidSignature:
                                pass
                    
                    if not matched_us:
                        #await self.log_event('No match found, kicking client...')
                        await self.kick(client_id, "Client provided an invalid signature")
                        del shared_secrect
                        continue
                    else:
                        await self.log_event(f'Client {client_id} identified as {matched_us}, type kick {client_id} if unexpected!')

                    #sets up server_key (sent by server), and client_key (sent by client)
                    #region
                    root_key = HKDF(
                        algorithm=hashes.SHA256(),
                        salt=None,
                        info=b'root',
                        length=32,
                    ).derive(shared_secrect)

                    self.client_keys[client_id]['server_key'] = HKDF(
                        algorithm=hashes.SHA256(),
                        salt=None,
                        info=b'server',
                        length=32,
                    ).derive(root_key)

                    self.client_keys[client_id]['client_key'] = HKDF(
                        algorithm=hashes.SHA256(),
                        salt=None,
                        info=b'client',
                        length=32,
                    ).derive(root_key)
                    
                    del root_key
                    #endregion

                    self.client_keys[client_id]['tunnel_established'] = True

                    #print_formatted_text(shared_secrect.hex())
                    del shared_secrect
                
                elif msg_type == 'usr' and self.client_keys[client_id]['tunnel_established']:
                    #print_formatted_text('usr sending msg')
                    server_key = self.client_keys[client_id]['server_key']
                    nonce, message = cfu.encrypt(server_key, data.encode('utf-8'))

                    #print_formatted_text('ratcheting key')
                    #Ratchet the key
                    self.client_keys[client_id]['server_key'] = cfu.ratchet(server_key, b'server')
                    del server_key

                    #print_formatted_text(f'Sent client {client_id} {message.hex()}')
                    await self.outbound.put((client_id,{
                        'type': 'enc_msg',
                        'nonce': nonce.hex(),
                        'contents': message.hex(),
                    }))
                
                elif msg_type == 'client' and data['type'] == 'enc_msg':
                    #If its a message send to user
                    #Decrypt Message
                    client_key = self.client_keys[client_id]['client_key']
                    nonce = bytes.fromhex(data['nonce'])
                    contents = bytes.fromhex(data['contents'])

                    #print_formatted_text(f'Recieved {contents} from client {client_id}')

                    message = cfu.decrypt(client_key, nonce, contents).decode('utf-8')
                    self.client_keys[client_id]['client_key'] = cfu.ratchet(client_key, b'client')
                    del client_key

                    await self.inbound_usr.put((client_id, message))

                else:
                    await self.log_event("Man idk watchu want :sob:")
        except Exception as e:
            full_traceback = traceback.format_exc()
            await self.log_event(f'Exception {full_traceback} in encryption')

    async def exit(self):
        self.stop_event.set()
        await self.inbound.put((self.STOP, None))
        await self.outbound.put((self.STOP, None))
        await self.inbound_usr.put((self.STOP, None))
        await self.outbound_usr.put((self.STOP, None))
        await self.encryption.put((self.STOP, None, None))
        return

    async def start_server(self, port, ed_private_key, account):
        cfu.empty_queue(self.inbound)
        cfu.empty_queue(self.inbound_usr)
        cfu.empty_queue(self.outbound)
        cfu.empty_queue(self.outbound_usr)
        cfu.empty_queue(self.encryption)

        async with websockets.serve(self.handler, "localhost", port):
            await self.log_event(f"Server running on ws://localhost:{port}")

            tasks = [
                asyncio.create_task(self.server_router(self.stop_event)),
                asyncio.create_task(self.server_encryption(self.stop_event, ed_private_key, account)),
            ]

            await self.stop_event.wait()

            for t in tasks:
                t.cancel()
            
            await asyncio.gather(*tasks, return_exceptions=True)
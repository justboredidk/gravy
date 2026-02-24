from PySide6.QtCore import Qt, QSize, Signal
from PySide6.QtWidgets import (QApplication, QLabel, QMainWindow, QPushButton, QVBoxLayout, QHBoxLayout, QWidget, QLineEdit, 
                               QTextBrowser,QStyle, QSizePolicy, QStackedWidget, QListWidget, QListWidgetItem, QComboBox,
                               QTabWidget)
from PySide6.QtGui import QColor, QPalette, QIcon
import PySide6.QtSvg

from tunnelmanager import Tunnel
import cfserverclass
import cfclientclass
import cfchatutils as cfu
import signal
from types import SimpleNamespace
import asyncio
import sys
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

class MainWindowTPL():
    LOGIN_PAGE = 0
    DASHBOARD_PAGE = 1
    MAKE_ACCOUNT_PAGE = 2
    CONNECT_SERVER_PAGE = 3
    CONFIGURE_SERVER_PAGE = 4

    def __init__(self):
        self.app: Application = None

class Application():

    def __init__(self):
        self.account = None
        self.user_data_key = None
        self.private_key = None
        self.public_key = None
        self.username = None
        self.base_dir = os.path.dirname(os.path.abspath(__file__))

class ClientSession(QWidget):
    finished = Signal(object)
    
    def __init__(self, app: Application, name="SERVER", parent=None):
        super().__init__(parent)
        self.client = None
        self.app = app
        self.server_name = name

        self.setMaximumWidth(600)

        self.main_layout = QVBoxLayout()
        self.main_layout.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.setLayout(self.main_layout)
        self.input_layout = QHBoxLayout()

        self.chat_display = QTextBrowser()
        self.chat_display.setReadOnly(True)

        self.input_box = QLineEdit(placeholderText="Message")
        self.input_box.returnPressed.connect(
            lambda: asyncio.create_task(self.send_message())
        )
        send_icon = QIcon(os.path.join(self.app.base_dir, "resources", "icons", "send.svg"))
        self.send_button = QPushButton("")
        self.send_button.setIcon(send_icon)
        self.send_button.setIconSize(QSize(24, 24))
        self.send_button.clicked.connect(
            lambda: asyncio.create_task(self.send_message())
        )

        self.input_layout.addWidget(self.input_box)
        self.input_layout.addWidget(self.send_button)

        self.close_button = QPushButton("Exit Session")
        self.close_button.clicked.connect(
            lambda: asyncio.create_task(self.client.exit())
            if self.client
            else None
        )

        self.main_layout.addWidget(self.chat_display)
        self.main_layout.addLayout(self.input_layout)
        self.main_layout.addWidget(self.close_button)
    
    async def start_client(self, url, server_id):
        self.client = cfclientclass.Client()

        try:
            client_task = asyncio.create_task(self.client.start_client(url, server_id, self.app.private_key))
            display_task = asyncio.create_task(self.client_display())

            await self.client.stop_event.wait()
        except Exception as e:
            print(f"Client exited with exception {e}")
        finally:
            display_task.cancel()
            await asyncio.gather(display_task, client_task, return_exceptions=True)

            self.cleanup()

    async def client_display(self):
        async for msg in self.client.recv_stream():
            if msg == self.client.STOP:
                break

            self.chat_display.append(f"[{self.server_name}] {msg}")

    async def send_message(self):
        text = self.input_box.text()
        self.input_box.clear()
        self.chat_display.append(f"[{self.app.username}] {text}")
        await self.client.send(text)

    def cleanup(self):
        self.finished.emit(self)

class ServerSession(QWidget):
    finished = Signal(object)

    def __init__(self, app: Application, parent=None):
        super().__init__(parent)
        self.app = app
        self.clients = {}

        self.main_layout = QVBoxLayout()
        self.setLayout(self.main_layout)
        self.main_layout.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.tab_widget = QTabWidget()

        self.main_layout.addWidget(self.tab_widget)
        self.server: cfserverclass.Server = None
        self.tunnel = None

    async def start_server(self, port, tunnel_type=Tunnel.disabled):
        self.server = cfserverclass.Server()
        self.tunnel = Tunnel()
        await self.tunnel.open_tunnel(tunnel_type, port, self.app.base_dir)

        print("Tunnel Opened")

        self.server_manager = ServerManager(self)
        self.tab_widget.addTab(self.server_manager, "Server Manager")

        try:
            server_task = asyncio.create_task(self.server.start_server(port, self.app.private_key, self.app.account.data["known_ids"]))
            client_manager_task = asyncio.create_task(self.client_manager())
            client_forwarder_task = asyncio.create_task(self.client_forwarder())

            await self.server.stop_event.wait()
        except Exception as e:
            print(f"Client manager exited with exception {e}")
        finally:
            server_task.cancel()
            client_manager_task.cancel()
            client_forwarder_task.cancel()
            await asyncio.gather(server_task, client_manager_task, client_forwarder_task, return_exceptions=True)

            await self.cleanup()
    
    async def client_manager(self):
        while not self.server.stop_event.is_set():
            mode, client_id, name = await self.server.join_queue.get()
            #print("Ui recieved client join")

            if mode == "join":
                try:
                    chat = ServerChat(self.app, self, client_id)
                except Exception as e:
                    print(f"Chat tab failed with {e}")
                #print("Created chat tab")
                self.clients[client_id] = chat
                self.tab_widget.addTab(chat, name)
                self.server_manager.reload_clients()
                #print("added chat tab")
            elif mode == "leave":
                self.tab_widget.removeTab(self.tab_widget.indexOf(self.clients[client_id]))
                self.clients[client_id].deleteLater()
                self.server_manager.reload_clients()


    async def client_forwarder(self):
        async for client_id, message in self.server.recv_stream():
            if message == self.server.STOP:
                break
            chat: ServerChat = self.clients[client_id]
            chat.display(message)
    
    async def kick_client(self, client_id):
        if client_id in self.server.clients.keys():
            await self.server.kick(client_id, "U SUCK BOZO")
            self.tab_widget.removeTab(self.tab_widget.indexOf(self.clients[client_id]))
            self.clients[client_id].deleteLater()
            self.server_manager.reload_clients()
        else:
            print(f"Print client {client_id} does not exist")

    async def shutdown(self):
        await self.server.exit()

    async def cleanup(self):
        await self.tunnel.close()
        self.finished.emit(self)
        
class ServerManager(QWidget):
    finished = Signal(object)

    def __init__(self, server_session: ServerSession, parent=None):
        super().__init__(parent)
        self.server_session = server_session

        self.setFixedWidth(400)
        self.main_layout = QVBoxLayout()
        self.setLayout(self.main_layout)
        self.main_layout.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        self.label = QLabel("Server Manager Beep Boop")
        self.url_label = QLabel(f"Tunnel URL: {self.server_session.tunnel.url}")
        self.url_label.setWordWrap(True)
        self.url_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        #on epstein :skull:
        self.client_list = QListWidget()
        self.kick_button = QPushButton("Kick Selected Client")
        self.kick_button.clicked.connect(
            lambda: asyncio.create_task(self.server_session.kick_client(
                int(self.client_list.currentItem().data(Qt.ItemDataRole.UserRole))
            ))
            if self.client_list.currentItem()
            else None
        )
        self.shutdown_button = QPushButton("Stop Server")
        self.shutdown_button.clicked.connect(lambda: asyncio.create_task(server_session.shutdown()))

        self.main_layout.addWidget(self.label)
        self.main_layout.addWidget(self.url_label)
        self.main_layout.addWidget(self.client_list)
        self.main_layout.addWidget(self.kick_button)
        self.main_layout.addWidget(self.shutdown_button)
    
    def reload_clients(self):
        #print("Reloading clients")
        self.client_list.setUpdatesEnabled(False)
        self.client_list.clear()
        for key in self.server_session.server.client_names:
            item = QListWidgetItem(f"{self.server_session.server.client_names[key]} ({key})")
            item.setData(Qt.ItemDataRole.UserRole, int(key))
            self.client_list.addItem(item)
        self.client_list.setUpdatesEnabled(True)
        #print("Reloaded clients")

class ServerChat(QWidget):
    finished = Signal(object)

    def __init__(self, app: Application, server_session: ServerSession, client_id, parent=None):
        super().__init__(parent)
        self.app = app
        self.server_session = server_session
        self.client_id = client_id
        self.client_name = self.server_session.server.client_names[client_id]

        self.setMaximumWidth(600)

        self.main_layout = QVBoxLayout()
        self.main_layout.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.setLayout(self.main_layout)
        self.input_layout = QHBoxLayout()

        self.chat_display = QTextBrowser()
        self.chat_display.setReadOnly(True)

        self.input_box = QLineEdit(placeholderText="Message")
        self.input_box.returnPressed.connect(
            lambda: asyncio.create_task(self.send_message())
        )
        send_icon = QIcon(os.path.join(self.app.base_dir, "resources", "icons", "send.svg"))
        self.send_button = QPushButton("")
        self.send_button.setIcon(send_icon)
        self.send_button.setIconSize(QSize(24, 24))
        self.send_button.clicked.connect(
            lambda: asyncio.create_task(self.send_message())
        )

        self.input_layout.addWidget(self.input_box)
        self.input_layout.addWidget(self.send_button)

        self.close_button = QPushButton("Kick Client")
        self.close_button.clicked.connect(
            lambda: asyncio.create_task(self.server_session.kick_client(self.client_id))
            if self.server_session.server
            else None
        )

        self.main_layout.addWidget(self.chat_display)
        self.main_layout.addLayout(self.input_layout)
        self.main_layout.addWidget(self.close_button)

    def display(self, msg):
        self.chat_display.append(f"[{self.client_name}] {msg}")

    async def send_message(self):
        text = self.input_box.text()
        self.input_box.clear()
        self.chat_display.append(f"[{self.app.username}] {text}")
        await self.server_session.server.send(self.client_id, text)

class LoginPage(QWidget):
        
    def __init__(self, parent):
        super().__init__(None)
        self.main_window = parent
        self.app: Application = parent.app

        #I think basically: Stacked widget needs to hold widget, widget needs ot have layout to hold other widget. Only widget can be center in layout. login ui widget contains layout. login_ui_layout contains input layout and button. AHHHH
        self.main_layout = QVBoxLayout(self)  #Layout to hold items within the page
        self.setLayout(self.main_layout)
        self.ui = QWidget()    #Widget to hold the login interface
        self.main_layout.addWidget(self.ui, alignment=Qt.AlignmentFlag.AlignCenter)
        self.ui.setMaximumHeight(100)
        self.ui.setFixedWidth(400)
        self.ui_layout = QVBoxLayout(self.ui)
        self.input_layout = QHBoxLayout()

        #Submission button
        self.submit_login = QPushButton()
        self.ok_icon = QIcon(os.path.join(self.app.base_dir, "resources", "icons", "login.svg"))
        self.submit_login.setIcon(self.ok_icon)
        self.submit_login.setIconSize(QSize(32, 32))
        self.submit_login.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        self.submit_login.clicked.connect(self.handle_login)

        #Username and Password entry
        self.login_text_layout = QVBoxLayout()
        self.username_box = QLineEdit(placeholderText="Username")
        self.password_box = QLineEdit(placeholderText="Password")
        self.username_box.returnPressed.connect(self.password_box.setFocus)
        self.password_box.returnPressed.connect(self.handle_login)
        self.password_box.setEchoMode(QLineEdit.EchoMode.Password)
        self.login_text_layout.addWidget(self.username_box)
        self.login_text_layout.addWidget(self.password_box)

        self.input_layout.addLayout(self.login_text_layout, stretch=5)
        self.input_layout.addWidget(self.submit_login, stretch=1)

        #Make account button:
        self.make_act_btn = QPushButton("Make Account")
        self.make_act_btn.clicked.connect(lambda: self.main_window.switch_page(MainWindowTPL.MAKE_ACCOUNT_PAGE))

        #Add elements to final layout   
        self.ui_layout.addLayout(self.input_layout)
        self.ui_layout.addWidget(self.make_act_btn)
    
    def handle_login(self):
        #print(self.login_page_obj.username_box.text())
        #print(self.login_page_obj.password_box.text())
        success, error = self.app.login(self.username_box.text(), self.password_box.text())
        if success:
            self.username_box.clear()
            self.password_box.clear()

            self.main_window.switch_page(MainWindowTPL.DASHBOARD_PAGE)
            #print("Login Successful!")
        else:
            self.password_box.clear()
            print(f"Login failed with error: {error}")
    
    def reset(self):
        self.username_box.clear()
        self.password_box.clear()

class DashboardPage(QWidget):

    def __init__(self, parent):
        super().__init__(None)
        self.main_window = parent
        self.app: Application = parent.app

        self.dash_layout = QVBoxLayout()
        self.setLayout(self.dash_layout)
        self.dash_widgets = QWidget()
        self.dash_layout.addWidget(self.dash_widgets)
        self.dash_widgets_layout = QVBoxLayout(self.dash_widgets)
        self.dash_lists_layout = QHBoxLayout()

        #Known Accounts List
        #Layouts
        self.ka_list_layout = QVBoxLayout()
        self.ka_buttons = QHBoxLayout()
        self.ka_text_input = QHBoxLayout()

        self.ka_username = QLineEdit(placeholderText="Username")
        self.ka_public_key = QLineEdit(placeholderText="Public Key")
        self.ka_text_input.addWidget(self.ka_username)
        self.ka_text_input.addWidget(self.ka_public_key)

        self.ka_add_btn = QPushButton("Add Contact")
        self.ka_remove_btn = QPushButton("Remove Contact")
        self.ka_add_btn.clicked.connect(self.add_contact)
        self.ka_remove_btn.clicked.connect(self.remove_contact)
        self.ka_buttons.addWidget(self.ka_add_btn)
        self.ka_buttons.addWidget(self.ka_remove_btn)

        self.ka_list = QListWidget()

        self.ka_list_layout.addWidget(self.ka_list)
        self.ka_list_layout.addLayout(self.ka_text_input)
        self.ka_list_layout.addLayout(self.ka_buttons)

        #Account Info
        self.account_information_list = QTextBrowser()
        self.account_information_list.setReadOnly(True)

        self.dash_lists_layout.addWidget(self.account_information_list)
        self.dash_lists_layout.addLayout(self.ka_list_layout)

        self.dash_widgets_layout.addLayout(self.dash_lists_layout)
        

        self.back_btn = QPushButton("Logout")
        self.back_btn.clicked.connect(self.handle_logout)
        self.dash_widgets_layout.addWidget(self.back_btn)
    
    def handle_logout(self):
        self.app.logout()
        self.main_window.switch_page(MainWindowTPL.LOGIN_PAGE)
        self.account_information_list.clear()
        print("Logged out!")

    def add_contact(self):
        success, error = self.app.add_contact(self.ka_username.text(), self.ka_public_key.text())
        if success:
            self.reload_contacts(self.ka_list)
            self.ka_username.clear()
            self.ka_public_key.clear()
        else:
            print(f"ID could not be added: {error}")
    
    def remove_contact(self):
        success, error = self.app.remove_contact(self.ka_username.text())
        if success:
            self.reload_contacts(self.ka_list)
            self.ka_username.clear()
            self.ka_public_key.clear()
        else:
            print(f"ID could not be removed: {error}")

    def reload_contacts(self, list: QListWidget):
        list.setUpdatesEnabled(False)
        list.clear()
        for key in self.app.account.data["known_ids"]:
            list.addItem(f"{key}: {self.app.account.data["known_ids"][key]}")
        list.setUpdatesEnabled(True)

    def reset(self):
        self.account_information_list.clear()
        self.account_information_list.append(f"Username: {self.app.username}")
        self.account_information_list.append(f"User Data Key: {self.app.user_data_key.hex()}")
        self.account_information_list.append(f"User Private Key: {self.app.private_key.private_bytes(encoding=serialization.Encoding.Raw, 
                                                                                                                                format=serialization.PrivateFormat.Raw, 
                                                                                                                                encryption_algorithm=serialization.NoEncryption()).hex()}")
        self.account_information_list.append(f"User Public Key: {self.app.public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()}")
        self.account_information_list.append(f"Base Directory: {self.app.base_dir}")
        self.ka_username.clear()
        self.ka_public_key.clear()
        self.reload_contacts(self.ka_list)

class MakeAccountPage(QWidget):

    def __init__(self, parent):
        super().__init__(None)
        self.main_window = parent
        self.app: Application = parent.app

        self.main_layout = QVBoxLayout()
        self.setLayout(self.main_layout)
        self.widgets = QWidget()
        self.widgets.setMaximumHeight(200)
        self.widgets.setFixedWidth(400)
        self.main_layout.addWidget(self.widgets, alignment=Qt.AlignmentFlag.AlignCenter)
        self.widgets_layout = QVBoxLayout(self.widgets)

        self.username_box = QLineEdit(placeholderText="Username")
        self.password_box = QLineEdit(placeholderText="Password")
        self.password_box_check = QLineEdit(placeholderText="Confirm Password")
        self.password_box.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_box_check.setEchoMode(QLineEdit.EchoMode.Password)

        self.submit_button = QPushButton("Create Account")
        self.submit_button.clicked.connect(self.handle_make_account)
        self.back_button = QPushButton("Back")
        self.back_button.clicked.connect(lambda: self.main_window.switch_page(MainWindowTPL.LOGIN_PAGE))

        self.password_feeback_label = QLabel("")

        self.widgets_layout.addWidget(self.username_box)
        self.widgets_layout.addWidget(self.password_box)
        self.widgets_layout.addWidget(self.password_box_check)
        self.widgets_layout.addWidget(self.submit_button)
        self.widgets_layout.addWidget(self.back_button)
        self.widgets_layout.addWidget(self.password_feeback_label)

    def handle_make_account(self):
        if not self.password_box.text() == self.password_box_check.text():
            self.password_box.clear()
            self.password_box_check.clear()
            self.password_feeback_label.setText("Passwords do not match!")
            self.password_feeback_label.setStyleSheet("color: red;")
            print(f"Passwords do not match")
            return False
        else:
            success, error = self.app.make_account(self.username_box.text(), self.password_box.text())
            
        if success:
            self.username_box.clear()
            self.password_box.clear()
            self.password_box_check.clear()
            self.password_feeback_label.setText("Passwords matched!")
            self.password_feeback_label.setStyleSheet("color: green;")

            self.main_window.switch_page(MainWindowTPL.LOGIN_PAGE)
            return True
        else:
            print(f"Account creation failed with error {error}")
    
    def reset(self):
        self.username_box.clear()
        self.password_box.clear()
        self.password_box_check.clear()
        self.password_feeback_label.setText("")

class ConnectServerPage(QWidget):

    def __init__(self, parent):
        super().__init__(None)

        self.main_window = parent
        self.app = parent.app

        self.main_layout = QVBoxLayout()
        self.setLayout(self.main_layout)
        self.ui = QWidget()
        self.ui.setFixedWidth(400)
        self.ui.setMaximumHeight(600)
        self.main_layout.addWidget(self.ui, alignment=Qt.AlignmentFlag.AlignHCenter)
        self.ui_layout = QVBoxLayout(self.ui)
        
        self.url_box = QLineEdit(placeholderText="ws://localhost:8080")
        self.name_box = QLineEdit(placeholderText="Server Name")
        self.id_box = QLineEdit(placeholderText="Server Public Key")
        self.id_list = QListWidget()
        #Makes it so when you click a user in the list it automatically sets the expected id to their key
        self.id_list.itemClicked.connect(
            lambda item: (
                self.id_box.setText(item.text().split(": ")[1]),
                self.name_box.setText(item.text().split(": ")[0])
            )
        )
        self.connect_btn = QPushButton("Connect to Server")
        self.connect_btn.clicked.connect(self.connect_to_server)

        self.ui_layout.addWidget(self.url_box)
        self.ui_layout.addWidget(self.name_box)
        self.ui_layout.addWidget(self.id_box)
        self.ui_layout.addWidget(self.id_list)
        self.ui_layout.addWidget(self.connect_btn)

    def connect_to_server(self):
        client_session = ClientSession(self.app, self.name_box.text())

        item = QListWidgetItem(self.name_box.text())
        item.setData(Qt.ItemDataRole.UserRole, client_session)

        self.main_window.sidebar_list.addItem(item)

        asyncio.create_task(client_session.start_client(
            self.url_box.text(),
            self.id_box.text()
        ))

        self.main_window.pages.addWidget(client_session)
        self.main_window.pages.setCurrentWidget(client_session)
        client_session.finished.connect(lambda: self.cleanup_client_session(client_session))
        
    def cleanup_client_session(self, session: ClientSession):
        for i in range(self.main_window.sidebar_list.count()):
            item = self.main_window.sidebar_list.item(i)
            if item.data(Qt.ItemDataRole.UserRole) == session:
                self.main_window.sidebar_list.takeItem(i)
        
        self.main_window.pages.removeWidget(session)
        session.deleteLater()
        self.main_window.switch_page(MainWindowTPL.DASHBOARD_PAGE)

    def reload_contacts(self, list: QListWidget):
        list.setUpdatesEnabled(False)
        list.clear()
        for key in self.app.account.data["known_ids"]:
            list.addItem(f"{key}: {self.app.account.data["known_ids"][key]}")
        list.setUpdatesEnabled(True)

    def reset(self):
        self.url_box.clear()
        self.name_box.clear()
        self.id_box.clear()
        self.reload_contacts(self.id_list)

class ConfigureServerPage(QWidget):

    def __init__(self, parent):
        super().__init__(None)

        self.main_window = parent
        self.app = parent.app

        self.main_layout = QVBoxLayout()
        self.setLayout(self.main_layout)
        self.ui = QWidget()
        self.ui.setFixedWidth(400)
        self.ui.setMaximumHeight(100)
        self.ui_layout = QVBoxLayout(self.ui)
        self.main_layout.addWidget(self.ui, alignment=Qt.AlignmentFlag.AlignHCenter)

        self.port_box = QLineEdit(placeholderText="Port")
        self.tunnel_selector = QComboBox()
        self.tunnel_selector.addItem("No Tunnel", userData=Tunnel.disabled)
        self.tunnel_selector.addItem("Cloudflare", userData=Tunnel.cloudflare)
        #self.tunnel_selector.addItem("Ngrok", userData=Tunnel.ngrok)

        self.start_button = QPushButton("Start Server")
        self.start_button.clicked.connect(self.start_server)

        self.ui_layout.addWidget(self.port_box)
        self.ui_layout.addWidget(self.tunnel_selector)
        self.ui_layout.addWidget(self.start_button)
        self.ui_layout.addStretch()
    
    def start_server(self):
        print(f"server started on port {self.port_box.text()} with tunnel {self.tunnel_selector.currentData()}")

        self.main_window.server_session = ServerSession(self.app)
        asyncio.create_task(self.main_window.server_session.start_server(
            int(self.port_box.text()), 
            self.tunnel_selector.currentData()
        ))
        self.main_window.pages.addWidget(self.main_window.server_session)
        self.main_window.pages.setCurrentWidget(self.main_window.server_session)

        self.main_window.server_session.finished.connect(self.cleanup_server_session)

    def cleanup_server_session(self):
        self.main_window.pages.removeWidget(self.main_window.server_session)
        self.main_window.server_session.deleteLater()

        self.port_box.clear()
        self.tunnel_selector.setCurrentIndex(0)
        self.main_window.pages.setCurrentIndex(MainWindowTPL.CONFIGURE_SERVER_PAGE)

    def reset(self):
        self.port_box.clear()
        self.tunnel_selector.setCurrentIndex(0)
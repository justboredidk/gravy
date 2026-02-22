from PySide6.QtCore import Qt, QSize
from PySide6.QtWidgets import QApplication, QLabel, QMainWindow, QPushButton, QVBoxLayout, QHBoxLayout, QWidget, QLineEdit, QTextBrowser, QStyle, QSizePolicy, QStackedWidget, QListWidget, QListWidgetItem
from PySide6.QtGui import QColor, QPalette, QIcon
from PySide6 import QtSvg

#import PySide6.QtAsyncio as QtAsyncio
import asyncio
from qasync import QEventLoop

from types import SimpleNamespace
import asyncio
import sys
import os
from jblob import JBlob
import cfchatutils as cfu
import cfserverclass
import cfclientclass
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
import json

#TO_DO
#Finish dashboard and account managed features (proxy, histories, etc)
#Make chat functional
#Add multiclient, multiserver
#Intgrate proxy
#Add Chat history
#Refactor client and server to allow for transmission of files, images, update encryption protocol to be more flexible and tolerant of delays.

class ServerSession():
    
    def __init__(self):
        pass

class Application():

    def __init__(self):
        self.account = None
        self.user_data_key = None
        self.private_key = None
        self.public_key = None
        self.username = None
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
    
    def login(self, username, password):
        path = os.path.join(self.base_dir, f"{username}.act")
        self.account = JBlob(path)

        if self.account.load():
            pass
        else:
            return False, "account_not_found"
        
        print(cfu.check_password(password, self.account))
        
        if cfu.check_password(password, self.account):
            self.username = self.account.opt_data['username']
            salt = bytes.fromhex(self.account.opt_data['salt'])
            self.user_data_key = cfu.derive_key(password, salt)

            self.account.decrypt(self.user_data_key)

            #print(f"Priv: {decrypted_blob['priv_bytes']}, Pub: {decrypted_blob['pub_bytes']}")
            self.private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(self.account.data['priv_bytes']))
            self.public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.account.data['pub_bytes']))

            test_sig = self.private_key.sign(b'test')
            try:
                self.public_key.verify(test_sig, b'test')
                return True, None
            except InvalidSignature:
                return False, "keys_did_not_match"
        else:
            return False, "incorrect_password"
    
    def logout(self):
        self.account = None
        self.user_data_key = None
        self.private_key = None
        self.public_key = None
        self.username = None
    
    def make_account(self, username, password):
        path = os.path.join(self.base_dir, f"{username}.act")
        salt = os.urandom(16)
        key = cfu.derive_key(password, salt)
        #decrypted_check = decrypt(key, encrypted_check["nonce"], encrypted_check["ciphertext"])
        #account.data is encrypted, account.opt_data is not encrypted, so it is used to store the salt and othername

        account = JBlob()
        account.opt_data = {
            "salt": salt.hex(),
            "username": username,
        }

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        account.data = {
            "priv_bytes": private_key.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption()).hex(),
            "pub_bytes": public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex(),
            "known_ids": {},
        }

        account.encrypt(key)
        success = account.save(path)
        return success, "File Could Not Save"
    
    def add_contact(self, name, id):
        self.account.data["known_ids"][name] = id
        self.account.encrypt(self.user_data_key)
        return self.account.save(), "File Couldn't Save"   
    
    def remove_contact(self, name):
        try:
            self.account.data["known_ids"].pop(name)
        except:
            return False, f"Name {name} not found"
        self.account.encrypt(self.user_data_key)
        return self.account.save(), "File Couldn't Save"

class ClientSession(QWidget):
    
    def __init__(self, app: Application, name="SERVER", parent=None):
        super().__init__(parent)
        self.app = app
        self.server_name = name

        self.setMaximumWidth(600)

        self.main_layout = QVBoxLayout()
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
        self.send_button.setIconSize(QSize(32, 32))
        self.send_button.clicked.connect(
            lambda: asyncio.create_task(self.send_message())
        )

        self.input_layout.addWidget(self.input_box)
        self.input_layout.addWidget(self.send_button)

        self.main_layout.addWidget(self.chat_display)
        self.main_layout.addLayout(self.input_layout)
    
    async def start_client(self, url, server_id):
        self.client = cfclientclass.Client()

        client_task = asyncio.create_task(self.client.start_client(url, server_id, self.app.private_key))
        display_task = asyncio.create_task(self.client_display())

        await self.client.stop_event.wait()

        display_task.cancel()
        await asyncio.gather(display_task, client_task, return_exceptions=True)

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

class MainWindow(QMainWindow):

    def __init__(self, app: Application):
        super().__init__()  #Calls parent class constructor

        self.app = app

        widget = QWidget()  #Container Widget to hold other stuff
        self.setCentralWidget(widget)   #Widget expands to fill window

        layout = QHBoxLayout(widget)    #Stack Widgets vertically

        palette = self.palette()
        base_color = palette.color(QPalette.ColorRole.Window)
        darker_color = base_color.darker(110)

        #Sidebar
        #region
        sidebar = QWidget()
        sidebar.setMaximumWidth(250)
        sidebar.setAutoFillBackground(True)
        palette = sidebar.palette()
        palette.setColor(QPalette.ColorRole.Window, darker_color)
        sidebar.setPalette(palette)
        sidebar_layout = QVBoxLayout(sidebar)

        dashboard_btn_icon = QIcon(os.path.join(self.app.base_dir, "resources", "icons", "dashboard.svg"))
        self.dashboard_btn = QPushButton("Dashboard")
        self.dashboard_btn.setIcon(dashboard_btn_icon)
        self.dashboard_btn.setIconSize(QSize(24, 24))
        self.dashboard_btn.clicked.connect(lambda: self.switch_page(self.DASHBOARD_PAGE) if self.app.username else None)

        connect_server_btn_icon = QIcon(os.path.join(self.app.base_dir, "resources", "icons", "connect_server.svg"))
        self.connect_server_btn = QPushButton("Connect")
        self.connect_server_btn.setIcon(connect_server_btn_icon)
        self.connect_server_btn.setIconSize(QSize(24, 24))
        self.connect_server_btn.clicked.connect(lambda: self.switch_page(self.CONNECT_SERVER_PAGE) if self.app.username else None)

        self.sidebar_list = QListWidget()
        self.sidebar_list.itemClicked.connect(
            lambda item: self.pages.setCurrentWidget(
                item.data(Qt.ItemDataRole.UserRole)
            )
        )

        sidebar_layout.addWidget(self.dashboard_btn)
        sidebar_layout.addWidget(self.connect_server_btn)
        sidebar_layout.addWidget(self.sidebar_list)
        sidebar_layout.addStretch()

        layout.addWidget(sidebar, stretch=1)



        #endregion

        #UI Pages
        self.pages = QStackedWidget()
        layout.addWidget(self.pages, stretch=5)

        #setCurrentIndex() Constants
        self.LOGIN_PAGE = 0
        self.DASHBOARD_PAGE = 1
        self.MAKE_ACCOUNT_PAGE = 2
        self.CONNECT_SERVER_PAGE = 3

        #Reference Object to organize self variables to be accessible by functions
        self.login_page_obj = SimpleNamespace()
        self.dashboard_page_obj = SimpleNamespace()
        self.make_account_page_obj = SimpleNamespace()
        self.connect_server_page_obj = SimpleNamespace()

        #Login Page (0)
        #region

        #GENIUNELY WTF is this stupid ass code I can't even ts is so dumb
        #I think basically: Stacked widget needs to hold widget, widget needs ot have layout to hold other widget. Only widget can be center in layout. login ui widget contains layout. login_ui_layout contains input layout and button. AHHHH
        self.login_page_obj.login_page = QWidget()  #Page Container
        self.login_page_obj.login_layout = QVBoxLayout(self.login_page_obj.login_page)  #Layout to hold items within the page
        self.login_page_obj.login_ui = QWidget()    #Widget to hold the login interface
        self.login_page_obj.login_layout.addWidget(self.login_page_obj.login_ui, alignment=Qt.AlignmentFlag.AlignCenter)
        self.login_page_obj.login_ui.setMaximumHeight(100)
        self.login_page_obj.login_ui.setFixedWidth(400)
        self.login_page_obj.login_ui_layout = QVBoxLayout(self.login_page_obj.login_ui)
        self.login_page_obj.login_input_layout = QHBoxLayout()

        #Submission button
        self.login_page_obj.submit_login = QPushButton()
        self.login_page_obj.ok_icon = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_DialogOkButton)
        self.login_page_obj.submit_login.setIcon(self.login_page_obj.ok_icon)
        self.login_page_obj.submit_login.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        self.login_page_obj.submit_login.clicked.connect(self.handle_login)

        #Username and Password entry
        self.login_page_obj.login_text_layout = QVBoxLayout()
        self.login_page_obj.username_box = QLineEdit(placeholderText="Username")
        self.login_page_obj.password_box = QLineEdit(placeholderText="Password")
        self.login_page_obj.password_box.setEchoMode(QLineEdit.EchoMode.Password)
        self.login_page_obj.login_text_layout.addWidget(self.login_page_obj.username_box)
        self.login_page_obj.login_text_layout.addWidget(self.login_page_obj.password_box)

        self.login_page_obj.login_input_layout.addLayout(self.login_page_obj.login_text_layout, stretch=5)
        self.login_page_obj.login_input_layout.addWidget(self.login_page_obj.submit_login, stretch=1)

        #Make account button:
        self.login_page_obj.make_act_btn = QPushButton("Make Account")
        self.login_page_obj.make_act_btn.clicked.connect(lambda: self.switch_page(self.MAKE_ACCOUNT_PAGE))

        #Add elements to final layout   
        self.login_page_obj.login_ui_layout.addLayout(self.login_page_obj.login_input_layout)
        self.login_page_obj.login_ui_layout.addWidget(self.login_page_obj.make_act_btn)


        #endregion

        #Dashboard Page (1)
        #region

        self.dashboard_page_obj.dashboard_page = QWidget()
        self.dashboard_page_obj.dash_layout = QVBoxLayout(self.dashboard_page_obj.dashboard_page)
        self.dashboard_page_obj.dash_widgets = QWidget()
        self.dashboard_page_obj.dash_layout.addWidget(self.dashboard_page_obj.dash_widgets)
        self.dashboard_page_obj.dash_widgets_layout = QVBoxLayout(self.dashboard_page_obj.dash_widgets)
        self.dashboard_page_obj.dash_lists_layout = QHBoxLayout()

        #Known Accounts List
        #Layouts
        self.dashboard_page_obj.ka_list_layout = QVBoxLayout()
        self.dashboard_page_obj.ka_buttons = QHBoxLayout()
        self.dashboard_page_obj.ka_text_input = QHBoxLayout()

        self.dashboard_page_obj.ka_username = QLineEdit(placeholderText="Username")
        self.dashboard_page_obj.ka_public_key = QLineEdit(placeholderText="Public Key")
        self.dashboard_page_obj.ka_text_input.addWidget(self.dashboard_page_obj.ka_username)
        self.dashboard_page_obj.ka_text_input.addWidget(self.dashboard_page_obj.ka_public_key)

        self.dashboard_page_obj.ka_add_btn = QPushButton("Add Contact")
        self.dashboard_page_obj.ka_remove_btn = QPushButton("Remove Contact")
        self.dashboard_page_obj.ka_add_btn.clicked.connect(self.add_contact)
        self.dashboard_page_obj.ka_remove_btn.clicked.connect(self.remove_contact)
        self.dashboard_page_obj.ka_buttons.addWidget(self.dashboard_page_obj.ka_add_btn)
        self.dashboard_page_obj.ka_buttons.addWidget(self.dashboard_page_obj.ka_remove_btn)

        self.dashboard_page_obj.ka_list = QListWidget()

        self.dashboard_page_obj.ka_list_layout.addWidget(self.dashboard_page_obj.ka_list)
        self.dashboard_page_obj.ka_list_layout.addLayout(self.dashboard_page_obj.ka_text_input)
        self.dashboard_page_obj.ka_list_layout.addLayout(self.dashboard_page_obj.ka_buttons)

        #Account Info
        self.dashboard_page_obj.account_information_list = QTextBrowser()
        self.dashboard_page_obj.account_information_list.setReadOnly(True)

        self.dashboard_page_obj.dash_lists_layout.addWidget(self.dashboard_page_obj.account_information_list)
        self.dashboard_page_obj.dash_lists_layout.addLayout(self.dashboard_page_obj.ka_list_layout)

        self.dashboard_page_obj.dash_widgets_layout.addLayout(self.dashboard_page_obj.dash_lists_layout)
        

        self.dashboard_page_obj.back_btn = QPushButton("Logout")
        self.dashboard_page_obj.back_btn.clicked.connect(self.handle_logout)
        self.dashboard_page_obj.dash_widgets_layout.addWidget(self.dashboard_page_obj.back_btn)

        #endregion

        #Make Account Page (2)
        #region
        self.make_account_page_obj.make_act_page = QWidget()
        self.make_account_page_obj.make_act_layout = QVBoxLayout(self.make_account_page_obj.make_act_page)
        self.make_account_page_obj.make_act_widgets = QWidget()
        self.make_account_page_obj.make_act_widgets.setMaximumHeight(200)
        self.make_account_page_obj.make_act_widgets.setFixedWidth(400)
        self.make_account_page_obj.make_act_layout.addWidget(self.make_account_page_obj.make_act_widgets, alignment=Qt.AlignmentFlag.AlignCenter)
        self.make_account_page_obj.make_act_widgets_layout = QVBoxLayout(self.make_account_page_obj.make_act_widgets)

        self.make_account_page_obj.username_box = QLineEdit(placeholderText="Username")
        self.make_account_page_obj.password_box = QLineEdit(placeholderText="Password")
        self.make_account_page_obj.password_box_check = QLineEdit(placeholderText="Confirm Password")
        self.make_account_page_obj.password_box.setEchoMode(QLineEdit.EchoMode.Password)
        self.make_account_page_obj.password_box_check.setEchoMode(QLineEdit.EchoMode.Password)

        self.make_account_page_obj.submit_button = QPushButton("Create Account")
        self.make_account_page_obj.submit_button.clicked.connect(self.handle_make_account)
        self.make_account_page_obj.back_button = QPushButton("Back")
        self.make_account_page_obj.back_button.clicked.connect(lambda: self.switch_page(self.LOGIN_PAGE))

        self.make_account_page_obj.password_feeback_label = QLabel("")

        self.make_account_page_obj.make_act_widgets_layout.addWidget(self.make_account_page_obj.username_box)
        self.make_account_page_obj.make_act_widgets_layout.addWidget(self.make_account_page_obj.password_box)
        self.make_account_page_obj.make_act_widgets_layout.addWidget(self.make_account_page_obj.password_box_check)
        self.make_account_page_obj.make_act_widgets_layout.addWidget(self.make_account_page_obj.submit_button)
        self.make_account_page_obj.make_act_widgets_layout.addWidget(self.make_account_page_obj.back_button)
        self.make_account_page_obj.make_act_widgets_layout.addWidget(self.make_account_page_obj.password_feeback_label)

        #endregion
        
        #Connect to Server Page (3)
        #region
        self.connect_server_page_obj.page = QWidget()
        self.connect_server_page_obj.layout = QVBoxLayout(self.connect_server_page_obj.page)
        self.connect_server_page_obj.ui = QWidget()
        self.connect_server_page_obj.ui.setFixedWidth(400)
        self.connect_server_page_obj.ui.setMaximumHeight(600)
        self.connect_server_page_obj.layout.addWidget(self.connect_server_page_obj.ui)
        self.connect_server_page_obj.ui_layout = QVBoxLayout(self.connect_server_page_obj.ui)
        
        self.connect_server_page_obj.url_box = QLineEdit(placeholderText="ws://localhost:8080")
        self.connect_server_page_obj.name_box = QLineEdit(placeholderText="Server Name")
        self.connect_server_page_obj.id_box = QLineEdit(placeholderText="Server Public Key")
        self.connect_server_page_obj.id_list = QListWidget()
        #Makes it so when you click a user in the list it automatically sets the expected id to their key
        self.connect_server_page_obj.id_list.itemClicked.connect(
            lambda item: self.connect_server_page_obj.id_box.setText(
                item.text().split(": ")[1]))
        self.connect_server_page_obj.connect_btn = QPushButton("Connect to Server")
        self.connect_server_page_obj.connect_btn.clicked.connect(self.connect_to_server)

        self.connect_server_page_obj.ui_layout.addWidget(self.connect_server_page_obj.url_box)
        self.connect_server_page_obj.ui_layout.addWidget(self.connect_server_page_obj.name_box)
        self.connect_server_page_obj.ui_layout.addWidget(self.connect_server_page_obj.id_box)
        self.connect_server_page_obj.ui_layout.addWidget(self.connect_server_page_obj.id_list)
        self.connect_server_page_obj.ui_layout.addWidget(self.connect_server_page_obj.connect_btn)
        #self.connect_server_page_obj.
        #endregion

        #Add pages to stack
        self.pages.addWidget(self.login_page_obj.login_page)
        self.pages.addWidget(self.dashboard_page_obj.dashboard_page)
        self.pages.addWidget(self.make_account_page_obj.make_act_page)
        self.pages.addWidget(self.connect_server_page_obj.page)

    def handle_login(self):
        #print(self.login_page_obj.username_box.text())
        #print(self.login_page_obj.password_box.text())
        success, error = self.app.login(self.login_page_obj.username_box.text(), self.login_page_obj.password_box.text())
        if success:
            self.login_page_obj.username_box.clear()
            self.login_page_obj.password_box.clear()

            self.switch_page(self.DASHBOARD_PAGE)
            print("Login Succesful!")
        else:
            self.login_page_obj.password_box.clear()
            print(f"Login failed with error: {error}")
    
    def handle_logout(self):
        self.app.logout()
        self.switch_page(self.LOGIN_PAGE)
        self.dashboard_page_obj.account_information_list.clear()
        print("Logged out!")
    
    def handle_make_account(self):
        if not self.make_account_page_obj.password_box.text() == self.make_account_page_obj.password_box_check.text():
            self.make_account_page_obj.password_box.clear()
            self.make_account_page_obj.password_box_check.clear()
            self.make_account_page_obj.password_feeback_label.setText("Passwords do not match!")
            self.make_account_page_obj.password_feeback_label.setStyleSheet("color: red;")
            print(f"Passwords do not match")
            return False
        else:
            success, error = self.app.make_account(self.make_account_page_obj.username_box.text(), self.make_account_page_obj.password_box.text())
            
        if success:
            self.make_account_page_obj.username_box.clear()
            self.make_account_page_obj.password_box.clear()
            self.make_account_page_obj.password_box_check.clear()
            self.make_account_page_obj.password_feeback_label.setText("Passwords matched!")
            self.make_account_page_obj.password_feeback_label.setStyleSheet("color: green;")

            self.switch_page(self.LOGIN_PAGE)
            return True
        else:
            print(f"Account creation failed with error {error}")
    
    def send_message(self):
        #Does the server actually exist?
        if self.app.server:
            #send_message
            pass
        else:
            return False, "No Server Exists"
    
    def add_contact(self):
        success, error = self.app.add_contact(self.dashboard_page_obj.ka_username.text(), self.dashboard_page_obj.ka_public_key.text())
        if success:
            self.reload_contacts(self.dashboard_page_obj.ka_list)
            self.dashboard_page_obj.ka_username.clear()
            self.dashboard_page_obj.ka_public_key.clear()
        else:
            print(f"ID could not be added: {error}")
    
    def remove_contact(self):
        success, error = self.app.remove_contact(self.dashboard_page_obj.ka_username.text())
        if success:
            self.reload_contacts(self.dashboard_page_obj.ka_list)
            self.dashboard_page_obj.ka_username.clear()
            self.dashboard_page_obj.ka_public_key.clear()
        else:
            print(f"ID could not be removed: {error}")
    
    def reload_contacts(self, list: QListWidget):
        list.setUpdatesEnabled(False)
        list.clear()
        for key in self.app.account.data["known_ids"]:
            list.addItem(f"{key}: {self.app.account.data["known_ids"][key]}")
        list.setUpdatesEnabled(True)

    def switch_page(self, index, type="static"):
        #This function sets up the page ui and then switches to it
        #Any type of page you add must be in here
        if index == self.LOGIN_PAGE:
            self.login_page_obj.username_box.clear()
            self.login_page_obj.password_box.clear()
            self.pages.setCurrentIndex(index)
        if index == self.MAKE_ACCOUNT_PAGE:
            self.make_account_page_obj.username_box.clear()
            self.make_account_page_obj.password_box.clear()
            self.make_account_page_obj.password_box_check.clear()
            self.make_account_page_obj.password_feeback_label.setText("")
            self.pages.setCurrentIndex(index)
        if index == self.DASHBOARD_PAGE:
            self.dashboard_page_obj.account_information_list.clear()
            self.dashboard_page_obj.account_information_list.append(f"Username: {self.app.username}")
            self.dashboard_page_obj.account_information_list.append(f"User Data Key: {self.app.user_data_key.hex()}")
            self.dashboard_page_obj.account_information_list.append(f"User Private Key: {self.app.private_key.private_bytes(encoding=serialization.Encoding.Raw, 
                                                                                                                                    format=serialization.PrivateFormat.Raw, 
                                                                                                                                    encryption_algorithm=serialization.NoEncryption()).hex()}")
            self.dashboard_page_obj.account_information_list.append(f"User Public Key: {self.app.public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()}")
            self.dashboard_page_obj.account_information_list.append(f"Base Directory: {self.app.base_dir}")
            self.dashboard_page_obj.ka_username.clear()
            self.dashboard_page_obj.ka_public_key.clear()
            self.reload_contacts(self.dashboard_page_obj.ka_list)
            self.pages.setCurrentIndex(index)
        if index == self.CONNECT_SERVER_PAGE:
            self.connect_server_page_obj.url_box.clear()
            self.connect_server_page_obj.id_box.clear()
            self.reload_contacts(self.connect_server_page_obj.id_list)
            self.pages.setCurrentIndex(index)

    def connect_to_server(self):
        client_session = ClientSession(self.app, self.connect_server_page_obj.name_box.text())
        self.pages.addWidget(client_session)

        item = QListWidgetItem(self.connect_server_page_obj.name_box.text())
        item.setData(Qt.ItemDataRole.UserRole, client_session)

        self.sidebar_list.addItem(item)

        asyncio.create_task(client_session.start_client(
            self.connect_server_page_obj.url_box.text(),
            self.connect_server_page_obj.id_box.text()
        ))

        self.pages.setCurrentWidget(client_session)
        

    def nothing(self):
        pass



if __name__ == "__main__":
    app = QApplication(sys.argv)
    backend = Application()
    main_window = MainWindow(backend)
    main_window.setWindowTitle("Encrypted Chat")
    main_window.resize(600, 400)
    main_window.show()

    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)

    with loop:
        loop.run_forever()
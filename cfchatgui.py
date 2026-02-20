from PySide6.QtCore import Qt, QSize
from PySide6.QtWidgets import QApplication, QLabel, QMainWindow, QPushButton, QVBoxLayout, QHBoxLayout, QWidget, QLineEdit, QTextBrowser, QStyle, QSizePolicy, QStackedWidget, QListWidget, QListWidgetItem
from PySide6.QtGui import QColor, QPalette, QIcon
from PySide6 import QtSvg

import PySide6.QtAsyncio as QtAsyncio

from types import SimpleNamespace
import asyncio
import sys
import os
import jblob
import cfchatutils as cfu
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
import json

class ClientSession():
    
    def __init__(self):
        pass

class ServerSession():
    
    def __init__(self):
        pass

class Application():

    def __init__(self):
        self.account_data = None
        self.user_data_key = None
        self.private_key = None
        self.public_key = None
        self.username = None
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
    
    def login(self, username, password):
        path = os.path.join(self.base_dir, f"{username}.act")
        print(path)
        try:
            with open(path, 'r') as f:
                self.account_data = json.load(f)
        except:
            return False, "account_not_found"
        
        if cfu.check_password(password, self.account_data):
            self.username = self.account_data['username']
            salt = bytes.fromhex(self.account_data['salt'])
            self.user_data_key = cfu.derive_key(password, salt)
            nonce = bytes.fromhex(self.account_data['blob'][0])
            ciphertext = bytes.fromhex(self.account_data['blob'][1])

            decrypted_blob_bytes = cfu.decrypt(self.user_data_key, nonce, ciphertext)
            decrypted_blob = json.loads(decrypted_blob_bytes.decode('utf-8'))

            #print(f"Priv: {decrypted_blob['priv_bytes']}, Pub: {decrypted_blob['pub_bytes']}")
            self.private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(decrypted_blob['priv_bytes']))
            self.public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(decrypted_blob['pub_bytes']))

            test_sig = self.private_key.sign(b'test')
            try:
                self.public_key.verify(test_sig, b'test')
                return True, None
            except InvalidSignature:
                return False, "keys_did_not_match"
        else:
            return False, "incorrect_password"
    
    def logout(self):
        self.account_data = None
        self.user_data_key = None
        self.private_key = None
        self.public_key = None
        self.username = None
    
    def make_account(self, username, password):
        check = os.urandom(32)
        salt = os.urandom(16)

        key = cfu.derive_key(password, salt)

        nonce, encrypted_check = cfu.encrypt(key, check)
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
        blob_nonce, blob_data = cfu.encrypt(key, blob_bytes)

        account['blob'] = (blob_nonce.hex(), blob_data.hex())

        try:
            print("Saving Account Information")
            path = os.path.join(self.base_dir, f"{username}.act")
            print(path)
            with open(path, 'w') as f:
                json.dump(account, f)
            return True, "account_created"
        except:
            return False, "file_write_failed"

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
        self.dashboard_btn.clicked.connect(lambda: self.pages.setCurrentIndex(self.DASHBOARD_PAGE) if self.app.username else None)
        sidebar_layout.addWidget(self.dashboard_btn)
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

        #Reference Object to organize self variables to be accessible by functions
        self.login_page_obj = SimpleNamespace()
        self.dashboard_page_obj = SimpleNamespace()
        self.make_account_page_obj = SimpleNamespace()

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
        self.login_page_obj.make_act_btn.clicked.connect(lambda: self.pages.setCurrentIndex(self.MAKE_ACCOUNT_PAGE))

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
        self.dashboard_page_obj.ka_private_key = QLineEdit(placeholderText="Private Key")
        self.dashboard_page_obj.ka_text_input.addWidget(self.dashboard_page_obj.ka_username)
        self.dashboard_page_obj.ka_text_input.addWidget(self.dashboard_page_obj.ka_private_key)

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
        self.dashboard_page_obj.account_information_list = QListWidget()

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
        self.make_account_page_obj.make_act_widgets.setMaximumHeight(150)
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

        self.make_account_page_obj.password_feeback_label = QLabel("")

        self.make_account_page_obj.make_act_widgets_layout.addWidget(self.make_account_page_obj.username_box)
        self.make_account_page_obj.make_act_widgets_layout.addWidget(self.make_account_page_obj.password_box)
        self.make_account_page_obj.make_act_widgets_layout.addWidget(self.make_account_page_obj.password_box_check)
        self.make_account_page_obj.make_act_widgets_layout.addWidget(self.make_account_page_obj.submit_button)
        self.make_account_page_obj.make_act_widgets_layout.addWidget(self.make_account_page_obj.password_feeback_label)

        #endregion
        #Add pages to stack
        self.pages.addWidget(self.login_page_obj.login_page)
        self.pages.addWidget(self.dashboard_page_obj.dashboard_page)
        self.pages.addWidget(self.make_account_page_obj.make_act_page)

    def handle_login(self):
        print(self.login_page_obj.username_box.text())
        print(self.login_page_obj.password_box.text())
        success, error = self.app.login(self.login_page_obj.username_box.text(), self.login_page_obj.password_box.text())
        if success:
            self.login_page_obj.username_box.clear()
            self.login_page_obj.password_box.clear()

            self.dashboard_page_obj.account_information_list.clear()
            self.dashboard_page_obj.username_list_item = QListWidgetItem(f"Username: {self.app.username}", self.dashboard_page_obj.account_information_list)
            self.dashboard_page_obj.user_data_key_list_item = QListWidgetItem(f"User Data Key: {self.app.user_data_key.hex()}", self.dashboard_page_obj.account_information_list)
            self.dashboard_page_obj.private_key_list_item = QListWidgetItem(f"User Private Key: {self.app.private_key.private_bytes(encoding=serialization.Encoding.Raw, 
                                                                                                                                    format=serialization.PrivateFormat.Raw, 
                                                                                                                                    encryption_algorithm=serialization.NoEncryption()).hex()}", 
                                                                                self.dashboard_page_obj.account_information_list)
            self.dashboard_page_obj.public_key_list_item = QListWidgetItem(f"User Public Key: {self.app.public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()}", self.dashboard_page_obj.account_information_list)
            self.dashboard_page_obj.base_dir_list_item = QListWidgetItem(f"Base Directory: {self.app.base_dir}", self.dashboard_page_obj.account_information_list)

            self.pages.setCurrentIndex(self.DASHBOARD_PAGE)
            print("Login Succesful!")
        else:
            self.login_page_obj.password_box.clear()
            print(f"Login failed with error: {error}")
    
    def handle_logout(self):
        self.app.logout()
        self.pages.setCurrentIndex(self.LOGIN_PAGE)
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

            self.pages.setCurrentIndex(self.LOGIN_PAGE)
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
        pass
    
    def remove_contact(self):
        pass

    def nothing():
        pass



if __name__ == "__main__":
    app = QApplication(sys.argv)
    backend = Application()
    main_window = MainWindow(backend)
    main_window.setWindowTitle("Encrypted Chat")
    main_window.resize(600, 400)
    main_window.show()

    QtAsyncio.run(handle_sigint=True)
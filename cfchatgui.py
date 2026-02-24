from PySide6.QtCore import Qt, QSize, Signal
from PySide6.QtWidgets import (QApplication, QLabel, QMainWindow, QPushButton, QVBoxLayout, QHBoxLayout, QWidget, QLineEdit, 
                               QTextBrowser,QStyle, QSizePolicy, QStackedWidget, QListWidget, QListWidgetItem, QComboBox,
                               QTabWidget)
from PySide6.QtGui import QColor, QPalette, QIcon
import PySide6.QtSvg

#import PySide6.QtAsyncio as QtAsyncio
from qasync import QEventLoop

import signal
from types import SimpleNamespace
import asyncio
import sys
import os
from jblob import JBlob
import cfchatutils as cfu
import cfserverclass
import cfclientclass
from uiobjects import ClientSession, ServerSession, LoginPage, DashboardPage, MakeAccountPage, ConnectServerPage, ConfigureServerPage
from tunnelmanager import Tunnel
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
        
        #print(cfu.check_password(password, self.account))
        
        if cfu.check_password(password, self.account):
            self.username = self.account.opt_data['username']
            salt = bytes.fromhex(self.account.opt_data['salt'])
            self.user_data_key = cfu.derive_key(password, salt)

            self.account.decrypt(self.user_data_key)

            #print(f"Priv: {decrypted_blob['priv_bytes']}, Pub: {decrypted_blob['pub_bytes']}")
            self.private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(self.account.data['priv_bytes']))
            self.public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.account.data['pub_bytes']))
            #for username, key in self.account.data["known_ids"].items():
                #print(f"{username} {key}")

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

class MainWindow(QMainWindow):

    def __init__(self, app: Application):
        super().__init__()  #Calls parent class constructor

        self._shutting_down = False
        self.app = app
        self.server_session = None

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

        server_btn_icon = QIcon(os.path.join(self.app.base_dir, "resources", "icons", "server.svg"))
        self.server_btn = QPushButton("Server")
        self.server_btn.setIcon(server_btn_icon)
        self.server_btn.setIconSize(QSize(24, 24))
        self.server_btn.clicked.connect(lambda: self.switch_page(self.CONFIGURE_SERVER_PAGE) if self.app.username else None)

        self.sidebar_list = QListWidget()
        self.sidebar_list.itemClicked.connect(
            lambda item: self.pages.setCurrentWidget(
                item.data(Qt.ItemDataRole.UserRole)
            )
        )

        sidebar_layout.addWidget(self.dashboard_btn)
        sidebar_layout.addWidget(self.connect_server_btn)
        sidebar_layout.addWidget(self.server_btn)
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
        self.CONFIGURE_SERVER_PAGE = 4

        #Reference Object to organize self variables to be accessible by functions
        self.login_page = LoginPage(self)
        self.dashboard_page = DashboardPage(self)
        self.make_account_page = MakeAccountPage(self)
        self.connect_server_page = ConnectServerPage(self)
        self.configure_server_page = ConfigureServerPage(self)

        #Add pages to stack
        self.pages.addWidget(self.login_page)
        self.pages.addWidget(self.dashboard_page)
        self.pages.addWidget(self.make_account_page)
        self.pages.addWidget(self.connect_server_page)
        self.pages.addWidget(self.configure_server_page)
    
    
    def switch_page(self, index, type="static"):
        #This function sets up the page ui and then switches to it
        #Any type of page you add must be in here
        self.sidebar_list.clearSelection()
        if index == self.LOGIN_PAGE:
            self.login_page.reset()
            self.pages.setCurrentIndex(index)
        if index == self.MAKE_ACCOUNT_PAGE:
            self.make_account_page.reset()
            self.pages.setCurrentIndex(index)
        if index == self.DASHBOARD_PAGE:
            self.dashboard_page.reset()
            self.pages.setCurrentIndex(index)
        if index == self.CONNECT_SERVER_PAGE:
            self.connect_server_page.reset()
            self.pages.setCurrentIndex(index)
        if index == self.CONFIGURE_SERVER_PAGE and not self.server_session:
            self.configure_server_page.reset()
            self.pages.setCurrentIndex(index)
        elif index == self.CONFIGURE_SERVER_PAGE and self.server_session:
            try:
                self.pages.setCurrentWidget(self.server_session)
            except:
                self.configure_server_page.reset()
                self.server_session = None
                self.pages.setCurrentIndex(index)
    
    def cleanup_server_session(self):
        self.pages.removeWidget(self.server_session)
        self.server_session.deleteLater()

        self.configure_server_page.port_box.clear()
        self.configure_server_page.tunnel_selector.setCurrentIndex(0)
        self.pages.setCurrentIndex(self.CONFIGURE_SERVER_PAGE)

    def closeEvent(self, event):
        #print("close event recieved")

        if self._shutting_down:
            event.accept()
            return

        event.ignore()
        self._shutting_down = True
        asyncio.create_task(self._shutdown())
    
    async def _shutdown(self):
        print("Shutting Down")
        #Close all sessions, in reverse
        for i in reversed(range(self.sidebar_list.count())):
            #get the item by index
            item = self.sidebar_list.item(i)
            session = item.data(Qt.ItemDataRole.UserRole)

            self.sidebar_list.takeItem(i)
            self.pages.removeWidget(session)
            session.deleteLater()
        
        try:
            await self.server_session.shutdown()
        except:
            pass

        self.app.logout()
        await asyncio.sleep(0)

        QApplication.instance().quit()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    backend = Application()
    main_window = MainWindow(backend)
    
    signal.signal(signal.SIGINT, lambda *_: QApplication.quit())
    
    main_window.setWindowTitle("Encrypted Chat")
    main_window.resize(600, 400)
    main_window.show()

    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)

    with loop:
        loop.run_forever()
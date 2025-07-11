from pickle import GLOBAL

from PyQt6.QtCore import QSize
from PyQt6.QtWidgets import QApplication, QMainWindow, QLineEdit, QVBoxLayout, QWidget, QPushButton,  QListWidget, QPlainTextEdit, QListWidgetItem, QBoxLayout
from cryptography.exceptions import InvalidKey
from cryptography.fernet import Fernet
import base64
import hashlib

import sys

import os
VAULT_PATH = r"C:\pythontest\vault"
if not os.path.exists(VAULT_PATH):
    os.makedirs(VAULT_PATH)
keyword = ""
class MainWindow(QMainWindow):
    namefile = ""
    def __init__(self):
        super().__init__()
        self.savename = ""
        self.setWindowTitle("Diary")
        self.setFixedSize(QSize(600, 400))

        self.creatingButton = QPushButton("create")
        self.creatingButton.clicked.connect(self.createFile)

        self.deleteButton = QPushButton("delete")
        self.deleteButton.clicked.connect(self.delete)

        self.fileCreationInput = QLineEdit()

        a = QListWidgetItem()
        a.setSizeHint(QLineEdit().sizeHint())

        self.list = QListWidget()
        self.list.addItem(a)
        self.list.setItemWidget(a, self.fileCreationInput)
        self.list.addItems(os.listdir(VAULT_PATH))
        self.list.currentTextChanged.connect(self.currentFile)
        self.list.currentTextChanged.connect(self.read)
        self.list.setRowHidden(0, True)

        self.naming = QLineEdit()
        self.naming.returnPressed.connect(self.rename)

        self.fileCreationInput.textChanged.connect(self.saveName)
        self.fileCreationInput.returnPressed.connect(self.returnation)


        self.input = QPlainTextEdit()
        self.input.textChanged.connect(self.write)

        self.additionalWindow = QWidget()

        layout = QVBoxLayout()
        layoutWithNamingAndInput = QVBoxLayout()
        layoutWithButtons = QVBoxLayout()

        layoutWithNamingAndInput.addWidget(self.naming)
        layoutWithNamingAndInput.addWidget(self.input)

        layoutWithButtons.addWidget(self.creatingButton)
        layoutWithButtons.addWidget(self.deleteButton)
        layoutWithButtons.addWidget(self.list)

        layout.setDirection(QBoxLayout.Direction.LeftToRight)
        container = QWidget()
        layout.insertLayout(0, layoutWithNamingAndInput, 10)
        layout.insertLayout(1, layoutWithButtons, 3)
        container.setLayout(layout)

        self.setCentralWidget(container)
    def read(self, s):
        global keyword
        self.list.clearSelection()
        if not s:
            self.naming.clear()
            self.input.clear()
        if s != "":
            self.naming.setText(self.namefile)
            with open(os.path.join(VAULT_PATH, self.namefile), 'rb') as filestream:
                g = filestream.read()
                if len(g) == 0:
                    self.input.setPlainText("")
                    return
                self.input.setPlainText(fernetIntegration(keyword, g, "d"))

    def write(self):
        global keyword
        s = self.fileCreationInput.text()
        if (self.namefile or s != self.fileNameCompare(s)) and self.input.toPlainText() != "":
            with open(os.path.join(VAULT_PATH, self.namefile), 'w') as filestream:
                s = fernetIntegration(keyword, self.input.toPlainText(), "e")
                filestream.write(s)

    def fileNameCompare(self, u):
        for j in range(self.list.count()):
            if self.list.item(j).text() == u:
                return self.list.item(j).text()

    def currentFile(self, s):
        if s != "" or self.input.toPlainText() != "":
            self.namefile = s

    def saveName(self, s):
        self.savename = s

    def rename(self):
        s = self.naming.text()
        if self.namefile != "" and s != "" and s != self.fileNameCompare(s):
            old_file = os.path.join(VAULT_PATH, self.namefile)
            new_file = os.path.join(VAULT_PATH, s)
            for i in range(self.list.count()):
                if self.list.item(i).text() == self.namefile:
                    self.naming.clear()
                    self.list.takeItem(i)
                    os.rename(old_file, new_file)
                    self.list.addItem(s)

    def returnation(self):
        s = self.fileCreationInput.text()
        if s != self.fileNameCompare(s):
            with open(os.path.join(VAULT_PATH, self.savename), 'w', encoding='utf-8') as filestream:
                self.list.addItem(self.savename)
                self.naming.clear()
                self.fileCreationInput.clear()
                self.list.setRowHidden(0, True)

    def createFile(self):
        self.naming.clear()
        self.input.clear()
        self.list.setRowHidden(0, False)

    def delete(self):
        if self.namefile:
            os.remove(os.path.join(VAULT_PATH, self.namefile))
            for i in range(self.list.count()):
                if self.list.item(i).text() == self.namefile:
                    self.list.takeItem(i)
                    break

class PasswrodCreationWindow(QMainWindow):
    def __init__(self, window):
        super().__init__()
        self.window = window
        self.enterPassword = QLineEdit()
        self.enterPassword.setWindowTitle("Password Creation")
        self.enterPassword.show()
        self.enterPassword.returnPressed.connect(self.passworde)

    def passworde(self):
        if self.enterPassword.text() != "":
            global keyword
            keyword = self.enterPassword.text()
            for j in range(self.window.list.count()):
                if self.window.list.item(j).isHidden():
                    continue
                with open(os.path.join(VAULT_PATH, self.window.list.item(j).text()), "rb") as shork:
                    a = shork.read()
                    print(a)
                    b = fernetIntegration(keyword, a, "d")
                    print(b)
                    if b is None:
                        self.window.list.setRowHidden(j, True)
            self.enterPassword.hide()
            self.window.show()

def fernetIntegration(keypass, thing_to_crypt, mode):
    key = base64.urlsafe_b64encode(hashlib.sha256(keypass.encode()).digest())
    f = Fernet(key)
    if mode == "e" :
        a = f.encrypt(thing_to_crypt.encode()).decode()
        return a
    if mode == "d":
        try:
            b = f.decrypt(thing_to_crypt).decode()
            return b
        except:
            print("password error")
            return None

app = QApplication(sys.argv)
window = MainWindow()
creatingPassword = PasswrodCreationWindow(window)

app.exec()
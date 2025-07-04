from pickle import GLOBAL

from PyQt6.QtCore import QSize
from PyQt6.QtWidgets import QApplication, QMainWindow, QLineEdit, QVBoxLayout, QWidget, QPushButton,  QListWidget, QPlainTextEdit, QListWidgetItem, QBoxLayout
from cryptography.fernet import Fernet
import base64
import hashlib

import sys

import os
vault_path = r"C:\pythontest\vault"
password_path = r"C:\pythontest\vault\.password"
if not os.path.exists(vault_path):
    os.makedirs(vault_path)
if not os.path.exists(password_path):
    with open(password_path, 'w', encoding='utf-8') as filestream:
        pass

keyword = ""
class MainWindow(QMainWindow):
    namefile = ""
    def __init__(self):
        super().__init__()
        self.savename = ""
        self.setWindowTitle("Diary")
        self.setFixedSize(QSize(600, 400))

        self.buttonw = QPushButton("create")
        self.buttonw.clicked.connect(self.createfile)

        self.deletebutton = QPushButton("delete")
        self.deletebutton.clicked.connect(self.delete)

        self.r = QLineEdit()

        a = QListWidgetItem()
        a.setSizeHint(QLineEdit().sizeHint())

        self.list = QListWidget()
        self.list.addItem(a)
        self.list.setItemWidget(a, self.r)
        self.list.addItems(os.listdir(vault_path))
        for i in range(self.list.count()):
            if self.list.item(i).text() == ".password":
                self.list.takeItem(i)
                break
        self.list.currentTextChanged.connect(self.current_file)
        self.list.currentTextChanged.connect(self.read)
        self.list.setRowHidden(0, True)

        self.naming = QLineEdit()
        self.naming.returnPressed.connect(self.rename)

        self.r.textChanged.connect(self.test)
        self.r.returnPressed.connect(self.returnation)


        self.input = QPlainTextEdit()
        self.input.textChanged.connect(self.write)

        self.additionalwindow = QWidget()

        layout = QVBoxLayout()
        layoutwithnamingandinput = QVBoxLayout()
        layoutwithbuttons = QVBoxLayout()

        layoutwithnamingandinput.addWidget(self.naming)
        layoutwithnamingandinput.addWidget(self.input)

        layoutwithbuttons.addWidget(self.buttonw)
        layoutwithbuttons.addWidget(self.deletebutton)
        layoutwithbuttons.addWidget(self.list)

        layout.setDirection(QBoxLayout.Direction.LeftToRight)
        container = QWidget()
        layout.insertLayout(0, layoutwithnamingandinput, 10)
        layout.insertLayout(1, layoutwithbuttons, 3)
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
            with open(os.path.join(vault_path, self.namefile), 'rb') as filestream:
                g = filestream.read()
                if len(g) == 0:
                    self.input.setPlainText("")
                    return
                self.input.setPlainText(FernetIntegration(keyword, g, "d"))

    def write(self):
        global keyword
        s = self.r.text()
        if (self.namefile or s != self.cringe(s)) and self.input.toPlainText() != "":
            with open(os.path.join(vault_path, self.namefile), 'w') as filestream:
                s = FernetIntegration(keyword, self.input.toPlainText(), "e")
                filestream.write(s)

    def cringe(self, u):
        for j in range(self.list.count()):
            if self.list.item(j).text() == u:
                return self.list.item(j).text()

    def current_file(self, s):
        if s != "" or self.input.toPlainText() != "":
            self.namefile = s

    def test(self, s):
        self.savename = s

    def rename(self):
        s = self.naming.text()
        if self.namefile != "" and s != "" and s != self.cringe(s):
            old_file = os.path.join(vault_path, self.namefile)
            new_file = os.path.join(vault_path, s)
            for i in range(self.list.count()):
                if self.list.item(i).text() == self.namefile:
                    self.naming.clear()
                    self.list.takeItem(i)
                    os.rename(old_file, new_file)
                    self.list.addItem(s)

    def returnation(self):
        s = self.r.text()
        if s != self.cringe(s):
            with open(os.path.join(vault_path, self.savename), 'w', encoding='utf-8') as filestream:
                self.list.addItem(self.savename)
                self.naming.clear()
                self.r.clear()
                self.list.setRowHidden(0, True)

    def createfile(self):
        self.naming.clear()
        self.input.clear()
        self.list.setRowHidden(0, False)

    def delete(self):
        if self.namefile:
            os.remove(os.path.join(vault_path, self.namefile))
            for i in range(self.list.count()):
                if self.list.item(i).text() == self.namefile:
                    self.list.takeItem(i)
                    break

class passwrodcreationwindow(QMainWindow):
    def __init__(self, window):
        super().__init__()
        self.window = window
        self.passworedenter = QLineEdit()
        self.passworedenter.setWindowTitle("Password Creation")
        self.passworedenter.show()
        self.passworedenter.returnPressed.connect(self.passworde)

    def passworde(self):
        if self.passworedenter.text() != "":
            with open(password_path, 'w', encoding='utf-8') as filestream:
                global keyword
                keyword = self.passworedenter.text()
                filestream.write(FernetIntegration(keyword, keyword, "e"))
                self.passworedenter.hide()
                self.window.show()

class PsPsWindow(QMainWindow):
    def __init__(self, window, filestream):
        super().__init__()
        self.window = window
        self.filestream = filestream
        self.password = QLineEdit()
        self.password.show()
        self.password.setWindowTitle("Enter Password")
        self.password.returnPressed.connect(self.passwordentered)

    def passwordentered(self):
        with open(password_path, 'r', encoding='utf-8') as pizdec:
            xyq = pizdec.read()
            if self.password.text() == FernetIntegration(self.password.text(), xyq, "d"):
                global keyword
                keyword = self.password.text()
                self.password.hide()
                self.window.show()

def FernetIntegration(keypass, thing_to_crypt, mode):
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

app = QApplication(sys.argv)
window = MainWindow()

with open(password_path, 'r', encoding='utf-8') as filestream:
    passwrodasdadad = filestream.read()
    if passwrodasdadad == "":
        creatingpassword = passwrodcreationwindow(window)
    else:
        passwrod = PsPsWindow(window, passwrodasdadad)

app.exec()
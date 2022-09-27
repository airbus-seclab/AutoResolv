
# This file is part of AutoResolv.
# Copyright 2022 - Airbus, thibault poncetta
# AutoResolv is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
# AutoResolv is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# You should have received a copy of the GNU Affero General Public License
# along with AutoResolv.  If not, see <http://www.gnu.org/licenses/>.


import sys
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import *
from PyQt5.QtGui import *
import os
from PyQt5.QtWidgets import *


class GUI_START(QtWidgets.QDialog):
    def __init__(self, cpath):
        QtWidgets.QDialog.__init__(self, None, QtCore.Qt.WindowSystemMenuHint | QtCore.Qt.WindowTitleHint)
        self.cpath = cpath
        self.newpath = None
        self.setupUi()
        self.setupAction()
        self.setup_label()

    def setupUi(self):
        if not self.objectName():
            self.setObjectName(u"BinaryManagement")
        self.resize(849, 300)
        self.l1 = QLabel(self)
        self.l1.setObjectName(u"l1")
        self.l1.setGeometry(QRect(50, 30, 781, 20))
        self.l2 = QLabel(self)
        self.l2.setObjectName(u"l2")
        self.l2.setGeometry(QRect(330, 110, 221, 17))
        self.textEdit = QLineEdit(self)
        self.textEdit.setObjectName(u"textEdit")
        self.textEdit.setGeometry(QRect(130, 140, 611, 31))
        self.pushButton = QPushButton(self)
        self.pushButton.setObjectName(u"pushButton")
        self.pushButton.setGeometry(QRect(350, 200, 161, 51))

        self.retranslateUi()

        QMetaObject.connectSlotsByName(self)

    def retranslateUi(self):
        self.setWindowTitle(QCoreApplication.translate("BinaryManagement", u"Dialog", None))
        self.l1.setText(QCoreApplication.translate("BinaryManagement", u"<html><head/><body><p align=\"center\"><span style=\" font-size:14pt; font-weight:600; font-style:italic;\">Binary project not found! Maybe IDB stored an old path or binary has moved</span></p></body></html>", None))
        self.l2.setText(QCoreApplication.translate("BinaryManagement", u"CurrentPath of project binary : ", None))
        self.pushButton.setText(QCoreApplication.translate("BinaryManagement", u"Set New Binary Path", None))

    def setup_label(self):
        self.textEdit.setText(self.cpath)

    def setupAction(self):
        self.pushButton.clicked.connect(self.onpathchange)

    def onpathchange(self):
        self.newpath = self.textEdit.text()
        self.close()
   

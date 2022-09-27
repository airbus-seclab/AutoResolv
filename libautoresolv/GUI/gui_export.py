
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

from libautoresolv.util import *
from libautoresolv.error import *
from libautoresolv.dbcache import *

class GUI_EXPORT(QtWidgets.QDialog):
    def __init__(self, cache):
        QtWidgets.QDialog.__init__(self, None, QtCore.Qt.WindowSystemMenuHint | QtCore.Qt.WindowTitleHint)
        self.cache = cache
        self.setupUi()
        self.setupAction()
        self.setup_label()


    def setupUi(self):
        if not self.objectName():
            self.setObjectName(u"Export")
        self.resize(1300, 300)
        self.listcache = QListWidget(self)
        self.listcache.setObjectName(u"listcache")
        self.listcache.setGeometry(QRect(20, 30, 256, 192))
        self.b_export = QPushButton(self)
        self.b_export.setObjectName(u"b_export")
        self.b_export.setGeometry(QRect(520, 160, 161, 61))
        self.l_info = QLabel(self)
        self.l_info.setObjectName(u"l_info")
        self.l_info.setGeometry(QRect(300, 30, 571, 21))
        self.l_info2 = QLabel(self)
        self.l_info2.setObjectName(u"l_info2")
        self.l_info2.setGeometry(QRect(300, 50, 591, 31))
        self.l_cache_i = QLabel(self)
        self.l_cache_i.setObjectName(u"l_cache_i")
        self.l_cache_i.setGeometry(QRect(300, 110, 161, 31))
        self.v_cache_i = QLabel(self)
        self.v_cache_i.setObjectName(u"v_cache_i")
        self.v_cache_i.setGeometry(QRect(370, 110, 1200, 31))

        self.retranslateUi()

        QMetaObject.connectSlotsByName(self)
    # setupUi

    def retranslateUi(self):
        self.setWindowTitle(QCoreApplication.translate("Export", u"Export", None))
        self.b_export.setText(QCoreApplication.translate("Export", u"Export to cache", None))
        self.l_info.setText(QCoreApplication.translate("Export", u"Please select the db cache of the main binary. ", None))
        self.l_info2.setText(QCoreApplication.translate("Export", u"Note that AutoResolv will use the main binary cache to export only resolved Functions", None))
        self.l_cache_i.setText(QCoreApplication.translate("Export", u"<html><head/><body><p><span style=\" font-weight:600;\">Action : </span></p></body></html>", None))
        self.v_cache_i.setText(QCoreApplication.translate("Export", u"cache_value", None))

    def setup_label(self):
        self.v_cache_i.setText("")
        cachelist = self.list_cache()
        for file in cachelist:
            self.listcache.addItem(file)
        
        binary = idaapi.get_input_file_path()
        self.v_cache_i.setText("Will parse {} resolved function and export {} signature".format(file, binary))
        

    def setupAction(self):
        self.b_export.clicked.connect(self.on_button_export)
        self.listcache.itemClicked.connect(self.modify_action)

    def on_button_export(self):
        if "No db found in" in self.v_cache_i.text():
            raise Exception("No db selected")

        self.exported_db= self.listcache.currentItem().text()
        self.close()

    def list_cache(self):
        try:
            module_path = os.path.dirname(__file__) + "/../db/"
            db = os.listdir(module_path)
            return db
        except FileNotFoundError:
            return ["No db found in {}".format(module_path)]

    def modify_action(self):
        item = self.listcache.currentItem().text()
        binary = idaapi.get_input_file_path()
        self.v_cache_i.setText("Will parse {} resolved function and export {} signature".format(item, binary))

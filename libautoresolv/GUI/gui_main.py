
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
from PyQt5.QtWidgets import *

from libautoresolv.resultshower import ResultShower
from libautoresolv.util import *
from libautoresolv.error import *
from libautoresolv.dbcache import *
from libautoresolv.GUI.gui_export import GUI_EXPORT

class GUI_MAIN(QtWidgets.QDialog):
    def __init__(self, cache):
        QtWidgets.QDialog.__init__(self, None, QtCore.Qt.WindowSystemMenuHint | QtCore.Qt.WindowTitleHint)
        self.cache = cache
        self.setupUi()
        self.setupAction()
        self.setupLabel()

    def setupUi(self):
        if not self.objectName():
            self.setObjectName(u"AutoResolv")
        self.resize(1088, 718)
        self.l_activeparam = QLabel(self)
        self.l_activeparam.setObjectName(u"l_activeparam")
        self.l_activeparam.setGeometry(QRect(240, 20, 181, 31))
        self.b_cleandb = QPushButton(self)
        self.b_cleandb.setObjectName(u"b_cleandb")
        self.b_cleandb.setGeometry(QRect(330, 240, 181, 51))
        self.b_resolve = QPushButton(self)
        self.b_resolve.setObjectName(u"b_resolve")
        self.b_resolve.setGeometry(QRect(130, 240, 181, 51))
        self.b_saveconf = QPushButton(self)
        self.b_saveconf.setObjectName(u"b_saveconf")
        self.b_saveconf.setGeometry(QRect(270, 100, 211, 51))
        self.c_libc = QCheckBox(self)
        self.c_libc.setObjectName(u"c_libc")
        self.c_libc.setGeometry(QRect(30, 70, 161, 23))
        self.c_demangle = QCheckBox(self)
        self.c_demangle.setObjectName(u"c_demangle")
        self.c_demangle.setGeometry(QRect(30, 100, 171, 23))
        self.c_comment = QCheckBox(self)
        self.c_comment.setObjectName(u"c_comment")
        self.c_comment.setGeometry(QRect(30, 130, 151, 23))
        self.l_info = QLabel(self)
        self.l_info.setObjectName(u"l_info")
        self.l_info.setGeometry(QRect(270, 340, 171, 31))
        self.l_info_db_path = QLabel(self)
        self.l_info_db_path.setObjectName(u"l_info_db_path")
        self.l_info_db_path.setGeometry(QRect(20, 390, 111, 17))
        self.v_info_db_path = QLabel(self)
        self.v_info_db_path.setObjectName(u"v_info_db_path")
        self.v_info_db_path.setGeometry(QRect(130, 390, 501, 17))
        self.l_info_db_value = QLabel(self)
        self.l_info_db_value.setObjectName(u"l_info_db_value")
        self.l_info_db_value.setGeometry(QRect(20, 420, 171, 17))
        self.v_info_db_value = QLabel(self)
        self.v_info_db_value.setObjectName(u"v_info_db_value")
        self.v_info_db_value.setGeometry(QRect(190, 420, 421, 17))
        self.lt = QLabel(self)
        self.lt.setObjectName(u"lt")
        self.lt.setGeometry(QRect(10, 320, 611, 17))
        self.lt2 = QLabel(self)
        self.lt2.setObjectName(u"lt2")
        self.lt2.setGeometry(QRect(20, 490, 621, 17))
        self.l_refactor = QLabel(self)
        self.l_refactor.setObjectName(u"l_refactor")
        self.l_refactor.setGeometry(QRect(280, 520, 171, 31))
        self.b_refactor_import = QPushButton(self)
        self.b_refactor_import.setObjectName(u"b_refactor_import")
        self.b_refactor_import.setGeometry(QRect(120, 570, 181, 51))
        self.b_refactor_export = QPushButton(self)
        self.b_refactor_export.setObjectName(u"b_refactor_export")
        self.b_refactor_export.setGeometry(QRect(340, 570, 181, 51))
        self.l_info_bin_path = QLabel(self)
        self.l_info_bin_path.setObjectName(u"l_info_bin_path")
        self.l_info_bin_path.setGeometry(QRect(20, 450, 171, 17))
        self.v_info_bin_path = QLabel(self)
        self.v_info_bin_path.setObjectName(u"v_info_bin_path")
        self.v_info_bin_path.setGeometry(QRect(170, 450, 451, 17))
        self.separator = QFrame(self)
        self.separator.setObjectName(u"separator")
        self.separator.setGeometry(QRect(630, 10, 20, 691))
        self.separator.setMinimumSize(QSize(20, 611))
        self.separator.setFrameShape(QFrame.VLine)
        self.separator.setFrameShadow(QFrame.Sunken)
        self.label = QLabel(self)
        self.label.setObjectName(u"label")
        self.label.setGeometry(QRect(210, 670, 291, 20))
        self.lib_info = QLabel(self)
        self.lib_info.setObjectName(u"lib_info")
        self.lib_info.setGeometry(QRect(770, 10, 231, 31))
        self.combobox_lib = QComboBox(self)
        self.combobox_lib.setObjectName(u"combobox_lib")
        self.combobox_lib.setGeometry(QRect(730, 310, 281, 25))
        self.lib_list = QListWidget(self)
        self.lib_list.setObjectName(u"lib_list")
        self.lib_list.setGeometry(QRect(660, 40, 421, 261))
        self.lineedit_lib = QLineEdit(self)
        self.lineedit_lib.setObjectName(u"lineedit_lib")
        self.lineedit_lib.setGeometry(QRect(690, 350, 361, 25))
        self.b_libchange = QPushButton(self)
        self.b_libchange.setObjectName(u"b_libchange")
        self.b_libchange.setGeometry(QRect(790, 390, 181, 51))
        self.c_verbose = QCheckBox(self)
        self.c_verbose.setObjectName(u"c_verbose")
        self.c_verbose.setGeometry(QRect(30, 160, 141, 23))
        self.lineedit_lib_path = QLineEdit(self)
        self.lineedit_lib_path.setObjectName(u"lineedit_lib_path")
        self.lineedit_lib_path.setGeometry(QRect(700, 600, 361, 25))
        self.b_libpathchange = QPushButton(self)
        self.b_libpathchange.setObjectName(u"b_libpathchange")
        self.b_libpathchange.setGeometry(QRect(790, 640, 181, 51))
        self.libpath_list = QListWidget(self)
        self.libpath_list.setObjectName(u"libpath_list")
        self.libpath_list.setGeometry(QRect(660, 450, 421, 141))

        self.retranslateUi()

        QMetaObject.connectSlotsByName(self)

    def retranslateUi(self):
        self.setWindowTitle(QCoreApplication.translate("AutoResolv", u"Dialog", None))
        self.l_activeparam.setText(QCoreApplication.translate("AutoResolv", u"<html><head/><body><p><span style=\" font-size:14pt; font-weight:600;\">Active Parameters</span></p></body></html>", None))
        self.b_cleandb.setText(QCoreApplication.translate("AutoResolv", u"Clean DB Cache", None))
        self.b_resolve.setText(QCoreApplication.translate("AutoResolv", u"Resolve", None))
        self.b_saveconf.setText(QCoreApplication.translate("AutoResolv", u"Save Parameters To Cache", None))
        self.c_libc.setText(QCoreApplication.translate("AutoResolv", u"resolve Libc functions", None))
        self.c_demangle.setText(QCoreApplication.translate("AutoResolv", u"demangle functions", None))
        self.c_comment.setText(QCoreApplication.translate("AutoResolv", u"comment IDA code", None))
        self.l_info.setText(QCoreApplication.translate("AutoResolv", u"<html><head/><body><p><span style=\" font-size:14pt; font-weight:600;\">Informations</span></p></body></html>", None))
        self.l_info_db_path.setText(QCoreApplication.translate("AutoResolv", u"db cache path : ", None))
        self.v_info_db_path.setText(QCoreApplication.translate("AutoResolv", u"<html><head/><body><p><span style=\" font-size:12pt; font-style:italic; color:#c01c28;\">DB_PATH_VALUE</span></p></body></html>", None))
        self.l_info_db_value.setText(QCoreApplication.translate("AutoResolv", u"db cache contain Data : ", None))
        self.v_info_db_value.setText(QCoreApplication.translate("AutoResolv", u"<html><head/><body><p><span style=\" font-size:12pt; font-style:italic; color:#c01c28;\">DB_CONTAIN_DATA_VALUE</span></p></body></html>", None))
        self.lt.setText(QCoreApplication.translate("AutoResolv", u"---------------------------------------------------------------------------------------------------------------------------------------", None))
        self.lt2.setText(QCoreApplication.translate("AutoResolv", u"----------------------------------------------------------------------------------------------------------------------------------------", None))
        self.l_refactor.setText(QCoreApplication.translate("AutoResolv", u"<html><head/><body><p><span style=\" font-size:12pt; font-weight:600;\">REFACTOR</span></p></body></html>", None))
        self.b_refactor_import.setText(QCoreApplication.translate("AutoResolv", u"Import Signature File", None))
        self.b_refactor_export.setText(QCoreApplication.translate("AutoResolv", u"Export Signature File", None))
        self.l_info_bin_path.setText(QCoreApplication.translate("AutoResolv", u"project binary path : ", None))
        self.v_info_bin_path.setText(QCoreApplication.translate("AutoResolv", u"<html><head/><body><p><span style=\" font-size:12pt; font-style:italic; color:#c01c28;\">Bin_path</span></p></body></html>", None))
        self.label.setText(QCoreApplication.translate("AutoResolv", u"AutoResolv dev-v0.90p | Thibault Poncetta", None))
        self.lib_info.setText(QCoreApplication.translate("AutoResolv", u"<html><head/><body><p><span style=\" font-size:14pt; font-weight:600;\">Librairies Management</span></p></body></html>", None))
        self.b_libchange.setText(QCoreApplication.translate("AutoResolv", u"ChangeLibraryPath", None))
        self.c_verbose.setText(QCoreApplication.translate("AutoResolv", u"Verbose Mode", None))
        self.b_libpathchange.setText(QCoreApplication.translate("AutoResolv", u"AddLibraryPath", None))


    def setupLabel(self):
        self.c_comment.setChecked(self.cache.CONFIG['comment'])
        self.c_libc.setChecked(self.cache.CONFIG['libc'])
        self.c_demangle.setChecked(self.cache.CONFIG['demangle'])
        self.c_verbose.setChecked(self.cache.CONFIG['verbose'])


        self.lineedit_lib_path.setText("Input Path of Library directory")

        if len(self.cache.rpath) >=1:
            for path in self.cache.rpath:
                self.libpath_list.addItem(path)
        self.libpath_list.addItem("/usr/lib/")
        self.libpath_list.addItem("/lib/x86_64-linux-gnu/")

        for lib in self.cache.libsinfo:
            self.lib_list.addItem(f"{lib} | {self.cache.libsinfo[lib]}")
            self.combobox_lib.addItem(lib)

        self.lineedit_lib.setText(self.cache.libsinfo[next(iter(self.cache.libsinfo))])

        self.v_info_db_path.setText(self.cache.db_path)
        self.v_info_bin_path.setText(self.cache.bin_path)
        if self.cache.is_cached_data:
            self.v_info_db_value.setText("Yes")
        else:
             self.v_info_db_value.setText("No")


    def setupAction(self):
        self.b_resolve.clicked.connect(self.on_button_resolv)
        self.b_saveconf.clicked.connect(self.on_button_saveconf)
        self.combobox_lib.activated.connect(self.on_combox_event)
        self.b_cleandb.clicked.connect(self.on_button_cleandb)
        self.b_libchange.clicked.connect(self.on_button_libchange)

        self.b_refactor_export.clicked.connect(self.on_button_export)
        self.b_refactor_import.clicked.connect(self.on_button_import)
        self.b_libpathchange.clicked.connect(self.on_newlibpath)


    def on_button_export(self):
        gui_export = GUI_EXPORT(self.cache)
        gui_export.exec_()
        try:
            main_db = self.cache.modpath + gui_export.exported_db
        except AttributeError:
            return
        self.cache_extern = DB_CACHE_MANAGER(main_db, module_path=self.cache.modpath)
        con = self.cache_extern.check_cache_con()
        if con:
            print(f"[AutoResolv] Extern DB Cache is UP")
        else:
            raise Exception(f"[AutoResolv] Extern DB Cache seem empty, can't export !")

        self.cache_extern.parse_data_cache(no_check=True)
        values = None
        try:
            values = self.cache_extern.cached_data
        except Exception:
            raise Exception("Returned values from cache is None ! Resolve at least one time on main binary is required")
        
        if self.cache.CONFIG['verbose']:
            print(f"[AutoResolv] Parsed external cache.")
        
        if self.cache.CONFIG['verbose']:
            print(f"[AutoResolv] Starting exporting")
        cpt, allsig = getSignature(values, self.cache.CONFIG)
        if self.cache.CONFIG['verbose']:
            print(f"[AutoResolv] Done exported {cpt} functions signature")

        self.cache_extern.save_signature(allsig)

        if self.cache.CONFIG['verbose']:
            print(f"[AutoResolv] Saved all data to cache, you can now import on main binary to start refactor")
        
    

    def on_button_import(self):
        if self.cache.CONFIG['verbose']:
            print("[AutoResolv] Importing Functions signature from cache")
        sigs = self.cache.parse_signature()
        if sigs is None:
            raise Exception("[AutoResolv] No signature found ! Did you use export on another IDA instance (yourcustomlib.so) ? ")

        if self.cache.CONFIG['verbose']:
            print("[AutoResolv] Parsed cached sucessfull. Refactoring wrapper and XREF using signature")
        
        cpt, xref_cpt = refactorExtern(sigs, self.cache.CONFIG)
        if self.cache.CONFIG['verbose']:
            print(f"[AutoResolv] Sucessfully patched {cpt} functions and {xref_cpt} Xrefs")


    def on_button_cleandb(self):
        
        os.remove(self.cache.db_path) 
        if self.cache.CONFIG['verbose']:
            print("[AutoResolv] Cleaned DB Cache sucessfull")

        self.close()
        
        


    def on_newlibpath(self):

    
        newpath = self.lineedit_lib_path.text()
        if not newpath.endswith("/"):
            newpath += "/"
        foundNewLibrary = False
        self.cache.parse_libinfo_cache()
        for lib in self.cache.libsinfo:
            _exist = os.path.exists(newpath + lib)
            if (_exist):

                print(f"[AutoResolv] Librairy {lib} found !")
                self.cache.setNewLibPath(lib, newpath + lib, self.cache.CONFIG)
                items = self.lib_list.findItems(lib, QtCore.Qt.MatchContains)
                row = self.lib_list.row(items[0])
                self.lib_list.takeItem(row)
                self.lib_list.addItem(f"{lib} | {newpath + lib}")
                if not foundNewLibrary:
                    self.libpath_list.addItem(newpath)
                    self.cache.rpath.append(newpath)
                    self.cache.cache_save_rpath()

                foundNewLibrary = True

        if (not foundNewLibrary):
            raise Exception(f"[AutoResolv] Couldn't find any new library with path : {newpath}")

        self.cache.parse_libinfo_cache()
        if self.cache.CONFIG['verbose']:
                    print("[AutoResolv] Updated cache and GUI")   
            
                
    def on_button_libchange(self):
        current_lib = self.combobox_lib.currentText().replace(" ","")
        items = self.lib_list.findItems(current_lib, QtCore.Qt.MatchContains)
        old_path = None
        for item in items:
            old_path = item.text().split("|")[1].replace(" ","")
        
        new_path = self.lineedit_lib.text().replace(" ","")
        if self.cache.CONFIG['verbose']:
            print("[AutoResolv] Changing the path of {} :[{}] to [{}]".format(current_lib, old_path, new_path))

        self.cache.setNewLibPath(current_lib, new_path, self.cache.CONFIG)
        self.cache.parse_libinfo_cache() 

        items = self.lib_list.findItems(current_lib, QtCore.Qt.MatchContains)
        row = self.lib_list.row(items[0])
        self.lib_list.takeItem(row)
        self.lib_list.addItem(f"{current_lib} | {new_path}")
        if self.cache.CONFIG['verbose']:
            print("[AutoResolv] Updated cache and GUI")   



    def on_button_resolv(self):

        if self.cache.is_cached_data:
            values = self.cache.cached_data
            if self.cache.CONFIG['verbose']:
                print("[AutoResolv] Data found in DB Cache, not resolving again")

            rs = ResultShower("Result", values, self.cache.CONFIG['demangle'])
            r = rs.show()
            self.close()

        else:
            if self.cache.CONFIG['verbose']:
                print("[AutoResolv] Looking for extern functions in .PLT | .PLT-SEC segment")                            
            start,end = get_seg(".plt")
            
            wrapper_funs_plt = {}
            wrapper_funs_plt2 = {}
            if start is not None and end is not None:
                wrapper_funs_plt = get_extern(start,end)
            
            start,end = get_seg(".plt.sec")
            if start is not None and end is not None:
                wrapper_funs_plt2 = get_extern(start,end)
         
            funs_binary = dict(wrapper_funs_plt)
            funs_binary.update(wrapper_funs_plt2)

            if len(funs_binary) == 0:
                raise IdaGetFunsError

            if self.cache.CONFIG['verbose']:
                print(f"[AutoResolv] Got {len(funs_binary)} functions")      

            self.libsfun = {}
            for lib in self.cache.libsinfo:
                funs = getAllFunsFromLib(self.cache.libsinfo[lib], self.cache.CONFIG['libc'])
            
                if funs is None:
                    if self.cache.CONFIG['verbose']:
                        print(f"[AutoResolv] Couldn't parse {lib}")
                    continue
                else:
                    if self.cache.CONFIG['verbose']:
                        print(f"[AutoResolv] Parsed {lib}")
                    self.libsfun[lib] = funs

            if self.cache.CONFIG['verbose']:
                print("\n[AutoResolv] All libs parsed. Resolving now...\n")

            
            values, external_resolved= Resolve(funs_binary, self.libsfun, self.cache.libsinfo, self.cache.CONFIG)
            rs = ResultShower("Result", values, self.cache.CONFIG['demangle'])
            r = rs.show()

            if self.cache.CONFIG['comment']:
                if self.cache.CONFIG['verbose']:
                    print("[AutoResolv] Adding libname in IDA code near the call")
                CommentFuns(external_resolved, self.cache.CONFIG)
    
            self.cache.save_data(values, self.cache.CONFIG)
            if self.cache.CONFIG['verbose']:
                print("[AutoResolv] Data Saved to Cache")
                
            if self.cache.CONFIG['verbose']:
                print("[AutoResolv] All done ")

            self.close()

    def on_button_saveconf(self):
        self.cache.CONFIG['libc'] = bool(self.c_libc.checkState())
        self.cache.CONFIG['demangle'] = bool(self.c_demangle.checkState())
        self.cache.CONFIG['comment'] = bool(self.c_comment.checkState())
        self.cache.CONFIG['verbose'] = bool(self.c_verbose.checkState())

        self.cache.save_conf(self.cache.CONFIG)
        if self.cache.CONFIG['verbose']:
            print("[AutoResolv] Saved Active parameters to cache")
        self.cache.parse_conf_cache()

    def on_combox_event(self):
        text = self.combobox_lib.currentText()
        items = self.lib_list.findItems(text, QtCore.Qt.MatchContains)
        path = None
        for item in items:
            path = item.text().split("|")[1]
        self.lineedit_lib.setText(path)







        

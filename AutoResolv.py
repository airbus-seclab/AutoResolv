
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


import idaapi
import idc
import sys
import idautils
import ida_funcs
import time
import os
import subprocess
import sys
from collections import defaultdict

from libautoresolv.resultshower import ResultShower
from libautoresolv.util import *
from libautoresolv.error import *
from libautoresolv.dbcache import *

from libautoresolv.GUI.gui_main import *
from libautoresolv.GUI.gui_start import *



VERSION = "dev-v0.90p"
idaapi.require("libautoresolv.GUI.gui_main")
idaapi.require("libautoresolv.GUI.gui_export")
idaapi.require("libautoresolv.GUI.gui_start")



class Kp_Menu_Context(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @classmethod
    def get_name(self):
        return self.__name__

    @classmethod
    def get_label(self):
        return self.label

    @classmethod
    def register(self, plugin, label):
        self.plugin = plugin
        self.label = label
        instance = self()
        return idaapi.register_action(idaapi.action_desc_t(
            self.get_name(),  # Name. Acts as an ID. Must be unique.
            instance.get_label(),  # Label. That's what users see.
            instance  # Handler. Called when activated, and for updating
        ))

    @classmethod
    def unregister(self):
        """Unregister the action.
        After unregistering the class cannot be used.
        """
        idaapi.unregister_action(self.get_name())

    @classmethod
    def activate(self, ctx):
        # dummy method
        return 1

    @classmethod
    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_DISASM:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET

class Searcher(Kp_Menu_Context):
    def activate(self, ctx):
        self.plugin.search()
        return 1



p_initialized = False
#--------------------------------------------------------------------------
# Plugin
#--------------------------------------------------------------------------
class AutoResolv(idaapi.plugin_t):
    comment = "Resolve imports to find libname/paths and refactor call type from signature file"
    help = "AutoResolv Help"
    wanted_name = "AutoResolv"
    flags = idaapi.PLUGIN_KEEP
    wanted_hotkey= "Ctrl+Shift-A"

    def init(self):
        global p_initialized

        # register popup menu handlers
        try:
            Searcher.register(self, "AutoResolv")
        except:
            pass

        if p_initialized is False:
            p_initialized = True
            idaapi.register_action(idaapi.action_desc_t(
                "AutoResolv",
                "AutoResolv imports",
                Searcher(),
                None,
                None,
                0))
            idaapi.attach_action_to_menu("Search", "AutoResolv", idaapi.SETMENU_APP)
            print("*" * 80)
            print(f"AutoResolv {VERSION} | Thibault Poncetta")
            print("*" * 80)

        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def _decompile_then_write_on_fd(self, fd, funs):
        lenf = len(funs)
        cpt = 0
        for fun in funs:
            ea = funs[fun]
            cfunc = str(idaapi.decompile(ea)).split("\n")[0] + ";"
            print(f"Exporting {cfunc}, Progression: {(cpt/lenf)*100}%")
            cpt += 1
            fd.write(cfunc + "\n")

    def _signature_export(self, fd):
        
        start,end = get_seg(".text")   
        if start == None or end == None:
            print("[AutoResolv] Error when parsing Segments() address.")
            
        funs = get_funs(start, end)
        nb_fun = len(funs)
        print(f"[AutoResolv] Exporting {nb_fun} function from .text segment")

        self._decompile_then_write_on_fd(fd, funs)
        print(f"[AutoResolv] Done")


    def main(self):
        print(f"AutoResolv {VERSION}")



        module_path = os.path.dirname(__file__) + "/libautoresolv/db/"
        binary_name = idaapi.get_root_filename()
        db_path = module_path + ".cache_" + binary_name + ".db"
        bin_path = os.getcwd() + "/" +  binary_name

        cache = DB_CACHE_MANAGER(db_path, module_path, bin_path)
        con = cache.check_cache_con()
        if con:
            cache.parse_conf_cache()
            cache.parse_libinfo_cache()
            cache.parse_rpath_cache()
            cache.parse_data_cache()
            cache.parse_bininfo_cache()
            bin_path = cache.bin_path

        if not os.path.exists(bin_path):
            

            gui_start = GUI_START(bin_path)
            gui_start.exec_()

            newpath = gui_start.newpath
            if newpath is None:
                raise Exception("[AutoResolv] No path given  ! Aborting")
            if not os.path.exists(newpath):
                raise Exception("[AutoResolv] Given path for binary location incorrect ! Aborting")
            else:
                print(f"[AutoResolv] Set new binary path to {newpath}")
                bin_path = newpath

        if not con:
            print(f"[AutoResolv] DB Cache seem empty, Creating cache")
            libs,rpath = getLibsFromBin(bin_path)
            if rpath is not None:
                print(f"[AutoResolv] I got a rpath : {rpath}")
                cache.create_cache(libs, bin_path, rpath)
                cache.rpath = rpath.split(":")
            else:
                cache.create_cache(libs, bin_path)
                cache.rpath = []

        cache.cache_save_bininfo(bin_path)
        gui_main = GUI_MAIN(cache)
        gui_main.exec_()
        
    
    def run(self, arg):
        self.main()


def PLUGIN_ENTRY():
    return AutoResolv()

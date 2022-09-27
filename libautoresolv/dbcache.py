
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


import sqlite3

from libautoresolv.error import *
import os

class DB_CACHE_MANAGER():
    
    def __init__(self, path, module_path=None, bin_path=None):
        self.db_path = path
        self.is_cached_data = False
        if module_path:
            self.modpath = module_path

        if bin_path:
            self.bin_path = bin_path

    def parse_bininfo_cache(self):
        try:
            cmd =self.cur.execute("SELECT * from bininfo")
            data = cmd.fetchone()
            self.bin_path = data[1]
        except Exception:
            raise CacheParseConfigError

        if (self.CONFIG['verbose']):
            print("[AutoResolv] Parsed binary information from cache")
        
    def check_cache_con(self):
        print(f"[AutoResolv] Checking path : {self.modpath}")
        if not os.path.isdir(self.modpath):
            print(f"[AutoResolv] /db directory not existing , creating it")
            os.mkdir(self.modpath)
        
        print(f"[AutoResolv] Connecting to : {self.db_path}")
        self.con = sqlite3.connect(self.db_path)
        self.cur = self.con.cursor()
        self.cur.execute("SELECT name from sqlite_master")
        cache_out = self.cur.fetchone()
        if cache_out is not None:
            return True
        else:
            return False

    def parse_signature(self):
        sigs = {}
        cmd = self.cur.execute("SELECT * from signature")
        values = cmd.fetchall()
        if values == []:
            return None
        else:
            
            for line in values:
                sigs[line[0]] = line[1]

        return sigs

    def parse_data_cache(self, no_check=None):
        if no_check:
            self.CONFIG = {}
            self.CONFIG['demangle'] = False
        cmd = self.cur.execute("SELECT * from autoresolv_data")
        values = cmd.fetchall()
        if values == []:
            return None
        else:

            values_ = []
            
            for line in values:
                if self.CONFIG['demangle']:
                    values_.append([line[0], line[1], line[2], line[3]])
                else:
                    values_.append([line[0], line[1], line[2]])

            self.cached_data = values_
            self.is_cached_data = True


    def save_signature(self, sigs):

        try:
            for fun_name in sigs:
                dataset = (fun_name, sigs[fun_name])
                self.cur.execute("INSERT INTO signature VALUES (?, ?)", dataset)
                self.con.commit()

        except Exception:
            raise Exception("CacheSaveSignatureError : cannot insert signature to extern database.")

    def save_data(self, value, config):
        try:
            for i in range(len(value)):
                if config['demangle']:
                    dataset = (str(value[i][0]), str(value[i][1]), str(value[i][2]), str(value[i][3]))
                else:
                    dataset = (str(value[i][0]), str(value[i][1]), str(value[i][2]), "None")

                self.cur.execute("INSERT INTO autoresolv_data VALUES (?, ?, ? , ?)", dataset)
                self.con.commit()
                
        except Exception:
            CacheSaveResolvedDataError

    def save_conf(self, config):
        try:
            self.cur.execute(f"UPDATE configuration SET id=0,libc={config['libc']}, demangle={config['demangle']} , comment={config['comment']} , verbose={config['verbose']} WHERE id=0")
            self.con.commit()
        except Exception:
            raise CacheUpdateConfigurationError

    def cache_save_rpath(self):
        rpath = self.rpath[0]
        if len(self.rpath) >= 2:
            for path in self.rpath[1:]:
                rpath += ":" + path

        noRpath = False
        try:
            cmd =self.cur.execute("SELECT * from rpath")
            cmx = cmd.fetchone()
            if cmx == None:
                noRpath = True
        except Exception: #no rpath data
            raise Exception("[AutoResolv] Unknow Exception")

        if noRpath:
            dataset=(0,rpath)
            try:
                self.cur.execute(f"INSERT into rpath VALUES (?,?)", dataset)
                self.con.commit()
            except Exception:
                raise Exception("[AutoResolv] Couldn't update rpath cache ")
        else:
            try:
                self.cur.execute(f"UPDATE rpath SET rp='{rpath}' WHERE id=0")
                self.con.commit()
            except Exception:
                raise Exception("[AutoResolv] Couldn't update rpath cache ")

    def cache_save_bininfo(self, bininfo):
        try:
            self.cur.execute(f"UPDATE bininfo SET binname='{bininfo}' WHERE id=0")
            self.con.commit()
        except Exception:
            raise Exception("[AutoResolv] Couldn't update binfo cache ")

    def setNewLibPath(self, lib, path, config):
        try:
            self.cur.execute(f"UPDATE libinfo SET libpath='{path}' WHERE libname='{lib}'")
            self.con.commit()
        except Exception:
            raise CacheUpdateConfigurationError
            

    def create_cache(self, libs, bininfo, rpath=None):
       
        try:
            self.cur.execute("CREATE TABLE configuration(id, libc, demangle, comment, verbose)")
            self.cur.execute("CREATE TABLE libinfo(libname, libpath)")
            self.cur.execute("CREATE TABLE autoresolv_data(fun_name, library, library_path, demangle_name)")
            self.cur.execute("CREATE TABLE signature(fun_name, csig)")
            self.cur.execute("CREATE TABLE rpath(id, rp)")
            self.cur.execute("CREATE TABLE bininfo(id, binname)")
            print(f"[AutoResolv] Created table sucessfully {self.db_path}")

        except Exception:
            raise CacheBaseCreationError


        conf = (0, False,True,True, True) #default config
        self.CONFIG = {}
        self.CONFIG['libc'] = False
        self.CONFIG['demangle'] = True
        self.CONFIG['comment'] = True
        self.CONFIG['verbose'] = True

        self.libsinfo = libs

        try:            
            self.cur.execute("INSERT INTO configuration VALUES (?, ?, ?, ?, ?)", conf)
            self.con.commit()
            if self.CONFIG['verbose']:
                print(f"[AutoResolv] Inserted default config into cache")

            dataset = (0, bininfo)
            self.cur.execute("INSERT INTO bininfo VALUES (?, ?)", dataset)
            self.con.commit()
            if self.CONFIG['verbose']:
                print(f"[AutoResolv] Inserted binary info into cache")

            for lib in libs:
                dataset = (lib, libs[lib])
                self.cur.execute("INSERT INTO libinfo VALUES (?, ?)", dataset)
                self.con.commit()
                

            if self.CONFIG['verbose']:
                print(f"[AutoResolv] Inserted Parsed lib into cache")
        
        except Exception:
            raise CacheBaseSetup

        if rpath is not None:
            try:
                dataset = (0, rpath)
                self.cur.execute("INSERT INTO rpath VALUES (?, ?)", dataset)
                self.con.commit()                
                if self.CONFIG['verbose']:
                    print(f"[AutoResolv] Inserted rpath into cache")

            except Exception:
                raise CacheBaseSetup

    def parse_conf_cache(self):

        self.CONFIG = {}

        try:
            cmd =self.cur.execute("SELECT * from configuration")
            config = cmd.fetchone()
            self.CONFIG['libc'] = bool(config[1])
            self.CONFIG['demangle'] = bool(config[2])
            self.CONFIG['comment'] = bool(config[3])
            self.CONFIG['verbose'] = bool(config[4])
        except Exception:
            raise CacheParseConfigError

        if (self.CONFIG['verbose']):
            print("[AutoResolv] Parsed Config Data from cache")


    def parse_libinfo_cache(self):
        
        self.libsinfo = {}

        try:
            cmd =self.cur.execute("SELECT * from libinfo")
            libs = cmd.fetchall()
            for lib in libs:
                self.libsinfo[lib[0]] = lib[1]
        except Exception:
            raise CacheParseLibDataError

        if (self.CONFIG['verbose']):
            print("[AutoResolv] Parsed Libraries Data from cache")

    def parse_rpath_cache(self):
        self.rpath = []
        try:
            cmd =self.cur.execute("SELECT * from rpath")
            rpath = cmd.fetchone()[1].split(":")
            for path in rpath:
                self.rpath.append(path)
        except Exception: #no rpath data
            return

        if (self.CONFIG['verbose']):
            print("[AutoResolv] Parsed rpath Data from cache")


        
  

        



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


import idautils
import idc
import ida_funcs
import idaapi
import os
import subprocess
import elftools
import re
from elftools.elf.elffile import ELFFile

from libautoresolv.error import *
from collections import defaultdict

def get_seg(segname):
        for s in idautils.Segments():
            seg = idaapi.getseg(s)
            name = idc.get_segm_name(s)
            if name == segname:
                start = seg.start_ea
                end = seg.end_ea
                return start, end
        
        return None,None
        
def get_extern(s,e):
    external = {}
    funs = idautils.Functions(start = s, end=e)
    for ea in funs:
        px = ida_funcs.get_func_name(ea)
        flags = idc.get_func_flags(ea)
        if str(px).startswith("sub_"):
            continue
        if (flags & 0x80): #all external functions are wrapper -> jump OFFSET, so flags ISJUMP should be 1
            external[px] = ea
        
    return external

def get_funs(s,e):
    fun_list = {}
    funs = idautils.Functions(start = s, end=e)
    for ea in funs:
        fun_name = ida_funcs.get_func_name(ea)
        fun_list[fun_name] = ea
    return fun_list


def checkLibExist(newpath):
    return os.path.exists(newpath)

def getAllFunsFromLib(path, libc):

    if "Path not found" in path:
        print(f"[AutoResolv] Couldn't Open {path} because path is not given")
        return None
    if ("libc.so" in path):
        if (not libc):
            return None
  
    funs = []
    file = None
    try:
        file = open(path,"rb")
    except Exception:
        print(f"[AutoResolv] Couldn't Open {path}, Are you sure the path is correct?")
        return None

    elf = ELFFile(file)
    funs = []
    for seg in elffile.iter_segments():
        if seg.header['p_type'] == "PT_DYNAMIC":
            for symb in seg.iter_symbols():
                if symb.entry['st_shndx'] != 'SHN_UNDEF' and symb.entry['st_info']['type'] == 'STT_FUNC':
                    funs.append(symb.name)                    
    return funs
        
def getLibsFromBin(binary):
    print("[AutoResolv] Using readelf to parse binary info.")
    libs = {}
    rpath = None
    try:
        libs = {}
        fd = open(binary ,"rb")
        elf = ELFFile(fd)
        for seg in elf.iter_segments():
            if seg.header['p_type'] == "PT_DYNAMIC":
                for tag in seg.iter_tags():
                    if tag.entry['d_tag'] == "DT_NEEDED":
                        libs[tag.needed] = "Path not found"
                    if tag.entry['d_tag'] == "DT_RPATH" or tag.entry['d_tag'] == "DT_RUNPATH":
                        
                        try:
                            rpath = tag.rpath
                        except Exception:
                            rpath = tag.runpath

    except Exception as e:
        raise Exception("[AutoResolv] Couldn't open binary, Aborting !")
    for lib in libs:
        path_lib = "/usr/lib/" + lib
        _exist = os.path.exists(path_lib)
        if _exist:
            libs[lib] = path_lib

        path_lib =  "/lib/x86_64-linux-gnu/" + lib
        _exist = os.path.exists(path_lib)
        if _exist:
            libs[lib] = path_lib

    if rpath is not None:
        all_rpath = rpath.split(":")
        for rpath_ in all_rpath:
            dir = None
            try:
                dir = os.listdir(rpath_)
            except FileNotFoundError:
                print("[AutoResolv] RPATH dir not found on computer, you must enter librairies manually on AutoResolv")
                return libs, None

            for lib in dir:
                if not os.path.isdir(rpath_ + "/" + lib):
                    path_lib =  rpath_ + "/" + lib
                    _exist = os.path.exists(path_lib)
                    if _exist:
                        double = False
                        setTXZ = None
                        for libx in libs:
                            if (lib.split(".")[0] + ".so") in libx and libs[libx] != "Path not found": #remove double , libcustom.so.1 and libcustom.so.1.0.0
                                double=True
                            

                        if not double:
                            lib_formatted = lib
                            if len(lib.split(".")) > 3:
                                lib_formatted = ".".join(lib.split(".")[0:-2])
                            if lib_formatted in libs:
                                libs[lib_formatted] = path_lib

    return libs,rpath

def Resolve(externalfuns, libs,paths, config):
        resolved = defaultdict(list)
        for fun in externalfuns:
            resolved[fun] = [externalfuns[fun], "Unknow Library"]
        values = []

        #TODO : better algo search        
        for lib in libs:
            for fun in libs[lib]:
                for externalfun in externalfuns:
                    externalfun_ = externalfun
                    try:
                        externalfun_ = externalfun.split(".")[1] #remove the .FUN_NAME from wrapper format
                    except Exception:
                        pass
                    finally:
                        if externalfun_ == fun:
                            
                            if (not config['demangle']):
                                values.append([fun, lib, paths[lib]])
                                resolved[externalfun] = [externalfuns[externalfun], lib]
                            else:
                                demangled_name = idc.demangle_name(fun, idc.get_inf_attr(idc.INF_SHORT_DN))
                                if demangled_name == None:
                                    demangled_name = fun

                                values.append([fun, lib, paths[lib] ,demangled_name])
                                resolved[externalfun] = [externalfuns[externalfun], lib]
                        
        return values, resolved

def CommentFuns(external_resolved, config):
        
        fun_cpt=0
        xref_cpt = 0
        for fun in external_resolved:
            try:
                ea = external_resolved[fun][0]
                lib = external_resolved[fun][1]
                xrefs= idautils.XrefsTo(ea)
                if "Unknow Library" in lib:
                    continue
                idc.set_cmt(ea, lib, 1)
                fun_cpt += 1
                for xref in xrefs:
                    idc.set_cmt(xref.frm, lib, 1)
                    xref_cpt += 1
            except Exception:
                if config['verbose']:
                    print(f"[AutoResolv] Couldn't patch {fun}, Skipping")

        if config['verbose']:
            print(f"[AutoResolv] Patched {fun_cpt} functions and {xref_cpt} functions references")
            

def getSignature(values, config):
    
    s,e = get_seg(".text")
    all_funs = get_funs(s,e)
    
    allsigs = {}
    cpt = 0
    for i in range(len(values)):
        try:

            fun_name = values[i][0]
            lib = values[i][1]
            binary_name = idaapi.get_root_filename()

            if lib in binary_name: #check is not severe because binary_name can be libcustom.so.4.0.0 and libname = libcustom.so.4
                ea = all_funs[fun_name]
                signature = str(idaapi.decompile(ea)).split("\n")[0] + ";"
                allsigs[fun_name] = signature
                cpt += 1
        except Exception:
            if config['verbose']:
                print(f"[AutoResolv] Couldn't get signature from {fun_name}, Skipping")


    return cpt, allsigs

def refactorExtern(signature, config):
    s,e = get_seg(".plt")
    s2, e2 = get_seg(".plt.sec")
    all_funs1 = None
    if s is not None and e is not None:
        all_funs1 = get_extern(s,e)

    all_funs2 = None
    if s2 is not None and e2 is not None:
        all_funs2 = get_extern(s2,e2)

    all_funs = all_funs1 | all_funs2
    
    cpt = 0
    xref_cpt = 0
    for sig in signature:
        for fun in all_funs:

            try:
            
                fun = fun.split(".")[1] #wrapper are .fun_name
                if fun == sig:
                    call_type = signature[sig]
                    ea = all_funs["." + fun]
                    xrefs= idautils.XrefsTo(ea)
                    idc.SetType(ea, call_type)
                    for xref in xrefs:
                        idc.SetType(xref.frm, call_type)
                        xref_cpt += 1

                    cpt += 1
            except Exception:
                if config['verbose']:
                    print(f"[AutoResolv] Couldn't refactor {fun}, Skipping")

    return cpt,xref_cpt




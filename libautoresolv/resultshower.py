
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

#class for result print on IDA
class ResultShower(idaapi.Choose):
    def __init__(self, title, items, demangle=False, flags=0, width=None, height=None, embedded=False, modal=False):
        self.demangle = demangle
        if self.demangle:
            idaapi.Choose.__init__(
                self,
                title,
                [
                    ["Function Name", idaapi.Choose.CHCOL_PLAIN|50],
                    ["Library Name", idaapi.Choose.CHCOL_PLAIN|20],
                    ["Path", idaapi.Choose.CHCOL_PLAIN|20],
                    ["C++ Demangled Name", idaapi.Choose.CHCOL_PLAIN|20],

                ],
                flags=flags,
                width=width,
                height=height,
                embedded=embedded)

        else:
            idaapi.Choose.__init__(
                self,
                title,
                [
                    ["Function Name", idaapi.Choose.CHCOL_PLAIN|50],
                    ["Library Name", idaapi.Choose.CHCOL_PLAIN|20],
                    ["Path", idaapi.Choose.CHCOL_PLAIN|20],

                ],
                flags=flags,
                width=width,
                height=height,
                embedded=embedded)


        self.items = items
        self.selcount = 0
        self.n = len(items)

    def OnClose(self):
        return
        self.selcount += 1

    def OnSelectLine(self, n):
        pass

    def OnGetLine(self, n):
        res = self.items[n]
        if self.demangle:
            res =   [res[0], res[1], res[2], res[3]]
        else:
            res = [res[0], res[1], res[2]]
        return res

    def OnGetSize(self):
        n = len(self.items)
        return n

    def show(self):
        return self.Show() >= 0
        
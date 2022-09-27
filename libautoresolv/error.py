
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


class Error(Exception):
    pass

class ProjectBinaryNotFoundError(Error):
    def __init__(self, message="ERR_CRITICAL : idaapi.get_input_file_path() returned None -> Couldn't find the project binary ! Exiting"):
        self.message = message
        super().__init__(self.message)

class CacheSaveResolvedDataError(Error):
    def __init__(self, message="ERR_CRITICAL : Saving Resolved Data to cache failed"):
        self.message = message
        super().__init__(self.message)

class CacheCleanDataTable(Error):
    def __init__(self, message="ERR_CRITICAL : Cleaning data of previous data table failed"):
        self.message = message
        super().__init__(self.message)
        

class ProjectRootBinaryNotFoundError(Error):
    def __init__(self, message="ERR_CRITICAL : idaapi.get_root_filename() returned None -> Couldn't find the root project binary ! Exiting"):
        self.message = message
        super().__init__(self.message)

class ProjectBinaryParsingLibErrror(Error):
    def __init__(self, message="ERR_CRITICAL : Parsing of librairies failed."):
        self.message = message
        super().__init__(self.message)

class CacheBaseCreationError(Error):
    def __init__(self, message="ERR_CRITICAL : Creation of table in DB cache failed"):
        self.message = message
        super().__init__(self.message)

class CacheBaseSetup(Error):
    def __init__(self, message="ERR_CRITICAL : Setup of required information for AutoResolv in DB Cache failed"):
        self.message = message
        super().__init__(self.message)

class CacheParseConfigError(Error):
    def __init__(self, message="ERR_CRITICAL : Parsing of old configuration failed"):
        self.message = message
        super().__init__(self.message)

class CacheParseLibDataError(Error):
    def __init__(self, message="ERR_CRITICAL : Parsing of old libraries data failed"):
        self.message = message
        super().__init__(self.message)
    
class CacheUpdateConfigurationError(Error):
    def __init__(self, message="ERR_CRITICAL : Update of Cache Configuration failed"):
        self.message = message
        super().__init__(self.message)

class IdaGetSegPLTError(Error):
    def __init__(self, message="ERR_CRITICAL : Can't gather .PLT segment adress. Resolving can't be done"):
        self.message = message
        super().__init__(self.message)

class IdaGetFunsError(Error):
    def __init__(self, message="ERR_CRITICAL : Retreived 0 function from .PLT ! Resolving can't be done"):
        self.message = message
        super().__init__(self.message)
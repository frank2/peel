#!/usr/bin/env python

from paranoia.base.abstract.array import Array
from paranoia.types.structure import Structure

from peel.types.rva import RVA32
from peel.types.typedefs import *

class DataDirectory(Structure.simple([
        ('VirtualAddress', RVA32)
        ,('Size', DWORD)])):
    pass

DataDirectoryArray = Array.static_declaration(base_class=DataDirectory)

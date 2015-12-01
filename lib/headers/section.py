#!/usr/bin/env python

from paranoia.base.abstract.array import Array
from paranoia.types.structure import Structure
from paranoia.types.union import Union

from peel.types.offset import Offset32
from peel.types.rva import RVA32
from peel.types.typedefs import *

class SectionHeader(Structure.simple([
        ('Name', BYTE_ARRAY.static_declaration(elements=8))
        ,('Misc', Union.simple([
            ('PhysicalAddress', Offset32)
            ,('VirtualSize', DWORD)]))
        ,('VirtualAddress', RVA32)
        ,('SizeOfRawData', DWORD)
        ,('PointerToRawData', Offset32)
        ,('PointerToRelocations', Offset32)
        ,('PointerToLinenumbers', Offset32)
        ,('NumberOfRelocations', WORD)
        ,('NumberOfLinenumbers', WORD)
        ,('Characteristics', DWORD)])):
    pass

class SectionTable(Array):
    BASE_CLASS = SectionHeader

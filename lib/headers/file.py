#!/usr/bin/env python

from paranoia.types.structure import Structure

from peel.types.offset import Offset32
from peel.types.typedefs import *

class FileHeader(Structure.simple([
        ('Machine', WORD)
        ,('NumberOfSections', WORD)
        ,('TimeDateStamp', DWORD)
        ,('PointerToSymbolTable', Offset32)
        ,('NumberOfSymbols', DWORD)
        ,('SizeOfOptionalHeader', WORD)
        ,('Characteristics', WORD)])):
    pass

IMAGE_FILE_HEADER = FileHeader

#!/usr/bin/env python

from paranoia.types.structure import Structure

from peel.headers.directory.data import DataDirectoryArray
from peel.types.rva import RVA32
from peel.types.typedefs import *

class OptionalHeader32(Structure.simple([
        ('Magic', WORD)
        ,('MajorLinkerVersion', BYTE)
        ,('MinorLinkerVersion', BYTE)
        ,('SizeOfCode', DWORD)
        ,('SizeOfInitializedData', DWORD)
        ,('SizeOfUninitializedData', DWORD)
        ,('AddressOfEntryPoint', RVA32)
        ,('BaseOfCode', DWORD)
        ,('BaseOfData', DWORD)
        ,('ImageBase', DWORD)
        ,('SectionAlignment', DWORD)
        ,('FileAlignment', DWORD)
        ,('MajorOperatingSystemVersion', WORD)
        ,('MinorOperatingSystemVersion', WORD)
        ,('MajorImageVersion', WORD)
        ,('MinorImageVersion', WORD)
        ,('MajorSubsystemVersion', WORD)
        ,('MinorSubsystemVersion', WORD)
        ,('Win32VersionValue', DWORD)
        ,('SizeOfImage', DWORD)
        ,('SizeOfHeaders', DWORD)
        ,('Checksum', DWORD)
        ,('Subsystem', WORD)
        ,('DllCharacteristics', WORD)
        ,('SizeOfStackReserve', DWORD)
        ,('SizeOfStackCommit', DWORD)
        ,('SizeOfHeapReserve', DWORD)
        ,('SizeOfHeapCommit', DWORD)
        ,('LoaderFlags', DWORD)
        ,('NumberOfRvaAndSizes', DWORD)
        ,('DataDirectory', DataDirectoryArray.static_declaration(elements=16))])):
    pass

class OptionalHeader64(Structure.simple([
        ('Magic', WORD)
        ,('MajorLinkerVersion', BYTE)
        ,('MinorLinkerVersion', BYTE)
        ,('SizeOfCode', DWORD)
        ,('SizeOfInitializedData', DWORD)
        ,('SizeOfUninitializedData', DWORD)
        ,('AddressOfEntryPoint', RVA32)
        ,('BaseOfCode', DWORD)
        ,('BaseOfData', DWORD)
        ,('ImageBase', QWORD)
        ,('SectionAlignment', DWORD)
        ,('FileAlignment', DWORD)
        ,('MajorOperatingSystemVersion', WORD)
        ,('MinorOperatingSystemVersion', WORD)
        ,('MajorImageVersion', WORD)
        ,('MinorImageVersion', WORD)
        ,('MajorSubsystemVersion', WORD)
        ,('MinorSubsystemVersion', WORD)
        ,('Win32VersionValue', DWORD)
        ,('SizeOfImage', DWORD)
        ,('SizeOfHeaders', DWORD)
        ,('Checksum', DWORD)
        ,('Subsystem', WORD)
        ,('DllCharacteristics', WORD)
        ,('SizeOfStackReserve', QWORD)
        ,('SizeOfStackCommit', QWORD)
        ,('SizeOfHeapReserve', QWORD)
        ,('SizeOfHeapCommit', QWORD)
        ,('LoaderFlags', DWORD)
        ,('NumberOfRvaAndSizes', DWORD)
        ,('DataDirectory', DataDirectoryArray.static_declaration(elements=16))])):
    pass

IMAGE_OPTIONAL_HEADER32 = OptionalHeader32
IMAGE_OPTIONAL_HEADER64 = OptionalHeader64

#!/usr/bin/env python

from paranoia.types.structure import Structure

from peel.headers.file import FileHeader
from peel.headers.optional import OptionalHeader32, OptionalHeader64
from peel.types.typedefs import *

class NTHeader32(Structure.simple([
        ('Signature', DWORD)
        ,('FileHeader', FileHeader)
        ,('OptionalHeader', OptionalHeader32)])):
    pass

class NTHeader64(Structure.simple([
        ('Signature', DWORD)
        ,('FileHeader', FileHeader)
        ,('OptionalHeader', OptionalHeader64)])):
    pass

IMAGE_NT_HEADERS32 = NTHeader32
IMAGE_NT_HEADERS64 = NTHeader64

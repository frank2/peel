#!/usr/bin/env python

from paranoia.base.abstract.structure import Structure

from .win32 import *

class FileHeader(Structure.simple([
    ('Machine',              WORD),
    ('NumberOfSections',     WORD),
    ('TimeDateStamp',        DWORD),
    ('PointerToSymbolTable', DWORD),
    ('NumberOfSymbols',      DWORD),
    ('SizeOfOptionalHeader', WORD),
    ('Characteristics',      WORD)])):

   def __init__(self, **kwargs):
      Structure.__init__(self, **kwargs)

      if kwargs.setdefault('set_defaults',0):
         self.set_defaults()

   def set_defaults(self):
      self.Machine.set_value(IMAGE_FILE_MACHINE_I386) 
      self.TimeDateStamp.set_value(int(time.time()))
      self.SizeOfOptionalHeader.set_value(sizeof(OptionalHeader32)+(sizeof(DataDirectory)*16))
      self.Characteristics.set_value(IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE)

IMAGE_FILE_HEADER = FileHeader

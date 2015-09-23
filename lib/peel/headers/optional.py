#!/usr/bin/env python

from paranoia.base.abstract.structure import Structure
from .win32 import *

class OptionalHeader32(Structure.simple([
   ('Magic',                         WORD)
   ,('MajorLinkerVersion',            BYTE)
   ,('MinorLinkerVersion',            BYTE)
   ,('SizeOfCode',                    DWORD)
   ,('SizeOfInitializedData',         DWORD)
   ,('SizeOfUninitializedData',       DWORD)
   ,('AddressOfEntryPoint',           DWORD)
   ,('BaseOfCode',                    DWORD)
   ,('BaseOfData',                    DWORD)
   ,('ImageBase',                     DWORD)
   ,('SectionAlignment',              DWORD)
   ,('FileAlignment',                 DWORD)
   ,('MajorOperatingSystemVersion',   WORD)
   ,('MinorOperatingSystemVersion',   WORD)
   ,('MajorImageVersion',             WORD)
   ,('MinorImageVersion',             WORD)
   ,('MajorSubsystemVersion',         WORD)
   ,('MinorSubsystemVersion',         WORD)
   ,('Win32VersionValue',             DWORD)
   ,('SizeOfImage',                   DWORD)
   ,('SizeOfHeaders',                 DWORD)
   ,('CheckSum',                      DWORD)
   ,('Subsystem',                     WORD)
   ,('DllCharacteristics',            WORD)
   ,('SizeOfStackReserve',            DWORD)
   ,('SizeOfStackCommit',             DWORD)
   ,('SizeOfHeapReserve',             DWORD)
   ,('SizeOfHeapCommit',              DWORD)
   ,('LoaderFlags',                   DWORD)
   ,('NumberOfRvaAndSizes',           DWORD)])):

   def __init__(self, **kwargs):
      Structure.__init__(self, **kwargs)

      if kwargs.setdefault('set_defaults',0):
         self.set_defaults()

   def set_defaults(self):
      self.Magic.set_value(IMAGE_NT_OPTIONAL_HDR32_MAGIC)
      self.MajorLinkerVersion.set_value(9)
      self.AddressOfEntryPoint.set_value(0x1000)
      self.BaseOfCode.set_value(0x1000)
      self.ImageBase.set_value(0x400000)
      self.SectionAlignment.set_value(0x1000)
      self.FileAlignment.set_value(0x200)
      self.MajorOperatingSystemVersion.set_value(4)
      self.MinorOperatingSystemVersion.set_value(0)
      self.MajorImageVersion.set_value(4)
      self.MinorImageVersion.set_value(0)
      self.MajorSubsystemVersion.set_value(4)
      self.MinorSubsystemVersion.set_value(0)
      self.Subsystem.set_value(IMAGE_SUBSYSTEM_WINDOWS_GUI)
      self.DllCharacteristics.set_value(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)
      self.SizeOfStackReserve.set_value(0x40000)
      self.SizeOfStackCommit.set_value(0x2000)
      self.SizeOfHeapReserve.set_value(0x100000)
      self.SizeOfHeapCommit.set_value(0x1000)
      self.NumberOfRvaAndSizes.set_value(0x10)

IMAGE_OPTIONAL_HEADER32 = OptionalHeader32

class OptionalHeader64(Structure.simple([
   ('Magic',                         WORD)
   ,('MajorLinkerVersion',            BYTE)
   ,('MinorLinkerVersion',            BYTE)
   ,('SizeOfCode',                    DWORD)
   ,('SizeOfInitializedData',         DWORD)
   ,('SizeOfUninitializedData',       DWORD)
   ,('AddressOfEntryPoint',           DWORD)
   ,('BaseOfCode',                    DWORD)
   ,('ImageBase',                     QWORD)
   ,('SectionAlignment',              DWORD)
   ,('FileAlignment',                 DWORD)
   ,('MajorOperatingSystemVersion',   WORD)
   ,('MinorOperatingSystemVersion',   WORD)
   ,('MajorImageVersion',             WORD)
   ,('MinorImageVersion',             WORD)
   ,('MajorSubsystemVersion',         WORD)
   ,('MinorSubsystemVersion',         WORD)
   ,('Win32VersionValue',             DWORD)
   ,('SizeOfImage',                   DWORD)
   ,('SizeOfHeaders',                 DWORD)
   ,('CheckSum',                      DWORD)
   ,('Subsystem',                     WORD)
   ,('DllCharacteristics',            WORD)
   ,('SizeOfStackReserve',            QWORD)
   ,('SizeOfStackCommit',             QWORD)
   ,('SizeOfHeapReserve',             QWORD)
   ,('SizeOfHeapCommit',              QWORD)
   ,('LoaderFlags',                   DWORD)
   ,('NumberOfRvaAndSizes',           DWORD)])):

   def __init__(self, **kwargs):
      Structure.__init__(self, **kwargs)

      if kwargs.setdefault('set_defaults',0):
         self.set_defaults()

   def set_defaults(self):
      self.Magic.set_value(IMAGE_NT_OPTIONAL_HDR64_MAGIC)
      self.MajorLinkerVersion.set_value(9)
      self.AddressOfEntryPoint.set_value(0x1000)
      self.BaseOfCode.set_value(0x1000)
      self.ImageBase.set_value(0x100000000)
      self.SectionAlignment.set_value(0x1000)
      self.FileAlignment.set_value(0x200)
      self.MajorOperatingSystemVersion.set_value(4)
      self.MinorOperatingSystemVersion.set_value(0)
      self.MajorImageVersion.set_value(4)
      self.MinorImageVersion.set_value(0)
      self.MajorSubsystemVersion.set_value(4)
      self.MinorSubsystemVersion.set_value(0)
      self.Subsystem.set_value(IMAGE_SUBSYSTEM_WINDOWS_GUI)
      self.DllCharacteristics.set_value(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)
      self.SizeOfStackReserve.set_value(0x40000)
      self.SizeOfStackCommit.set_value(0x2000)
      self.SizeOfHeapReserve.set_value(0x100000)
      self.SizeOfHeapCommit.set_value(0x1000)
      self.NumberOfRvaAndSizes.set_value(0x10)

IMAGE_OPTIONAL_HEADER64 = OptionalHeader64

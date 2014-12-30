#!C:/Python27/python.exe

#                                                            lllllll
#                                                            l:::::l
#                                                            l:::::l
#                                                            l:::::l
# ppppp   ppppppppp       eeeeeeeeeeee        eeeeeeeeeeee    l::::l
# p::::ppp:::::::::p    ee::::::::::::ee    ee::::::::::::ee  l::::l
# p:::::::::::::::::p  e::::::eeeee:::::ee e::::::eeeee:::::eel::::l
# pp::::::ppppp::::::pe::::::e     e:::::ee::::::e     e:::::el::::l
#  p:::::p     p:::::pe:::::::eeeee::::::ee:::::::eeeee::::::el::::l
#  p:::::p     p:::::pe:::::::::::::::::e e:::::::::::::::::e l::::l
#  p:::::p     p:::::pe::::::eeeeeeeeeee  e::::::eeeeeeeeeee  l::::l
#  p:::::p    p::::::pe:::::::e           e:::::::e           l::::l
#  p:::::ppppp:::::::pe::::::::e          e::::::::e         l::::::l
#  p::::::::::::::::p  e::::::::eeeeeeee   e::::::::eeeeeeee l::::::l
#  p::::::::::::::pp    ee:::::::::::::e    ee:::::::::::::e l::::::l
#  p::::::pppppppp        eeeeeeeeeeeeee      eeeeeeeeeeeeee llllllll
#  p:::::p
#  p:::::p
# p:::::::p              - the PE executable library! -
# p:::::::p       
# p:::::::p              (redunant like an ATM machine!)
# ppppppppp
#
# Copyright (C) 2011-2013, frank2 <frank2 [!] dc949 [:] org>
#
# Originally called "pestuff," PEEL is here to help you deal with PE files!
# Reading, writing-- whatever! It's all good!
#
# License pending. Open-source licensing is a clusterfuck. I dunno what I wanna
# do just yet. :(
#
# Thanks to Ero Carrera's pefile for a lot of guidance on how to properly parse
# PE files without getting bitten in the ass by malware! 
# http://code.google.com/p/pefile/
#
# Also thanks to Alexander Sotirov's TinyPE research for helping with curious
# quirks of PE files. 
# http://www.phreedom.org/research/tinype/
#
# Finally, thanks to the Corkami project for providing an exhaustive PE corpus
# of extremely odd quirks and other interesting PE file oddities for testing.
# http://code.google.com/p/corkami/

import binascii
import code
import ctypes
import hashlib
import math
import mmap
import os
import random
import re
import struct
import subprocess
import sys
import tempfile
import time
import zlib

# TODO add "set_$attr" functions where get/parse exist (mostly just for 
# TODO cleaner-looking code)

###############################################################################
## PE defines
###############################################################################

try:
   VirtualProtect = ctypes.windll.kernel32.VirtualProtect
   GetProcAddress = ctypes.windll.kernel32.GetProcAddress
   LoadLibraryA = ctypes.windll.kernel32.LoadLibraryA
   LoadLibraryW = ctypes.windll.kernel32.LoadLibraryW
   GetLastError = ctypes.windll.kernel32.GetLastError
   GetModuleHandleW = ctypes.windll.kernel32.GetModuleHandleW
   AddVectoredExceptionHandler = ctypes.windll.kernel32.AddVectoredExceptionHandler
   RemoveVectoredExceptionHandler = ctypes.windll.kernel32.RemoveVectoredExceptionHandler
   ExpandEnvironmentStringsA = ctypes.windll.kernel32.ExpandEnvironmentStringsA

   WIN32_COMPATIBLE = 1

   import ctypes.wintypes
except AttributeError:
   VirtualProtect = None
   GetProcAddress = None
   LoadLibraryA = None
   LoadLibraryW = None
   GetLastError = None
   GetModuleHandleW = None
   AddVectoredExceptionHandler = None
   RemoveVectoredExceptionHandler = None
   ExpandEnvironmentStringsA = None

   WIN32_COMPATIBLE = 0

# Various image signatures
IMAGE_DOS_SIGNATURE    = 0x5A4D    
IMAGE_OS2_SIGNATURE    = 0x454E    
IMAGE_OS2_SIGNATURE_LE = 0x454C    
IMAGE_VXD_SIGNATURE    = 0x454C    
IMAGE_NT_SIGNATURE     = 0x00004550
                                    
# Characteristics flags for IMAGE_FILE_HEADER.Characteristics
IMAGE_FILE_RELOCS_STRIPPED          = 0x0001
IMAGE_FILE_EXECUTABLE_IMAGE         = 0x0002
IMAGE_FILE_LINE_NUMS_STRIPPED       = 0x0004
IMAGE_FILE_LOCAL_SYMS_STRIPPED      = 0x0008
IMAGE_FILE_AGGRESIVE_WS_TRIM        = 0x0010
IMAGE_FILE_LARGE_ADDRESS_AWARE      = 0x0020
IMAGE_FILE_16BIT_MACHINE            = 0x0040
IMAGE_FILE_BYTES_REVERSED_LO        = 0x0080
IMAGE_FILE_32BIT_MACHINE            = 0x0100
IMAGE_FILE_DEBUG_STRIPPED           = 0x0200
IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP  = 0x0400
IMAGE_FILE_NET_RUN_FROM_SWAP        = 0x0800
IMAGE_FILE_SYSTEM                   = 0x1000
IMAGE_FILE_DLL                      = 0x2000
IMAGE_FILE_UP_SYSTEM_ONLY           = 0x4000
IMAGE_FILE_BYTES_REVERSED_HI        = 0x8000

# Characteristics flags for IMAGE_SECTION_HEADER.Characteristics
IMAGE_SCN_CNT_CODE =               0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA =   0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_LNK_OTHER =              0x00000100
IMAGE_SCN_LNK_INFO =               0x00000200
IMAGE_SCN_LNK_REMOVE =             0x00000800
IMAGE_SCN_LNK_COMDAT =             0x00001000
IMAGE_SCN_MEM_FARDATA =            0x00008000
IMAGE_SCN_MEM_PURGEABLE =          0x00020000
IMAGE_SCN_MEM_16BIT =              0x00020000
IMAGE_SCN_MEM_LOCKED =             0x00040000
IMAGE_SCN_MEM_PRELOAD =            0x00080000
IMAGE_SCN_ALIGN_1BYTES =           0x00100000
IMAGE_SCN_ALIGN_2BYTES =           0x00200000
IMAGE_SCN_ALIGN_4BYTES =           0x00300000
IMAGE_SCN_ALIGN_8BYTES =           0x00400000
IMAGE_SCN_ALIGN_16BYTES =          0x00500000
IMAGE_SCN_ALIGN_32BYTES =          0x00600000
IMAGE_SCN_ALIGN_64BYTES =          0x00700000
IMAGE_SCN_ALIGN_128BYTES =         0x00800000
IMAGE_SCN_ALIGN_256BYTES =         0x00900000
IMAGE_SCN_ALIGN_512BYTES =         0x00A00000
IMAGE_SCN_ALIGN_1024BYTES =        0x00B00000
IMAGE_SCN_ALIGN_2048BYTES =        0x00C00000
IMAGE_SCN_ALIGN_4096BYTES =        0x00D00000
IMAGE_SCN_ALIGN_8192BYTES =        0x00E00000
IMAGE_SCN_ALIGN_MASK =             0x00F00000
IMAGE_SCN_LNK_NRELOC_OVFL =        0x01000000
IMAGE_SCN_MEM_DISCARDABLE =        0x02000000
IMAGE_SCN_MEM_NOT_CACHED =         0x04000000
IMAGE_SCN_MEM_NOT_PAGED =          0x08000000
IMAGE_SCN_MEM_SHARED =             0x10000000
IMAGE_SCN_MEM_EXECUTE =            0x20000000
IMAGE_SCN_MEM_READ =               0x40000000
IMAGE_SCN_MEM_WRITE =              0x80000000

# defines for FileHeader.Machine
IMAGE_FILE_MACHINE_UNKNOWN    = 0
IMAGE_FILE_MACHINE_I860       = 0x014d
IMAGE_FILE_MACHINE_I386       = 0x014c
IMAGE_FILE_MACHINE_R3000      = 0x0162
IMAGE_FILE_MACHINE_R4000      = 0x0166
IMAGE_FILE_MACHINE_R10000     = 0x0168
IMAGE_FILE_MACHINE_WCEMIPSV2  = 0x0169
IMAGE_FILE_MACHINE_ALPHA      = 0x0184
IMAGE_FILE_MACHINE_SH3        = 0x01a2
IMAGE_FILE_MACHINE_SH3DSP     = 0x01a3
IMAGE_FILE_MACHINE_SH3E       = 0x01a4
IMAGE_FILE_MACHINE_SH4        = 0x01a6
IMAGE_FILE_MACHINE_SH5        = 0x01a8
IMAGE_FILE_MACHINE_ARM        = 0x01c0
IMAGE_FILE_MACHINE_THUMB      = 0x01c2
IMAGE_FILE_MACHINE_ARMV7      = 0x01c4
IMAGE_FILE_MACHINE_AM33       = 0x01d3
IMAGE_FILE_MACHINE_POWERPC    = 0x01f0
IMAGE_FILE_MACHINE_POWERPCFP  = 0x01f1
IMAGE_FILE_MACHINE_IA64       = 0x0200
IMAGE_FILE_MACHINE_MIPS16     = 0x0266
IMAGE_FILE_MACHINE_ALPHA64    = 0x0284
IMAGE_FILE_MACHINE_MIPSFPU    = 0x0366
IMAGE_FILE_MACHINE_MIPSFPU16  = 0x0466
IMAGE_FILE_MACHINE_AXP64      = IMAGE_FILE_MACHINE_ALPHA64
IMAGE_FILE_MACHINE_TRICORE    = 0x0520
IMAGE_FILE_MACHINE_CEF        = 0x0cef
IMAGE_FILE_MACHINE_EBC        = 0x0ebc
IMAGE_FILE_MACHINE_AMD64      = 0x8664
IMAGE_FILE_MACHINE_M32R       = 0x9041
IMAGE_FILE_MACHINE_CEE        = 0xc0ee

# from Wine
IMAGE_FILE_MACHINE_SPARC      = 0x2000

# Magic values
IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B
IMAGE_ROM_OPTIONAL_HDR_MAGIC  = 0x107

# DataDirectory indices
IMAGE_DIRECTORY_ENTRY_EXPORT         = 0
IMAGE_DIRECTORY_ENTRY_IMPORT         = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE       = 2
IMAGE_DIRECTORY_ENTRY_EXCEPTION      = 3
IMAGE_DIRECTORY_ENTRY_SECURITY       = 4
IMAGE_DIRECTORY_ENTRY_BASERELOC      = 5
IMAGE_DIRECTORY_ENTRY_DEBUG          = 6
IMAGE_DIRECTORY_ENTRY_COPYRIGHT      = 7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR      = 8
IMAGE_DIRECTORY_ENTRY_TLS            = 9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    = 10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   = 11
IMAGE_DIRECTORY_ENTRY_IAT            = 12
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   = 13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14

# DLL Characteristics
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE          = 0x0040
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY       = 0x0080
IMAGE_DLLCHARACTERISTICS_NX_COMPAT             = 0x0100
IMAGE_DLLCHARACTERISTICS_NO_ISOLATION          = 0x0200
IMAGE_DLLCHARACTERISTICS_NO_SEH                = 0x0400
IMAGE_DLLCHARACTERISTICS_NO_BIND               = 0x0800
IMAGE_DLLCHARACTERISTICS_WDM_DRIVER            = 0x2000
IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000

# Subsystems
IMAGE_SUBSYSTEM_UNKNOWN                    = 0
IMAGE_SUBSYSTEM_NATIVE                     = 1
IMAGE_SUBSYSTEM_WINDOWS_GUI                = 2
IMAGE_SUBSYSTEM_WINDOWS_CUI                = 3
IMAGE_SUBSYSTEM_OS2_CUI                    = 5
IMAGE_SUBSYSTEM_POSIX_CUI                  = 7
IMAGE_SUBSYSTEM_NATIVE_WINDOWS             = 8
IMAGE_SUBSYSTEM_WINDOWS_CE_GUI             = 9
IMAGE_SUBSYSTEM_EFI_APPLICATION            = 10
IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER    = 11
IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER         = 12
IMAGE_SUBSYSTEM_EFI_ROM                    = 13
IMAGE_SUBSYSTEM_XBOX                       = 14
IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION   = 16

# Context record constants
SIZE_OF_80387_REGISTERS =     80
MAXIMUM_SUPPORTED_EXTENSION = 512

###############################################################################
## Debug stuff
###############################################################################

# debug logging verbosity (set_verbosity() to adjust)
VERBOSITY = 0

# some names for fancypants debugging
MILD_VERBOSITY = 1
MEDIUM_VERBOSITY = 2
SPICY_VERBOSITY = 3
XTREME_VERBOSITY = 4

def set_verbosity(verbosity):
   global VERBOSITY
   VERBOSITY = verbosity

def no_verbosity():
   return set_verbosity(0)

def mild_verbosity():
   return set_verbosity(MILD_VERBOSITY)

def medium_verbosity():
   return set_verbosity(MEDIUM_VERBOSITY)

def spicy_verbosity():
   return set_verbosity(SPICY_VERBOSITY)

def xtreme_verbosity():
   return set_verbosity(XTREME_VERBOSITY)

def is_mild():
   return get_verbosity() >= MILD_VERBOSITY

def is_medium():
   return get_verbosity() >= MEDIUM_VERBOSITY

def is_spicy():
   return get_verbosity() >= SPICY_VERBOSITY

def is_xtreme():
   return get_verbosity() >= XTREME_VERBOSITY

def get_verbosity(): # so we don't have to type "global VERBOSITY" everywhere
   global VERBOSITY
   return VERBOSITY

def DEBUG(level, fmt, *args):
   if level > get_verbosity():
      return

   return sys.stderr.write('[%.3f] [DEBUG=%d] %s\n' % (time.time(),level,fmt % tuple(args)))

def DBG1(fmt, *args):
   return DEBUG(1, fmt, *args)

def DBG2(fmt, *args):
   return DEBUG(2, fmt, *args)

def DBG3(fmt, *args):
   return DEBUG(3, fmt, *args)

def DBG4(fmt, *args):
   return DEBUG(4, fmt, *args)

###############################################################################
## Generic error stub just to have all the errors organized
###############################################################################
class PEELError(Exception):
   pass

###############################################################################
## Address data
###############################################################################
class AddressError(PEELError): # TODO some contextual stuff
   pass

class HeaderError(PEELError):
   pass

# TODO this class should really get cleaned up a bit. it just feels gross.
class Address:
   VALUE_VA =     0x0
   VALUE_RVA =    0x1
   VALUE_OFFSET = 0x2
   VALUE_PVA =    0x4
   VALUES = ['va','rva','offset','pva']
   INVALID_ADDRESS = -1

   def __init__(self, image, value, value_type):
      self.image = image
      self._value = int(value)

      if value_type > len(Address.VALUES) or value_type < 0:
         raise TypeError('bad value type')

      self._value_type = value_type

      if self._value_type == Address.VALUE_VA:
         self._va = self._value
         self._offset = Address.INVALID_ADDRESS
         self._rva = Address.INVALID_ADDRESS
      elif self._value_type == Address.VALUE_RVA:
         self._rva = self._value
         self._va = Address.INVALID_ADDRESS
         self._offset = Address.INVALID_ADDRESS
      elif self._value_type == Address.VALUE_OFFSET:
         self._offset = self._value
         self._va = Address.INVALID_ADDRESS
         self._rva = Address.INVALID_ADDRESS

   def rva(self):
      if self._rva == Address.INVALID_ADDRESS:
         self._rva = self.get_rva()

      return self._rva

   def va(self):
      if self._va == Address.INVALID_ADDRESS:
         self._va = self.get_va()

      return self._va

   def offset(self):
      if self._offset == Address.INVALID_ADDRESS:
         self._offset = self.get_offset()

      return self._offset

   # FIXME make PVAs an actual thing down the road.
   def pva(self):
      return self.rva() + self.image.virtual_base() 

   def get_rva(self):
      if self.is_null():
         return 0

      if self._value_type == Address.VALUE_RVA:
         return self._value
      elif self._value_type == Address.VALUE_VA:
         return self.image.va_to_rva(self._value)
      else:
         return self.image.offset_to_rva(self._value)

   def get_va(self):
      if self.is_null():
         return 0

      if self._value_type == Address.VALUE_RVA:
         return self.image.rva_to_va(self._value)
      elif self._value_type == Address.VALUE_VA:
         return self._value
      else:
         return self.image.offset_to_va(self._value)

   def get_offset(self):
      if self.is_null():
         return 0

      if self._value_type == Address.VALUE_RVA:
         return self.image.rva_to_offset(self._value)
      elif self._value_type == Address.VALUE_VA:
         return self.image.va_to_offset(self._value)
      else:
         return self._value

   def as_rva(self):
      rva = self.rva()
      return self.image.rva(rva)

   def as_va(self):
      va = self.va()
      return self.image.va(va)

   def as_offset(self):
      offset = self.offset()
      return self.image.offset(offset)

   def valid_rva(self):
      # an rva can be null and valid
      if self.is_null():
         return 1

      if not self._rva == Address.INVALID_ADDRESS:
         value_check = self._rva
      else:
         try:
            value_check = self.rva()
         except (AddressError, HeaderError),e:
            DBG3("got error converting value: %s", str(e))
            return 0

      if self.image.has_virtual_image():
         return 0 < value_check < self.image.virtual_length()
      elif self.image.has_optional_header():
         size = int(self.image.IMAGE_OPTIONAL_HEADER.SizeOfImage)
         return 0 < value_check < size 
      else:
         raise ImageError("attempting to verify validity of an rva via SizeOfImage without an optional header present. see PEImage.section_by_offset as to why this error was raised.")

   def valid_va(self):
      optional = self.image.IMAGE_OPTIONAL_HEADER
      size = int(optional.SizeOfImage)
      base = int(optional.ImageBase)

      # a va can be null and valid only if the image base is zero
      if self.is_null() and size:
         return 0

      if not self._va == Address.INVALID_ADDRESS:
         value_check = self._va
      else:
         try:
            value_check = self.va()
         except (AddressError, HeaderError),e:
            DBG3("got error checking VA validity: %s", repr(e))
            return 0

      return base < value_check < (size+base)

   def valid_offset(self):
      # an offset can be null and valid
      if self.is_null():
         return 1

      if not self._offset == Address.INVALID_ADDRESS:
         value_check = self._offset
      else:
         try:
            value_check = self.offset()
         except (AddressError, HeaderError),e:
            DBG3("got error checking offset validity: %s", repr(e))
            return 0

      size = len(self.image)
      return 0 < value_check < size

   def null(self):
      return self.image.null()

   def copy(self): # just something to look more pretty.
      return self.address()

   def address(self):
      new_addr = Address(self.image, self._value, self._value_type)
      new_addr._offset = self._offset
      new_addr._rva = self._rva
      new_addr._va = self._va
      
      return new_addr

   def is_null(self):
      return self._value == 0

   def is_orphan(self):
      return self.image == None

   def unpack_qword(self, signed=0):
      return self.image.unpack_qword(self, signed)

   def unpack_qword_raw(self, signed=0):
      return self.image.unpack_qword_raw(self, signed)

   def unpack_qword_virtual(self, signed=0):
      return self.image.unpack_qword_virtual(self, signed)

   def unpack_qwords(self, qwords, signed=0):
      return self.image.unpack_qwords(self, qwords, signed)

   def unpack_qwords_raw(self, qwords_raw, signed=0):
      return self.image.unpack_qwords_raw(self, qwords_raw, signed)

   def unpack_qwords_virtual(self, qwords_virtual, signed=0):
      return self.image.unpack_qwords_virtual(self, qwords_virtual, signed)

   def unpack_dword(self, signed=0):
      return self.image.unpack_dword(self, signed)

   def unpack_dword_raw(self, signed=0):
      return self.image.unpack_dword_raw(self, signed)

   def unpack_dword_virtual(self, signed=0):
      return self.image.unpack_dword_virtual(self, signed)

   def unpack_dwords(self, dwords, signed=0):
      return self.image.unpack_dwords(self, dwords, signed)

   def unpack_dwords_raw(self, dwords_raw, signed=0):
      return self.image.unpack_dwords_raw(self, dwords_raw, signed)

   def unpack_dwords_virtual(self, dwords_virtual, signed=0):
      return self.image.unpack_dwords_virtual(self, dwords_virtual, signed)

   def unpack_word(self, signed=0):
      return self.image.unpack_word(self, signed)

   def unpack_word_raw(self, signed=0):
      return self.image.unpack_word_raw(self, signed)

   def unpack_word_virtual(self, signed=0):
      return self.image.unpack_word_virtual(self, signed)

   def unpack_words(self, words, signed=0):
      return self.image.unpack_words(self, words, signed)

   def unpack_words_raw(self, words_raw, signed=0):
      return self.image.unpack_words_raw(self, words_raw, signed)

   def unpack_words_virtual(self, words_virtual, signed=0):
      return self.image.unpack_words_virtual(self, words_virtual, signed)

   def unpack_byte(self, signed=0):
      return self.image.unpack_byte(self, signed)

   def unpack_byte_raw(self, signed=0):
      return self.image.unpack_byte_raw(self, signed)

   def unpack_byte_virtual(self, signed=0):
      return self.image.unpack_byte_virtual(self, signed)

   def unpack_bytes(self, bytecount, signed=0):
      return self.image.unpack_bytes(self, bytecount, signed)

   def unpack_bytes_raw(self, bytes_raw, signed=0):
      return self.image.unpack_bytes_raw(self, bytes_raw, signed)

   def unpack_bytes_virtual(self, bytes_virtual, signed=0):
      return self.image.unpack_bytes_virtual(self, bytes_virtual, signed)

   def unpack_string_limit(self, limit):
      return self.image.unpack_string_limit(self, limit)

   def unpack_string_limit_raw(self, limit_raw):
      return self.image.unpack_string_limit_raw(self, limit_raw)

   def unpack_string_limit_virtual(self, limit_virtual):
      return self.image.unpack_string_limit_virtual(self, limit_virtual)

   def unpack_string(self):
      return self.image.unpack_string(self)

   def unpack_string_raw(self):
      return self.image.unpack_string_raw(self)

   def unpack_string_virtual(self):
      return self.image.unpack_string_virtual(self)

   def unpack_wide_string_limit(self, limit):
      return self.image.unpack_wide_string_limit(self, limit)

   def unpack_wide_string_limit_raw(self, limit_raw):
      return self.image.unpack_wide_string_limit_raw(self, limit_raw)

   def unpack_wide_string_limit_virtual(self, limit_virtual):
      return self.image.unpack_wide_string_limit_virtual(self, limit_virtual)

   def unpack_wide_string(self):
      return self.image.unpack_wide_string(self)

   def unpack_wide_string_raw(self):
      return self.image.unpack_wide_string_raw(self)

   def unpack_wide_string_virtual(self):
      return self.image.unpack_wide_string_virtual(self)

   def read(self, length=0):
      return self.image.read(self, length)

   def read_raw(self, length=0):
      return self.image.read_raw(self, length)

   def read_virtual(self, length=0):
      return self.image.read_virtual(self, length)

   def parse_pe(self):
      return self.image.parse_image_at_address(self)

   def pack_qword(self, qword, signed=0):
      return self.image.pack_qword(self, qword, signed)

   def pack_qword_raw(self, qword_raw, signed=0):
      return self.image.pack_qword_raw(self, qword_raw, signed)

   def pack_qword_virtual(self, qword_virtual, signed=0):
      return self.image.pack_qword_virtual(self, qword_virtual, signed)

   def pack_qwords(self, qwords, signed=0):
      return self.image.pack_qwords(self, qwords, signed)

   def pack_qwords_raw(self, qwords_raw, signed=0):
      return self.image.pack_qwords_raw(self, qwords_raw, signed)

   def pack_qwords_virtual(self, qwords_virtual, signed=0):
      return self.image.pack_qwords_virtual(self, qwords_virtual, signed)

   def pack_dword(self, dword, signed=0):
      return self.image.pack_dword(self, dword, signed)

   def pack_dword_raw(self, dword_raw, signed=0):
      return self.image.pack_dword_raw(self, dword_raw, signed)

   def pack_dword_virtual(self, dword_virtual, signed=0):
      return self.image.pack_dword_virtual(self, dword_virtual, signed)

   def pack_dwords(self, dwords, signed=0):
      return self.image.pack_dwords(self, dwords, signed)

   def pack_dwords_raw(self, dwords_raw, signed=0):
      return self.image.pack_dwords_raw(self, dwords_raw, signed)

   def pack_dwords_virtual(self, dwords_virtual, signed=0):
      return self.image.pack_dwords_virtual(self, dwords_virtual, signed)

   def pack_word(self, word, signed=0):
      return self.image.pack_word(self, word, signed)

   def pack_word_raw(self, word_raw, signed=0):
      return self.image.pack_word_raw(self, word_raw, signed)

   def pack_word_virtual(self, word_virtual, signed=0):
      return self.image.pack_word_virtual(self, word_virtual, signed)

   def pack_words(self, words, signed=0):
      return self.image.pack_words(self, words, signed)

   def pack_words_raw(self, words_raw, signed=0):
      return self.image.pack_words_raw(self, words_raw, signed)

   def pack_words_virtual(self, words_virtual, signed=0):
      return self.image.pack_words_virtual(self, words_virtual, signed)

   def pack_byte(self, byte, signed=0):
      return self.image.pack_byte(self, byte, signed)

   def pack_byte_raw(self, byte_raw, signed=0):
      return self.image.pack_byte_raw(self, byte_raw, signed)

   def pack_byte_virtual(self, byte_virtual, signed=0):
      return self.image.pack_byte_virtual(self, byte_virtual, signed)

   def pack_bytes(self, bytelist, signed=0):
      return self.image.pack_bytes(self, bytelist, signed)

   def pack_bytes_raw(self, bytes_raw, signed=0):
      return self.image.pack_bytes_raw(self, bytes_raw, signed)

   def pack_bytes_virtual(self, bytes_virtual, signed=0):
      return self.image.pack_bytes_virtual(self, bytes_virtual, signed)

   def pack_string(self, string):
      return self.image.pack_string(self, string)

   def pack_string_raw(self, string_raw):
      return self.image.pack_string_raw(self, string_raw)

   def pack_string_virtual(self, string_virtual):
      return self.image.pack_string_virtual(self, string_virtual)

   def pack_wide_string(self, string):
      return self.image.pack_wide_string(self, string)

   def write(self, raw):
      return self.image.write(self, raw)

   def write_raw(self, raw):
      return self.image.write_raw(self, raw)

   def write_virtual(self, raw):
      return self.image.write_virtual(self, raw)

   def section_by_offset(self):
      return self.image.section_by_offset(self.offset())

   def section_by_rva(self):
      return self.image.section_by_rva(self.rva())

   def create_function(self, function_class):
      return self.image.create_function(self, function_class)

   def relocate(self, target_base=None):
      return self.image.relocate(self, target_base)

   def relocate_raw(self, target_base=None):
      return self.image.relocate_raw(self, target_base)

   def relocate_virtual(self, target_base=None):
      return self.image.relocate_virtual(self, target_base)

   def __add__(self, val):
      new_addr = Address(self.image, self._value+val, self._value_type)

      if not self._offset == Address.INVALID_ADDRESS:
         new_addr._offset = self._offset + val
      if not self._rva == Address.INVALID_ADDRESS:
         new_addr._rva = self._rva + val
      if not self._va == Address.INVALID_ADDRESS:
         new_addr._va = self._va + val

      return new_addr

   def __iadd__(self, val):
      return self+val

   def __sub__(self, val):
      new_addr = Address(self.image, self._value-val, self._value_type)

      if not self._offset == Address.INVALID_ADDRESS:
         new_addr._offset = self._offset - val
      if not self._rva == Address.INVALID_ADDRESS:
         new_addr._rva = self._rva - val
      if not self._va == Address.INVALID_ADDRESS:
         new_addr._va = self._va - val

      return new_addr

   def __isub__(self, val):
      return self-val

   def __rsub__(self, val):
      new_addr = Address(self.image, val-self._value, self._value_type)

      if not self._offset == Address.INVALID_ADDRESS:
         new_addr._offset = val - self._offset
      if not self._rva == Address.INVALID_ADDRESS:
         new_addr._rva = val - self._rva
      if not self._va == Address.INVALID_ADDRESS:
         new_addr._va = val - self._va

      return new_addr

   def __hash__(self):
      return hash(self._value)

   def __cmp__(self, addr):
      if not isinstance(addr, Address):
         raise AddressError("can't compare address object to non-address object")

      DBG4("comparing %s to %s", repr(self), repr(addr))

      if self._value_type == addr._value_type:
         return cmp(self._value, addr._value)

      if not self._offset == Address.INVALID_ADDRESS and not addr._offset == Address.INVALID_ADDRESS:
         return cmp(self._offset, addr._offset)

      if not self._rva == Address.INVALID_ADDRESS and not addr._rva == Address.INVALID_ADDRESS:
         return cmp(self._rva, addr._rva)

      if not self._va == Address.INVALID_ADDRESS and not addr._va == Address.INVALID_ADDRESS:
         return cmp(self._va, addr._va)

      # okay. now you're just being a dick. we HAVE to convert one of the addresses.
      # the lowest hanging fruit is RVA -> VA. so if one is an RVA and another is a VA,
      # we're in business.

      if self._value_type == Address.VALUE_RVA and not addr._va == Address.INVALID_ADDRESS:
         return cmp(self.va(), addr._va)

      if not self._va == Address.INVALID_ADDRESS and addr._value_type == Address.VALUE_RVA:
         return cmp(self._va, addr.va())

      # the next lowest hanging fruit is VA -> RVA.

      if self._value_type == Address.VALUE_RVA and not addr._va == Address.INVALID_ADDRESS:
         return cmp(self._rva, addr.va())

      if not self._va == Address.INVALID_ADDRESS and addr._value_type == Address.VALUE_RVA:
         return cmp(self.rva(), addr._va)

      # if we've gotten here, we have to do something nasty anyway. force them
      # both into RVAs.
      return cmp(self.rva(), addr.rva())

   def __str__(self):
      if self._value >= 0xFFFFFFFF: # we can't use architecture() for reasons
         return '%s:0x%016X'%(self.VALUES[self._value_type].upper(),self._value)
      else:
         return '%s:0x%08X'%(self.VALUES[self._value_type].upper(),self._value)

   def __repr__(self):
      return '<Address [%s]>' % str(self)

   def __int__(self):
      return self._value

class PVA(Address):
   def __init__(self, image, pva):
      Address.__init__(self, image, pva, Address.VALUE_PVA)

   @classmethod
   def orphan(cls, value=0):
      return PVA(None, value)

class RVA(Address):
   def __init__(self, image, rva):
      Address.__init__(self, image, rva, Address.VALUE_RVA)

   @classmethod
   def orphan(cls, value=0):
      return RVA(None, value)

class VA(Address):
   def __init__(self, image, va):
      Address.__init__(self, image, va, Address.VALUE_VA)

   @classmethod
   def orphan(cls, value=0):
      return VA(None, value)

class Offset(Address):
   def __init__(self, image, offset):
      Address.__init__(self, image, offset, Address.VALUE_OFFSET)

   @classmethod
   def orphan(cls, value=0):
      return Offset(None, value)

###############################################################################
## Base data types
###############################################################################

# TODO endianness

class DataError(PEELError):
   pass

def sizeof(cls):
   return cls.sizeof()

class Data:
   DEFAULT_VALUE = None

   def __init__(self, **kwargs):
      self.address = kwargs.setdefault('address', None)
      self.copy = kwargs.setdefault('copy', 0)
      self._data = None

      if kwargs.setdefault('data', None):
         self.set_data(kwargs['data'])
      elif self.copy and self.address:
         self.copy_data() 
      elif not self.address:
         raise ValueError('cannot create a data object with no address or data')

      if self.address:
         self.address = self.address.address()

   def checksum(self, seed=0):
      #FIXME I really don't like using ''.join for this...
      return zlib.crc32(''.join(self.read()), seed)

   def set_data(self, data):
      if not len(data) == sizeof(self.__class__):
         raise ValueError('data size not equal to size of class')

      for i in xrange(len(data)):
         if not type(data[i]) is str or not len(data[i]) == 1:
            raise TypeError('data argument must be a list of bytes')

      if not type(data) is list:
         data = list(data)

      self._data = data[:]

   def copy_data(self):
      self._address_check()
      self._data = self.address.read(sizeof(self.__class__))

   def read(self):
      if self._has_data():
         return ''.join(self._data[:])
      else:
         self._address_check()
         return self.address.read(sizeof(self.__class__))

   def get_value(self):
      pass

   def set_value(self):
      pass

   def write(self):
      if not self._has_data():
         return # data should have been saved with set_value

      self._address_check()
      self.address.write(self._data)

   def clear(self):
      self._data = None

   def size(self):
      return sizeof(self.__class__)

   def _address_check(self):
      if not self.address:
         raise ValueError("data object contains no address")

   def _has_data(self):
      return not self._data is None

   def __len__(self):
      return sizeof(self.__class__)

   def __cmp__(self, other):
      return cmp(self.read(),other.read())

   def __repr__(self):
      return '<Data: "%s">' % ''.join(self.read())

   def __hash__(self):
      return hash(self.read())

   @classmethod
   def sizeof(cls):
      raise DataError('classmethod Data::sizeof undefined')

class DataArray:
   BASE_CLASS = Data

   def __init__(self, **kwargs):
      self.address = kwargs.setdefault('address', None)
      self.length = kwargs.setdefault('length', 0)
      self._data = None
      self.copy = kwargs.setdefault('copy', 0)

      if kwargs.setdefault('data', None):
         self.set_data(kwargs['data'])
      elif self.copy and self.address:
         self.copy_data()
      elif kwargs.setdefault('elements', None):
         self.set_elements(kwargs['elements'])
      elif not self.address:
         raise ValueError('cannot create a data reference with no address')

      if self.address:
         self.address = self.address.address()

   def set_data(self, data):
      cls = self.BASE_CLASS
      size = sizeof(cls)
      data_size = len(data)

      if not data_size % size == 0:
         raise ValueError('data size not a multiple of base class size')

      if not type(data) is list:
         raise TypeError('data argument not a list')

      for byte in data:
         if not type(byte) is str or not len(byte) == 1:
            raise TypeError('data argument must be a list of bytes')

      self._data = data[:]

   def copy_data(self):
      self._address_check()
      self._data = self.address.read(self.size())

   def read(self):
      if self._has_data():
         return ''.join(self._data[:])
      else:
         self._address_check()
         return self.address.read(self.size())

   def index_to_offset(self, index):
      cls = self.BASE_CLASS
      base_size = sizeof(cls)

      if index < 0:
         index = (self.size() - abs(index)*base_size)/base_size

      return index*base_size

   def offset_to_index(self, offset):
      cls = self.BASE_CLASS
      base_size = sizeof(cls)
      return offset / base_size

   def verify_offset(self, offset):
      self._sync_array_size()

      if offset < 0:
         offset = self.size() + offset

      if offset >= self.size() or offset < 0:
         raise IndexError(offset)

      return offset

   def get_element(self, index):
      cls = self.BASE_CLASS
      base_size = sizeof(cls)
      offset = self.verify_offset(self.index_to_offset(index))

      if self.address:
         new_addr = self.address+self.index_to_offset(index)
      else:
         new_addr = Offset.orphan(index)

      return self.BASE_CLASS(address=new_addr)

   def get_copied_element(self, index):
      elem = self.get_element(index)

      if elem.address.is_orphan():
         raise ValueError("can't copy data from an orphan address")

      elem.copy_data()
      return elem

   def get_elements(self):
      cls = self.BASE_CLASS
      base_size = sizeof(cls)
      elements = self.size()/base_size

      ret = list()

      for i in xrange(elements):
         ret.append(self[i])

   def get_copied_elements(self):
      elems = self.get_elements()

      if len(elems) and elems[0].address.is_orphan():
         raise ValueError("can't copy data from an orphan address")

      map(lambda x: x.copy_data(), elems)
      return elems

   def get_sliced_elements(self, slicer):
      start = slicer.start or 0
      step = slicer.step or 0
      stop = slicer.stop or 0
      ret = list()

      for i in range(start, step, stop):
         ret.append(self[i])

      return ret

   def get_copied_sliced_elements(self, slicer):
      elems = self.get_sliced_elements(slicer)

      if len(elems) and elems[0].address.is_orphan():
         raise ValueError("can't copy data from an orphan address")

      map(lambda x: x.copy_data(), elems)
      return elems

   def set_element_in_data(self, index, data):
      cls = self.BASE_CLASS

      if not len(data) == sizeof(cls):
         raise ValueError("data not same size of base class")

      offset = self.verify_offset(self.index_to_offset(index))

      for i in xrange(len(data)):
         self._data[i+offset] = data[i]

   def set_element_in_image(self, index, data):
      cls = self.BASE_CLASS

      if not len(data) == sizeof(cls):
         raise ValueError("data not same size of base class")

      self._address_check()
      offset = self.verify_offset(self.index_to_offset(index))
      (self.address+offset).write(data)

   def set_element(self, index, element):
      if self._has_data():
         self.set_element_in_data(index, element.read())
      else:
         self.set_element_in_image(index, element.read())

   def set_elements(self, elements):
      for i in xrange(len(elements)):
         self.set_element(i, elements[i])

   def remove_element_from_data(self, index):
      cls = self.BASE_CLASS
      size = sizeof(cls)
      offset = self.verify_offset(self.index_to_offset(index))

      for i in xrange(size):
         self._data.pop(offset)

      self._sync_array_size()

   def remove_element_from_image(self, index):
      if self.length == 0:
         return

      self._address_check()

      cls = self.BASE_CLASS
      size = sizeof(cls)
      offset = self.verify_offset(self.index_to_offset(index))

      null_offset = self.size()-size
      null_data = ['\x00']*size

      extra_offset = offset+size

      if extra_offset > null_offset:
         extra_offset = self.size()

      shiftable_data = self.size() - extra_offset

      if shiftable_data:
         data = (self.address+extra_offset).read(shiftable_data)
         (self.address+offset).write(data)

      (self.address+null_offset).write(null_data)

      self.length -= 1

   def remove_element(self, index):
      if self._has_data():
         self.remove_element_from_data(index)
      else:
         self.remove_element_from_image(index)

   def insert_data_into_data(self, index, data):
      cls = self.BASE_CLASS
      size = sizeof(cls)

      if not len(data) == size:
         raise ValueError("data not same size of base class")

      offset = self.index_to_offset(index)

      if offset > self.size():
         offset = self.size()
      elif offset < 0:
         offset = 0

      for i in xrange(size):
         self._data.insert(offset+i, data[i])

      self._sync_array_size()

   def insert_data_into_image(self, index, data):
      self._address_check()

      cls = self.BASE_CLASS
      size = sizeof(cls)

      if not len(data) == size:
         raise ValueError("data not same size of base class")

      offset = self.index_to_offset(index)

      if offset > self.size():
         offset = self.size()
      elif offset < 0:
         offset = 0

      shift_end = self.size()
      shiftable_data = shift_end - offset

      if shiftable_data:
         shift_data = (self.address+offset).read(shiftable_data)
         (self.address+(offset+size)).write(shift_data)

      (self.address+offset).write(data)
      self.length += 1

   def insert_element_into_data(self, index, element):
      self.insert_data_into_data(index, element.read())

   def insert_element_into_image(self, index, element):
      self.insert_data_into_image(index, element.read())

   def insert_element(self, index, element):
      if self._has_data():
         self.insert_element_into_data(index, element)
      else:
         self.insert_element_into_image(index, element)

   def append_element(self, element):
      self.insert_element(self.offset_to_index(self.size()), element)

   def pop_element(self):
      cls = self.BASE_CLASS
      size = sizeof(cls)
      index = self.offset_to_index(self.size() - size)

      element = self.get_element(index)
      self.remove_element(index)

      return element

   def write(self):
      if not self._has_data():
         return

      self._address_check()
      self.address.write(self._data)

   def size(self):
      if self._has_data():
         return len(self._data)
      else:
         return self.length*sizeof(self.BASE_CLASS)

   def checksum(self, seed=0):
      #FIXME I really don't like using ''.join for this...
      return zlib.crc32(''.join(self.read()), seed)

   def clear(self):
      if self._has_data():
         self._data = None
      else:
         self.length = 0

   def destroy(self):
      while len(self):
         self.pop_element()

      self.clear()

   def truncate(self, index):
      if self._has_data():
         self._data = self._data[:self.index_to_offset(index)]
      else:
         self.length = index

   def end_address(self):
      self._address_check()
      return self.address+self.size()

   def _address_check(self):
      if not self.address:
         raise ValueError("data array object contains no address")

   def _has_data(self):
      return not self._data is None

   def _sync_array_size(self):
      if not self._has_data():
         return

      self.length = len(self._data) / sizeof(self.BASE_CLASS)

   def __len__(self):
      return self.size() / self.BASE_CLASS.sizeof() 

   def __getitem__(self, index):
      if type(index) is slice:
         return self.get_sliced_elements(index)
      else:
         return self.get_element(index)

   def __setitem__(self, index, value):
      if type(index) is slice:
         raise TypeError('DataArray::__setitem__ does not support slices')

      self.set_element(index, value)

   def __cmp__(self, other):
      # we could compare the data, but likely, we want to compare the elements
      return cmp(self.get_elements(),other.get_elements())

   def __repr__(self):
      return '<DataArray: "%s">' % binascii.hexlify(self.read())

   def __hash__(self):
      return hash(self.read())

   def __iter__(self):
      for i in xrange(len(self)):
         yield self[i]

   @classmethod
   def orphan_list(cls, values):
      return map(cls.BASE_CLASS.orphan, values)

def parse_field(field):
   ret = dict()

   if type(field) == dict:
      for entry in field.items():
         key,data = entry

         new_parse = [key]
         new_parse += data

         ret[key] = parse_field(new_parse)[key]
   else:
      if len(field) < 2:
         raise ValueError('field not long enough (need at least 2 items)')

      element_name = field[0]
      element_class = field[1]

      if not getattr(element_class,'sizeof',None):
         if not len(field) == 3:
            raise ValueError('wrong field size (need 3 items for DataArray)')
         
         element_size = field[2]
      else:
         element_size = sizeof(element_class)

      ret[element_name] = [element_class, element_size]

   return ret

# TODO would a data dictionary mapped by address even further solve the issue of
# TODO unions in a Struct class? the main issue with unions is that writes don't
# TODO exactly go down the chain of command, so to speak. not to mention that
# TODO data makes copies rather than references for obvious reasons when copying
# TODO things. writing with non-copied unions are pretty much fine by design,
# TODO but copied unions are going to be a pain to do right.
class Struct:
   FIELDS = list()

   def __init__(self, **kwargs):
      self.address = kwargs.setdefault('address', None)
      self._data = None
      self.copy = kwargs.setdefault('copy', 0)

      self._make_field_dict()
      self._object_dict = dict()

      if kwargs.setdefault('data', None):
         self.set_data(kwargs['data'])
      elif self.copy and self.address:
         self.copy_data()
      elif not self.address:
         raise ValueError('cannot create a struct object with no address or data')

      if self.address:
         self.address = self.address.address()

   def set_data(self, data):
      if not len(data) == self.size():
         raise ValueError('data size not equal to size of struct')

      for i in xrange(len(data)):
         if not type(data[i]) is str or not len(data[i]) == 1:
            raise TypeError('data argument must be a list of bytes')

      self._data = list(data[:])

   def copy_data(self):
      self._address_check()
      self._data = self.address.read(sizeof(self.__class__))

   def read(self):
      if self._has_data():
         return ''.join(self._data[:])

      ret = ['\x00'] * self.size()

      for key in self._field_dict.keys():
         offset,cls,size = self._field_dict[key]

         object_data = getattr(self, key).read()
         ret[offset:offset+len(object_data)] = object_data

      return ''.join(ret)

   def write(self):
      if not self._has_data():
         return

      self._address_check()

      if not len(self._data) == len(self.size()): # it can happen.
         self._data = self._data[:self.size()]

         if not len(self._data) == len(self.size()): # oh, not -enough- data!
            self._data += ['\x00'] * (self.size() - len(self._data))

      for object_key in self._object_dict.keys():
         object_data = self._object_dict[object_key].read()
         object_offset = self._field_dict[object_key][0]

         for i in xrange(len(object_data)):
            self._data[i+object_offset] = object_data[i]

      self.address.write(self._data)

   def size(self):
      return sizeof(self.__class__)

   def end_address(self):
      self._address_check()
      return self.address+self.size()

   def diff(self, other):
      element_compare = cmp(self.FIELDS,other.FIELDS)

      if not element_compare == 0:
         raise TypeError('cannot diff two structs with differing fields')

      for field in self.FIELDS:
         key = field[0]

         if not getattr(self, key) == getattr(other, key):
            return key

   def _address_check(self):
      if not self.address:
         raise ValueError("struct object contains no address")

   def _has_data(self):
      ret = not self._data is None

      if ret:
         self.copy = 1
      else:
         self.copy = 0

      return ret

   def _make_field_dict(self):
      offset = 0
      self._field_dict = dict()
      
      for field in self.FIELDS:
         field_result = parse_field(field)
         max_size = 0

         for key in field_result.keys():
            self._field_dict[key] = [offset] + field_result[key]
            max_size = max(max_size, self._field_dict[key][2])

         offset += max_size

   def __cmp__(self, other):
      my_data = self.read()
      their_data = other.read()

      return cmp(my_data,their_data)

      element_compare = cmp(self.FIELDS, other.FIELDS)

      if not element_compare == 0:
         return element_compare

      for field_name in self._field_dict.keys():
         res = cmp(getattr(self, field_name),getattr(other, field_name))

         if not res == 0:
            return res

      return 0

   def __repr__(self):
      fields = self.FIELDS
      classname = self.__class__.__name__
      ret = list()
      ret.append('=> %s:' % classname)

      for field in fields:
         if type(field) == dict:
            ret.append('=>     [Union]')

            for key in field.keys():
               elem = getattr(self, key)
               elem_text = repr(elem)
               elem_text = elem_text.replace('\n', '\n\t')
               ret.append('=>        %s -> %s' % (key, elem_text))
         else:
            name = field[0]
            elem = getattr(self, name)
            elem_text = repr(elem)
            elem_text = elem_text.replace('\n', '\n\t')
            ret.append('=>     %s -> %s' % (name, elem_text))

      return '\n'.join(ret)

   def __getattr__(self, attr):
      if self.__dict__.has_key(attr):
         return self.__dict__[attr]

      if not self._field_dict.has_key(attr):
         raise AttributeError('struct %s has no element named "%s"' % (self.__class__.__name__, attr))

      if self._object_dict.has_key(attr):
         return self._object_dict[attr]

      field_data = self._field_dict[attr]
      offset,cls,size = field_data

      if self.address:
         new_address = self.address+offset
      else:
         new_address = Offset.orphan(offset)

      if self._has_data():
         object_data = self._data[offset:offset+size]
      else:
         object_data = None

      new_object = cls(address=new_address, copy=self.copy, length=size, data=object_data)

      if self.copy:
         self._object_dict[attr] = new_object

      return new_object

   def __hash__(self):
      return hash(self.read())

   @classmethod
   def sizeof(cls):
      size = 0

      for field in cls.FIELDS:
         parsed = parse_field(field)
         max_size = 0

         for key in parsed.keys():
            max_size = max(parsed[key][1], max_size)

         size += max_size

      return size

   @classmethod
   def anonymous(cls, *fields):
      class AnonymousStruct(cls):
         FIELDS = fields[0]

      return AnonymousStruct

   @classmethod
   def orphan(cls, *fields):
      # I don't want to think about this right now. sorry broseph.
      raise DataError('Struct::orphan not implemented')

###############################################################################
## Explicit data types
###############################################################################
class NumericDataStub(Data):
   DEFAULT_VALUE = 0

   def __init__(self, **kwargs):
      address = kwargs.setdefault('address', None)
      signed = kwargs.setdefault('signed', 0)
      copy_data = kwargs.setdefault('copy', 0)

      if kwargs.has_key('value'):
         new_bytes = list()
         value = kwargs['value']
         size = sizeof(self.__class__)

         for i in xrange(size):
            new_bytes.append(chr(value & 0xFF))
            value >>= 8

         #FIXME take care of this when taking endianness into account.
         #new_bytes.reverse()
      elif kwargs.setdefault('data', None):
         new_bytes = kwargs['data']
      else:
         new_bytes = None

      Data.__init__(self, address=address, data=new_bytes, copy=copy_data)
      self.signed = signed

   def signed_bit(self):
      # FIXME take care of this when taking endianness into account.
      return ord(self.read()[-1]) & 0x80

   def write(self):
      if not self._has_data():
         return

      self.address.write(self._data)

   def _squeeze_value(self, value):
      resized = value & (1 << (8 * self.size())) - 1

      if resized < 0 and not self.signed:
         resized *= -1

      return resized

   def __add__(self, val): 
      return int(self)+val

   def __radd__(self, val):
      return self+val

   def __iadd__(self, val):
      self.set_value(self._squeeze_value(self+val))
      return self

   def __sub__(self, val):
      return int(self)-val

   def __rsub__(self, val):
      return val-int(self)

   def __isub__(self, val):
      self.set_value(self._squeeze_value(self-val))
      return self

   def __mul__(self, val):
      return int(self)*val

   def __rmul__(self, val):
      return self*val

   def __imul__(self, val):
      self.set_value(self._squeeze_value(self*val))
      return self

   def __div__(self, val):
      return int(self)/val

   def __rdiv__(self, val):
      return val/int(self)

   def __idiv__(self, val):
      self.set_value(self._squeeze_value(self/val))
      return self

   def __mod__(self, val):
      return int(self) % val

   def __rmod__(self, val):
      return val % int(self)

   def __imod__(self, val):
      self.set_value(self._squeeze_value(self%val))
      return self

   def __pow__(self, val, modulo=None):
      if modulo == None:
         return int(self) ** val
      else:
         return int(self) ** val % modulo

   def __rpow__(self, val):
      return val ** int(self)

   def __ipow__(self, val, modulo=None):
      if modulo == None:
         result = self ** val
      else:
         result = self ** val % modulo

      self.set_value(self._squeeze_value(result))
      return self

   def __lshift__(self, val):
      return int(self) << val

   def __rlshift__(self, val):
      return val << int(self)

   def __ilshift__(self, val):
      self.set_value(self._squeeze_value(self << val))
      return self

   def __rshift__(self, val):
      return int(self) >> val

   def __rrshift__(self, val):
      return val >> int(self)

   def __irshift__(self, val):
      self.set_value(self._squeeze_value(self >> val))
      return self

   def __and__(self, val):
      return int(self) & val

   def __rand__(self, val):
      return val & int(self)

   def __iand__(self, val):
      self.set_value(self._squeeze_value(self & val))
      return self

   def __xor__(self, val):
      return int(self) ^ val

   def __rxor__(self, val):
      return val ^ int(self)

   def __ixor__(self, val):
      self.set_value(self._squeeze_value(self ^ val))
      return self

   def __or__(self, val):
      return int(self) | val

   def __ror__(self, val):
      return val | int(self)

   def __ior__(self, val):
      self.set_value(self._squeeze_value(self | val))
      return self

   def __int__(self):
      return self.get_value()

   @classmethod
   def sizeof(self):
      return 0

class Byte(NumericDataStub):
   def get_value(self):
      if self._has_data():
         return unpack_byte(self._data, 0)
      else:
         return self.address.unpack_byte()

   def set_value(self, value):
      if self._has_data():
         write(self._data, 0, (value, self.signed))
      else:
         self.address.pack_byte(value)

   def __repr__(self):
      return '<Byte: 0x%02X>' % int(self)

   @classmethod
   def sizeof(cls):
      return 1

   @classmethod
   def orphan(cls, value):
      return Byte(value=value)

class ByteArray(DataArray):
   BASE_CLASS = Byte

   def to_string(self):
      if self._has_data():
         return String(address=self.address, copy=1, length=len(self._data))
      else:
         return String(address=self.address)

   def from_string(self, string):
      if self._has_data():
         self.set_data(list(str(string)))
      else:
         self.address.write(str(string))

   def __str__(self):
      return ''.join(self.read())

   @classmethod
   def orphan(cls, values):
      orphan_list = ByteArray.orphan_list(values)
      data = ''.join(map(Byte.read, orphan_list))
      return ByteArray(data=data)

class String(ByteArray):
   DEFAULT_VALUE = ''

   def __init__(self, **kwargs):
      ByteArray.__init__(self, **kwargs)

      if self.copy and not kwargs.setdefault('data', None):
         if not self.length:
            # if you didn't provide a length, you're a jerk. 
            self.length = len(self.address.unpack_string())+1

         self.copy_data()
      elif kwargs.setdefault('value', None):
         self._address_check()
         self.set_data(list(kwargs['value']+'\x00'))
      elif self.address:
         self.length = len(self.read())

   def get_value(self):
      strval = ''.join(self.read())
      return strval.split('\x00')[0]

   def set_value(self, value):
      if self._has_data():
         self.set_data(list(str(value)+'\x00'))
         self.length = len(str(value))+1
      else:
         self.address.pack_string(str(value))
         self.length = len(str(value))+1

   def write(self):
      if not self._has_data():
         return

      self.address.pack_string(self.get_value())

   def read(self):
      if self._has_data():
         return ''.join(self._data[:])

      return self.address.unpack_string()+'\x00'

   def __str__(self):
      return self.get_value()

   def __repr__(self):
      return '<String: %s>' % str(self)

   @classmethod
   def orphan(cls, s):
      return String(data=list(s+'\x00'))

class Word(NumericDataStub):
   def get_value(self):
      if self._has_data():
         return unpack_word(self._data, self.signed)
      else:
         return self.address.unpack_word()

   def set_value(self, value):
      if self._has_data():
         write(self._data, 0, pack_word(value, self.signed))
      else:
         self.address.pack_word(value)

   def __repr__(self):
      return '<Word: 0x%04X>' % int(self)

   @classmethod
   def sizeof(self):
      return 2

   @classmethod
   def orphan(cls, value):
      return Word(value=value)

class WordArray(DataArray):
   BASE_CLASS = Word

   def to_wide_string(self):
      if self._has_data():
         return String(address=self.address, copy=1, length=len(self._data))
      else:
         return String(address=self.address)

   def from_wide_string(self, string):
      if self._has_data():
         self.set_data(list(str(string)))
      else:
         self.address.write(list(str(string)))

   def __str__(self):
      try:
         return unicode(self).encode('ascii')
      except UnicodeEncodeError:
         return ''.join(self.read())

   def __unicode__(self):
      return ''.join(self.read()).decode('utf-16')

   @classmethod
   def orphan(cls, values):
      orphan_list = WordArray.orphan_list(values)
      data = ''.join(map(Word.read, orphan_list))
      return WordArray(data=data)

class WideString(WordArray):
   DEFAULT_VALUE = u''

   def __init__(self, **kwargs):
      WordArray.__init__(self, **kwargs)

      if self.copy and not kwargs.setdefault('data', None):
         if not self.length:
            # if you didn't provide a length, you're a jerk. 
            self.length = len(self.address.unpack_wide_string())+2

         self.copy_data()
      elif kwargs.setdefault('value', None):
         self._address_check()
         self.set_data(list(self.address.unpack_wide_string()+'\x00\x00'))

   def get_value(self):
      strval = ''.join(self.read())
      slicepoint = 0

      while slicepoint < len(strval) and strval[slicepoint:slicepoint+2] != '\x00\x00':
         slicepoint += 2

      return strval[:slicepoint].decode('utf-16')

   def set_value(self, value):
      if self._has_data():
         self.set_data(list(str(value).encode('utf-16')[2:]))
      else:
         self.address.pack_wide_string(value)

   def write(self):
      if not self._has_data():
         return

      self.address.pack_wide_string(self.get_value())

   def __unicode__(self):
      return self.get_value()

   def __repr__(self):
      return '<WideString: %s>' % str(self)

   @classmethod
   def orphan(self, ws):
      return WideString(data=list(ws.encode('utf-16')[2:]+'\x00\x00'))

class Dword(NumericDataStub):
   def get_value(self):
      if self._has_data():
         return unpack_dword(self._data, self.signed)
      else:
         return self.address.unpack_dword()

   def set_value(self, value):
      if self._has_data():
         write(self._data, 0, pack_dword(value, self.signed))
      else:
         self.address.pack_dword(value)

   def as_va(self):
      return self.address.image.va(int(self))

   def as_rva(self):
      return self.address.image.rva(int(self))

   def as_offset(self):
      return self.address.image.offset(int(self))

   def __repr__(self):
      return '<Dword: 0x%08X>' % int(self)

   @classmethod
   def sizeof(self):
      return 4

   @classmethod
   def orphan(cls, value):
      return Dword(value=value)

class DwordArray(DataArray):
   BASE_CLASS = Dword

   @classmethod
   def orphan(cls, values):
      orphan_list = DwordArray.orphan_list(values)
      data = ''.join(map(Dword.read, orphan_list))
      return DwordArray(data=data)

class Qword(NumericDataStub):
   def get_value(self):
      if self._has_data():
         return unpack_qword(self._data, self.signed)
      else:
         return self.address.unpack_qword()

   def set_value(self, value):
      if self._has_data():
         write(self._data, 0, pack_qword(value, self.signed))
      else:
         self.address.pack_qword(value)

   def as_va(self):
      return self.address.image.va(int(self))

   def as_rva(self):
      return self.address.image.rva(int(self))

   def as_offset(self):
      return self.address.image.offset(int(self))

   def __repr__(self):
      return '<Qword: 0x%016X>' % int(self)

   @classmethod
   def sizeof(self):
      return 8

   @classmethod
   def orphan(cls, value):
      return Qword(value=value)

class QwordArray(DataArray):
   BASE_CLASS = Qword

   @classmethod
   def orphan(cls, values):
      orphan_list = QwordArray.orphan_list(values)
      data = ''.join(map(Qword.read, orphan_list))
      return QwordArray(data=data)

BYTE = Byte
LPBYTE = ByteArray
LPSTR = String
WORD = Word
LPWORD = WordArray
LPWSTR = WideString
DWORD = Dword
LPDWORD = DwordArray
QWORD = Qword
LPQWORD = QwordArray

###############################################################################
## Headers
###############################################################################
class DOSHeader(Struct):
   FIELDS = [('e_magic',     WORD),
             ('e_cblp',      WORD),
             ('e_cp',        WORD),
             ('e_crlc',      WORD),
             ('e_cparhdr',   WORD),  
             ('e_minalloc',  WORD),
             ('e_maxalloc',  WORD),
             ('e_ss',        WORD),
             ('e_sp',        WORD),
             ('e_csum',      WORD),
             ('e_ip',        WORD),
             ('e_cs',        WORD),
             ('e_lfarlc',    WORD),
             ('e_ovno',      WORD),
             ('e_res',       WORD),
             ('e_unused1',   LPBYTE,  6),
             ('e_oemid',     WORD),
             ('e_oeminfo',   WORD),
             ('e_res2',      WORD),
             ('e_unused2',   LPBYTE,  0x12),
             ('e_lfanew',    DWORD)]

   DOS_WARNING = [0x0E,0x1F,0xBA,0x0E,0x00,0xB4,0x09,0xCD,0x21,0xB8,0x01,0x4C,
                  0xCD,0x21,0x54,0x68,0x69,0x73,0x20,0x70,0x72,0x6F,0x67,0x72,
                  0x61,0x6D,0x20,0x63,0x61,0x6E,0x6E,0x6F,0x74,0x20,0x62,0x65,
                  0x20,0x72,0x75,0x6E,0x20,0x69,0x6E,0x20,0x44,0x4F,0x53,0x20,
                  0x6D,0x6F,0x64,0x65,0x2E,0x0D,0x0D,0x0A,0x24,0x00,0x00,0x00,
                  0x00,0x00,0x00,0x00,0x08,0x73,0xA6,0x53,0x4C,0x12,0xC8,0x00,
                  0x4C,0x12,0xC8,0x00,0x4C,0x12,0xC8,0x00,0x45,0x6A,0x5D,0x00,
                  0x45,0x12,0xC8,0x00,0x4C,0x12,0xC9,0x00,0xD8,0x13,0xC8,0x00,
                  0x45,0x6A,0x5B,0x00,0x6D,0x12,0xC8,0x00,0x45,0x6A,0x4B,0x00,
                  0x57,0x12,0xC8,0x00,0x45,0x6A,0x4C,0x00,0xCE,0x12,0xC8,0x00,
                  0x45,0x6A,0x5C,0x00,0x4D,0x12,0xC8,0x00,0x45,0x6A,0x59,0x00,
                  0x4D,0x12,0xC8,0x00,0x52,0x69,0x63,0x68,0x4C,0x12,0xC8,0x00,
                  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]

   def __init__(self, **kwargs):
      Struct.__init__(self, **kwargs)

      if kwargs.setdefault('set_defaults',0):
         self.set_defaults()

   def set_defaults(self):
      self.e_magic.set_value(IMAGE_DOS_SIGNATURE)
      self.e_lfanew.set_value(0xE0)

IMAGE_DOS_HEADER = DOSHeader

class NTHeader(Struct): # FIXME this should be deprecated.
   FIELDS = [('Signature',   DWORD)]

   def __init__(self, **kwargs):
      Struct.__init__(self, **kwargs)

      if kwargs.setdefault('set_defaults',0):
         self.set_defaults()

   def set_defaults(self):
      self.Signature.set_value(IMAGE_NT_SIGNATURE)

class FileHeader(Struct):
   FIELDS = [('Machine',              WORD),
             ('NumberOfSections',     WORD),
             ('TimeDateStamp',        DWORD),
             ('PointerToSymbolTable', DWORD),
             ('NumberOfSymbols',      DWORD),
             ('SizeOfOptionalHeader', WORD),
             ('Characteristics',      WORD)]

   def __init__(self, **kwargs):
      Struct.__init__(self, **kwargs)

      if kwargs.setdefault('set_defaults',0):
         self.set_defaults()

   def set_defaults(self):
      self.Machine.set_value(IMAGE_FILE_MACHINE_I386) 
      self.TimeDateStamp.set_value(int(time.time()))
      self.SizeOfOptionalHeader.set_value(sizeof(OptionalHeader32)+(sizeof(DataDirectory)*16))
      self.Characteristics.set_value(IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE)

IMAGE_FILE_HEADER = FileHeader

class OptionalHeader32(Struct):
   FIELDS = [('Magic',                         WORD),
             ('MajorLinkerVersion',            BYTE),
             ('MinorLinkerVersion',            BYTE),
             ('SizeOfCode',                    DWORD),
             ('SizeOfInitializedData',         DWORD),
             ('SizeOfUninitializedData',       DWORD),
             ('AddressOfEntryPoint',           DWORD),
             ('BaseOfCode',                    DWORD),
             ('BaseOfData',                    DWORD),
             ('ImageBase',                     DWORD),
             ('SectionAlignment',              DWORD),
             ('FileAlignment',                 DWORD),
             ('MajorOperatingSystemVersion',   WORD),
             ('MinorOperatingSystemVersion',   WORD),
             ('MajorImageVersion',             WORD),
             ('MinorImageVersion',             WORD),
             ('MajorSubsystemVersion',         WORD),
             ('MinorSubsystemVersion',         WORD),
             ('Win32VersionValue',             DWORD),
             ('SizeOfImage',                   DWORD),
             ('SizeOfHeaders',                 DWORD),
             ('CheckSum',                      DWORD),
             ('Subsystem',                     WORD),
             ('DllCharacteristics',            WORD),
             ('SizeOfStackReserve',            DWORD),
             ('SizeOfStackCommit',             DWORD),
             ('SizeOfHeapReserve',             DWORD),
             ('SizeOfHeapCommit',              DWORD),
             ('LoaderFlags',                   DWORD),
             ('NumberOfRvaAndSizes',           DWORD)]

   def __init__(self, **kwargs):
      Struct.__init__(self, **kwargs)

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

class OptionalHeader64(Struct):
   FIELDS = [('Magic',                         WORD),
             ('MajorLinkerVersion',            BYTE),
             ('MinorLinkerVersion',            BYTE),
             ('SizeOfCode',                    DWORD),
             ('SizeOfInitializedData',         DWORD),
             ('SizeOfUninitializedData',       DWORD),
             ('AddressOfEntryPoint',           DWORD),
             ('BaseOfCode',                    DWORD),
             ('ImageBase',                     QWORD),
             ('SectionAlignment',              DWORD),
             ('FileAlignment',                 DWORD),
             ('MajorOperatingSystemVersion',   WORD),
             ('MinorOperatingSystemVersion',   WORD),
             ('MajorImageVersion',             WORD),
             ('MinorImageVersion',             WORD),
             ('MajorSubsystemVersion',         WORD),
             ('MinorSubsystemVersion',         WORD),
             ('Win32VersionValue',             DWORD),
             ('SizeOfImage',                   DWORD),
             ('SizeOfHeaders',                 DWORD),
             ('CheckSum',                      DWORD),
             ('Subsystem',                     WORD),
             ('DllCharacteristics',            WORD),
             ('SizeOfStackReserve',            QWORD),
             ('SizeOfStackCommit',             QWORD),
             ('SizeOfHeapReserve',             QWORD),
             ('SizeOfHeapCommit',              QWORD),
             ('LoaderFlags',                   DWORD),
             ('NumberOfRvaAndSizes',           DWORD)]

   def __init__(self, **kwargs):
      Struct.__init__(self, **kwargs)

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

class NTHeaders32(Struct):
   FIELDS = [('Signature',       DWORD),
             ('FileHeader',      IMAGE_FILE_HEADER),
             ('OptionalHeader',  IMAGE_OPTIONAL_HEADER32)]

   def __init__(self, **kwargs):
      Struct.__init__(self, **kwargs)

      if kwargs.setdefault('set_defaults',0):
         self.set_defaults()

   def set_defaults(self):
      self.Signature.set_value(IMAGE_NT_SIGNATURE)
      self.FileHeader.set_defaults()
      self.OptionalHeader.set_defaults()

IMAGE_NT_HEADERS32 = NTHeaders32

class NTHeaders64(Struct):
   FIELDS = [('Signature',       DWORD),
             ('FileHeader',      IMAGE_FILE_HEADER),
             ('OptionalHeader',  IMAGE_OPTIONAL_HEADER64)]

   def __init__(self, **kwargs):
      Struct.__init__(self, **kwargs)

      if kwargs.setdefault('set_defaults',0):
         self.set_defaults()

   def set_defaults(self):
      self.Signature.set_value(IMAGE_NT_SIGNATURE)
      self.FileHeader.set_defaults()
      self.OptionalHeader.set_defaults()

IMAGE_NT_HEADERS64 = NTHeaders64

class Section(Struct):
   FIELDS = [('Name',                  ByteArray,  8),
             ('VirtualSize',           DWORD),
             ('VirtualAddress',        DWORD),
             ('SizeOfRawData',         DWORD),
             ('PointerToRawData',      DWORD),
             ('PointerToRelocations',  DWORD),
             ('PointerToLinenumbers',  DWORD),
             ('NumberOfRelocations',   WORD),
             ('NumberOfLinenumbers',   WORD),
             ('Characteristics',       DWORD)]

   def read_section(self):
      addr = self.PointerToRawData.as_offset()

      # found some rude-ass malware that has some fucked up section nonsense!
      # md5: F375365111B4DD5026ACC0E37581DC00

      raw_size = int(self.SizeOfRawData)
      virtual_size = int(self.VirtualSize)

      if raw_size > virtual_size:
         DBG2("whoa! you've got some FUCKED UP sections, dude! raw size greater than virtual size?! rude!")
         section_size = virtual_size
      else:
         section_size = raw_size

      if addr.valid_rva():
         return addr.read(section_size)

   def entropy(self):
      start = self.VirtualAddress.as_rva()
      end = start+int(self.VirtualSize)
      return self.address.image.specific_entropy(start, end)

   def compare_data(self, other):
      if not isinstance(other, Section):
         raise TypeError("argument must be a Section type")

      my_data = self.read()
      their_data = other.read()

      return cmp(my_data,their_data)

   def raw_address(self):
      return self.PointerToRawData.as_offset()

   def virtual_address(self): 
      return self.VirtualAddress.as_rva()

   def end_raw_address(self):
      return self.raw_address()+int(self.SizeOfRawData)

   def end_virtual_address(self):
      return self.virtual_address()+int(self.VirtualSize)

   def find_objects_like(self, obj):
      # this is really slow, it should be threaded for MAXIMUM SEARCH SPEEEEEEED
      if not isinstance(obj, Data) and not isinstance(obj, DataArray) and not isinstance(obj, Struct):
         raise TypeError("argument must be a Data, DataArray or Struct type")

      obj_type = obj.__class__
      
      if issubclass(obj_type, DataArray):
         length = obj.length
      else:
         length = 0

      start_addr = self.raw_address()
      end_addr = self.end_raw_address()
      ret = list()

      while start_addr < end_addr:
         new_object = obj_type(address=start_addr.address(), length=length)

         if new_object == obj:
            ret.append(start_addr.address())

         start_addr = start_addr+1

      return ret

class SectionArray(DataArray):
   BASE_CLASS = Section

   def add_section(self, **kwargs):
      section = self._new_section(**kwargs)
      self.append_element(section)

      if getattr(self, 'address'):
         self.address.image.IMAGE_FILE_HEADER.NumberOfSections += 1

   def insert_section(self, **kwargs):
      section = self._new_section(**kwargs)
      self.insert_element(kwargs['index'], section)

   def delete_section_by_index(self, section_index):
      self.remove_element(section_index)

   def delete_section_by_name(self, name):
      index = self.section_index_by_name(name)

      if index == -1:
         raise ValueError('no such section with the name "%s"' % name)

      self.delete_section_by_index(index)

   def delete_section_by_binary_name(self, name):
      index = self.section_index_by_binary_name(name)

      if index == -1:
         raise ValueError('no such section with the binary name "%s"' % repr(name))

      self.delete_section_by_index(index)

   def section_index_by_name(self, name):
      for i in xrange(len(self)):
         section = self[i]

         if str(section.Name).strip('\x00') == name:
            return i

      return -1

   def section_index_by_binary_name(self, name):
      for i in xrange(len(self)):
         section = self[i]

         if str(section.Name) == name:
            return i

      return -1

   def _new_section(self, **kwargs):
      if kwargs.has_key('data'):
         section = Section(data=kwargs['data'])
      else:
         section = Section(address=self.end_address())

      if kwargs.has_key('Name'):
         section.Name.from_string(kwargs['Name'])

      if kwargs.has_key('VirtualSize'):
         section.VirtualSize.set_value(kwargs['VirtualSize'])

      if kwargs.has_key('VirtualAddress'):
         rva = kwargs['VirtualAddress']

         if isinstance(rva, Address):
            rva = rva.rva()

         section.VirtualAddress.set_value(rva)

      if kwargs.has_key('SizeOfRawData'):
         section.SizeOfRawData.set_value(kwargs['SizeOfRawData'])

      if kwargs.has_key('PointerToRawData'):
         offset = kwargs['PointerToRawData']

         if isinstance(offset, Address):
            offset = offset.offset()

         section.PointerToRawData.set_value(offset)

      if kwargs.has_key('PointerToRelocations'):
         section.PointerToRelocations.set_value(kwargs['PointerToRelocations'])

      if kwargs.has_key('PointerToLinenumbers'):
         section.PointerToLinenumbers.set_value(kwargs['PointerToLinenumbers'])

      if kwargs.has_key('NumberOfRelocations'):
         section.NumberOfRelocations.set_value(kwargs['NumberOfRelocations'])

      if kwargs.has_key('NumberOfLinenumbers'):
         section.NumberOfRelocations.set_value(kwargs['NumberOfLinenumbers'])

      if kwargs.has_key('Characteristics'):
         section.Characteristics.set_value(kwargs['Characteristics'])

      return section

   def __repr__(self):
      return '<SectionArray:\n%s\n>' % '\n'.join(map(repr, self))

IMAGE_SECTION_HEADER = Section
PIMAGE_SECTION_HEADER = SectionArray

class FloatingSaveArea(Struct):
   FIELDS = [('ControlWord',           DWORD),
             ('StatusWord',            DWORD),
             ('TagWord',               DWORD),
             ('ErrorOffset',           DWORD),
             ('ErrorSelector',         DWORD),
             ('DataOffset',            DWORD),
             ('DataSelector',          DWORD),
             ('RegisterArea',          LPBYTE,     SIZE_OF_80387_REGISTERS),
             ('Cr0NpxState',           DWORD)]

FLOATING_SAVE_AREA = FloatingSaveArea

class Context(Struct):
   FIELDS = [('ContextFlags',          DWORD),
             ('Dr0',                   DWORD),
             ('Dr1',                   DWORD),
             ('Dr2',                   DWORD),
             ('Dr3',                   DWORD),
             ('Dr6',                   DWORD),
             ('Dr7',                   DWORD),
             ('FloatSave',             FLOATING_SAVE_AREA),
             ('SegGs',                 DWORD),
             ('SegFs',                 DWORD),
             ('SegEs',                 DWORD),
             ('SegDs',                 DWORD),
             ('Edi',                   DWORD),
             ('Esi',                   DWORD),
             ('Ebx',                   DWORD),
             ('Edx',                   DWORD),
             ('Ecx',                   DWORD),
             ('Eax',                   DWORD),
             ('Ebp',                   DWORD),
             ('Eip',                   DWORD),
             ('SegCs',                 DWORD),
             ('EFlags',                DWORD),
             ('Esp',                   DWORD),
             ('SegSs',                 DWORD),
             ('ExtendedRegisters',     LPBYTE,     MAXIMUM_SUPPORTED_EXTENSION)]

CONTEXT = Context

###############################################################################
## Data Directories
###############################################################################
class DataDirectory(Struct):
   FIELDS = [('VirtualAddress', DWORD),
             ('Size',           DWORD)]  

   def read(self):
      addr = self.VirtualAddress.as_rva()
         
      if addr.valid_rva():
         return addr.read(int(self.Size))

   def compare_data(self, other):
      if not isinstance(other, DataDirectory):
         raise TypeError("argument must be a DataDirectory instance")

      return cmp(self.read(),other.read())

   @classmethod
   def from_directory(cls, directory, copy=0):
      return cls(address=directory.address, copy=copy)

IMAGE_DATA_DIRECTORY = DataDirectory

class DataDirectoryArray(DataArray):
   BASE_CLASS = DataDirectory

   def __repr__(self):
      return '<DataDirectoryArray:\n%s\n>' % '\n'.join(map(repr, self))

PIMAGE_DATA_DIRECTORY = DataDirectoryArray

# TODO class ResourceDirectory(DataDirectory):
# TODO class BoundImportDirectory(DataDirectory):
# TODO class ImportAddressTableDirectory(DataDirectory):
# TODO class DelayImportDirectory(DataDirectory):
# TODO class ExceptionDirectory(DataDirectory):
# TODO class DebugDirectory(DataDirectory):
# TODO class TLSDirectory(DataDirectory):
# TODO class SecurityDirectory(DataDirectory):
# TODO class ArchitectureDirectory(DataDirectory):
# TODO class ConfigurationDirectory(DataDirectory):
# TODO class DotNetMetaDataDirectory(DataDirectory):

###############################################################################
## Import/Export related structures
###############################################################################
class ImportDescriptor(Struct):
   FIELDS = [{
               'Characteristics':      (DWORD,),
               'OriginalFirstThunk':   (DWORD,)
             },
             ('TimeDateStamp',   DWORD),
             ('ForwarderChain',  DWORD),
             ('Name',            DWORD),
             ('FirstThunk',      DWORD)]

   def parse_descriptor_table(self, copy=0):
      return ImportDescriptorArray.parse_descriptor_table(self.address, copy)

   def aggro_parse_descriptor_table(self, copy=0):
      return ImportDescriptorArray.aggro_parse_descriptor_table(self.address, copy)

class ImportDescriptorArray(DataArray):
   BASE_CLASS = ImportDescriptor

   def map_entries(self):
      ret = dict()

      for entry in self:
         name_addr = entry.Name.as_rva()

         if not name_addr.valid_rva():
            DBG2('hey! %s has an invalid name address!', repr(entry.address))
            name_value = repr(entry.address)
         else:
            name_value = name_addr.unpack_string()

         ret[name_value.upper()] = entry

      return ret

   @classmethod
   def parse_descriptor_table(cls, address, copy=0):
      imports = 0
      indexer = address.address()

      while indexer.unpack_dword():
         imports += 1
         indexer += sizeof(ImportDescriptor)

      return cls(address=address, length=imports, copy=copy)

   @classmethod
   def aggro_parse_descriptor_table(cls, address, copy=0):
      imports = 0
      indexer = address.address()

      while 1:
         descriptor = cls.BASE_CLASS(address=indexer)
         
         if int(descriptor.OriginalFirstThunk) == 0 and int(descriptor.FirstThunk) == 0:
            break

         imports += 1
         indexer += sizeof(ImportDescriptor)

      return cls(address=address, length=imports, copy=copy)

class ThunkStub: # helper function class, don't instantiate directly
   def parse_export_thunk(self, export_start, export_end):
      addr = self.Function.as_rva()

      if addr < export_end and addr >= export_start: # this is a forwarder!
         return addr.unpack_string()
      else:
         return addr

class ThunkDataArrayStub(DataArray): # another helper function class, don't instantiate directly
   def map_thunks(self):
      ret = dict()

      for i in xrange(len(self)):
         elem = self[i]
         ret[elem.address] = elem.parse_import_thunk()

      return ret

   @classmethod
   def parse_import_thunk_table(cls, address, copy=0):
      thunks = 0
      indexer = address.address()

      while indexer.unpack_dword():
         thunks += 1
         indexer += sizeof(cls.BASE_CLASS)

      return cls(address=address, length=thunks, copy=copy)

class ThunkData32(Struct, ThunkStub):
   FIELDS = [{
               'ForwarderString':   (DWORD,),
               'Function':          (DWORD,),
               'Ordinal':           (DWORD,),
               'AddressOfData':     (DWORD,)
             }]

   def is_ordinal(self):
      return int(self.Ordinal) & 0x80000000

   def parse_import_thunk(self):
      if self.is_ordinal():
         return int(self.Ordinal) & 0xFFFF
      else:
         return ImportByName(address=self.AddressOfData.as_rva(),copy=self.copy)

class ThunkData32Array(ThunkDataArrayStub):
   BASE_CLASS = ThunkData32

class ThunkData64(Struct, ThunkStub):
   FIELDS = [{
               'ForwarderString':   (QWORD,),
               'Function':          (QWORD,),
               'Ordinal':           (QWORD,),
               'AddressOfData':     (QWORD,)
             }]

   def is_ordinal(self):
      return int(self.Ordinal) & 0x8000000000000000

   def parse_import_thunk(self):
      if self.is_ordinal():
         return int(self.Ordinal) & 0xFFFFFFFF
      else:
         return ImportByName(address=self.AddressOfData.as_rva(),copy=self.copy)

class ThunkData64Array(ThunkDataArrayStub):
   BASE_CLASS = ThunkData64

class ImportByName(Struct):
   FIELDS = [('Hint',   WORD),
             ('Name',   LPSTR,  1)]

   def __init__(self, **kwargs):
      # cheat the inability to make variable data
      address = kwargs['address']+2
      name = address.unpack_string()
      name_len = len(name)+1 # null byte
      name_len += name_len % 2

      Struct.__init__(self, **kwargs)
      self._fix_size_discrepancy(name_len)

   def size(self):
      name = self.Name
      size = sizeof(WORD) + len(self.Name)
      size += size % 2

      self._fix_size_discrepancy(size - sizeof(WORD))

      return size

   def _fix_size_discrepancy(self, new_size):
      self._field_dict['Name'][2] = new_size

   def __getattr__(self, attr):
      result = Struct.__getattr__(self, attr)

      if attr == 'Name':
         self._fix_size_discrepancy(len(result))

      return result

   def __str__(self):
      return str(self.Name)

class BoundImportDescriptor(Struct):
   FIELDS = [('TimeDateStamp',               DWORD),
             ('OffsetModuleName',            WORD),
             ('NumberOfModuleForwarderRefs', WORD)]

class BoundImportDescriptor(Struct):
   FIELDS = [('TimeDateStamp',      DWORD),
             ('OffsetModuleName',   WORD),
             ('Reserved',           WORD)]

###############################################################################
## Relocation directory
###############################################################################
class RelocationDirectory(DataDirectory):
   def __init__(self, **kwargs):
      DataDirectory.__init__(self, **kwargs)

      if kwargs.setdefault('parse', 0):
         self.parse_relocations()

   def parse_relocations(self):
      start_addr = self.VirtualAddress.as_rva()

      if start_addr.is_null() or not start_addr.valid_rva():
         raise HeaderError('relocation directory RVA is invalid')

      end_addr = start_addr+int(self.Size)

      self.relocations = dict()

      while start_addr < end_addr:
         base_relocation = ImageBaseRelocation(address=start_addr, copy=self.copy)

         relocations = start_addr+sizeof(ImageBaseRelocation)
         items = int(base_relocation.SizeOfBlock) - sizeof(ImageBaseRelocation)
         items /= sizeof(WORD)
         relocation_table = LPWORD(address=relocations, length=items, copy=self.copy)

         start_addr = relocations+relocation_table.size()
         self.relocations[base_relocation] = relocation_table

      return self.relocations

   def get_relocations(self):
      if not getattr(self, 'relocations', None):
         return self.parse_relocations()

      return self.relocations

   def get_relocation_values(self, target_base=None):
      relocations = self.get_relocations()
      relocation_values = dict()

      delta = self.address.image.get_base_delta(target_base)
      delta_high = delta & 0xFFFF0000
      delta_low = delta & 0xFFFF

      for base in relocations.keys():
         reloc_table = relocations[base]
         reloc_rva = base.VirtualAddress.as_rva()

         for reloc_word in reloc_table:
            reloc_word = int(reloc_word)

            reloc_type = reloc_word >> 12
            reloc_offset = reloc_word & 0xFFF
            reloc_ptr = reloc_rva + reloc_offset
            reloc_value = reloc_ptr.unpack_dword()

            if reloc_type == 3: # HIGHLOW
               reloc_value += delta
            elif reloc_type == 1: # HIGH
               reloc_value += delta_high
            elif reloc_type == 2: # LOW
               reloc_value += delta_low
            else: # it's otherwise a no-op afaik
               continue

            reloc_value &= 0xFFFFFFFF
            relocation_values[reloc_ptr] = reloc_value

      return relocation_values

class ImageBaseRelocation(Struct):
   FIELDS = [('VirtualAddress',     DWORD),
             ('SizeOfBlock',        DWORD)]

IMAGE_BASE_RELOCATION = ImageBaseRelocation

# TODO I have no idea what the fuck this is ACTUALLY for... but I'm leaving it
# TODO anyway. someone might need it. I might need it. who knows!
class ImageRelocation(Struct):
   FIELDS = [{
                'VirtualAddress':    (DWORD,),
                'RelocCount':        (DWORD,)
             },
             ('SymbolTableIndex',   DWORD),
             ('Type',               WORD)]

IMAGE_RELOCATION = ImageRelocation

class ImageRelocationArray(DataArray):
   BASE_CLASS = ImageRelocation

PIMAGE_RELOCATION = ImageRelocationArray

###############################################################################
## Export Directory
###############################################################################
class ExportDirectory(DataDirectory):
   def __init__(self, **kwargs):
      DataDirectory.__init__(self, **kwargs)

      if kwargs.setdefault('parse', 0):
         self.parse_export_table()

   def dll_name(self):
      try:
         export_table = self.get_export_table()
      except HeaderError:
         return

      dll_name = export_table.get_dll_name()

      if dll_name.address.is_null():
         return

      return str(dll_name)

   def parse_export_table(self):
      addr = self.VirtualAddress.as_rva()

      if not addr.valid_rva():
         raise HeaderError('export directory RVA is invalid')

      self.export_table = ExportTable(address=addr, copy=self.copy)

      DBG1('got the export table')
      DBG2('have the export table:')
      DBG2(repr(self.export_table))

      return self.export_table

   def get_export_table(self):
      if not getattr(self, 'export_table', None):
         return self.parse_export_table()

      return self.export_table

   def map_exports(self):
      export_table = self.get_export_table()
      ordinals = export_table.get_ordinals()
      names = export_table.get_names()
      functions = export_table.get_functions()
      ret = dict()
      start = self.VirtualAddress.as_rva()
      end = start+int(self.Size)

      for i in xrange(len(names)):
         ordinal = int(ordinals[i])
         name_addr = names[i].as_rva()

         if not name_addr.valid_rva():
            DBG2('hey! export name address #%d is invalid!', i)
            continue

         name = name_addr.unpack_string()
         function = functions[ordinal]
         ret[name] = function.parse_export_thunk(start, end)

      return ret

class ExportTable(Struct):
   FIELDS = [('Characteristics',          DWORD),
             ('TimeDateStamp',            DWORD),
             ('MajorVersion',             WORD),
             ('MinorVersion',             WORD),
             ('Name',                     DWORD),
             ('Base',                     DWORD),
             ('NumberOfFunctions',        DWORD),
             ('NumberOfNames',            DWORD),
             ('AddressOfFunctions',       DWORD),
             ('AddressOfNames',           DWORD),
             ('AddressOfNameOrdinals',    DWORD)]

   def __init__(self, **kwargs):
      Struct.__init__(self, **kwargs)

      if kwargs.setdefault('parse', 0):
         self.parse_export_table()

   def parse_export_table():
      self.parse_dll_name()
      self.parse_functions()
      self.parse_names()
      self.parse_ordinals()

   def parse_dll_name(self):
      addr = self.Name.as_rva()

      if not addr.valid_rva():
         raise HeaderError('export name not a valid rva')

      self.dll_name = String(address=self.Name.as_rva(), copy=self.copy)
      return self.dll_name

   def get_dll_name(self):
      if not getattr(self, 'dll_name', None):
         return self.parse_dll_name()

      return self.dll_name

   def parse_functions(self):
      addr = self.AddressOfFunctions.as_rva()

      if not addr.valid_rva():
         raise HeaderError('function address not a valid rva')

      length = int(self.NumberOfFunctions)
      self.functions=ThunkData32Array(address=addr,length=length,copy=self.copy)
      return self.functions

   def get_functions(self):
      if not getattr(self, 'functions', None):
         return self.parse_functions()

      return self.functions

   def parse_names(self):
      addr = self.AddressOfNames.as_rva()

      if not addr.valid_rva():
         raise HeaderError('names address not a valid rva')

      length = int(self.NumberOfNames)
      self.names = LPDWORD(address=addr, length=length, copy=self.copy)
      return self.names

   def get_names(self):
      if not getattr(self, 'names', None):
         return self.parse_names()

      return self.names

   def parse_ordinals(self):
      addr = self.AddressOfNameOrdinals.as_rva()

      if not addr.valid_rva():
         raise HeaderError('ordinals address not a valid rva')

      length = int(self.NumberOfNames)
      self.ordinals = LPWORD(address=addr, length=length, copy=self.copy)
      return self.ordinals

   def get_ordinals(self):
      if not getattr(self, 'ordinals', None):
         return self.parse_ordinals()

      return self.ordinals

###############################################################################
## Import Directory
###############################################################################
class ImportDirectory(DataDirectory):
   def __init__(self, **kwargs):
      DataDirectory.__init__(self, **kwargs)

      if kwargs.setdefault('parse', 0):
         self.parse_imports()

   def parse_imports(self):
      self.parse_descriptor_table()
      self.parse_oft_thunks()
      self.parse_ft_thunks()

   def parse_descriptor_table(self):
      addr = self.VirtualAddress.as_rva()

      if not addr.valid_rva():
         raise HeaderError('directory RVA is invalid')

      table = ImportDescriptorArray.parse_descriptor_table(addr,self.copy)
      self.descriptor_table = table

      return table

   def get_descriptor_table(self):
      if not getattr(self, 'descriptor_table', None):
         return self.parse_descriptor_table()

      return self.descriptor_table

   def _parse_import_thunks(self, thunk_attr):
      descriptor_table = self.get_descriptor_table()
      arch = self.address.image.architecture()
      thunk_stubs = [ThunkData32Array,ThunkData64Array]
      thunk_data = list()

      for entry in descriptor_table:
         addr = getattr(entry, thunk_attr).as_rva()

         if not addr.valid_rva():
            DBG2('hey! %s has an invalid thunk address!', repr(entry.address))
            continue

         thunks = thunk_stubs[arch].parse_import_thunk_table(addr, self.copy)
         thunk_data.append(thunks)

      return thunk_data

   def parse_oft_thunks(self):
      self.oft_thunks = self._parse_import_thunks('OriginalFirstThunk')
      return self.oft_thunks

   def get_oft_thunks(self):
      if not getattr(self, 'oft_thunks', None):
         return self.parse_oft_thunks()

      return self.oft_thunks

   def parse_ft_thunks(self):
      self.ft_thunks = self._parse_import_thunks('FirstThunk')
      return self.ft_thunks

   def get_ft_thunks(self):
      if not getattr(self, 'ft_thunks', None):
         return self.parse_ft_thunks()

      return self.ft_thunks

   def map_descriptor_table(self):
      ret = dict()
      descriptor_table = self.get_descriptor_table()

      for entry in descriptor_table:
         name_addr = entry.Name.as_rva()

         if not name_addr.valid_rva():
            DBG2('hey! %s has an invalid name address!', repr(entry.address))
            name_value = repr(entry.address)
         else:
            name_value = name_addr.unpack_string()

         ret[name_value.upper()] = entry

      return ret

   def map_thunks(self):
      ret = dict()
      descriptor_table = self.get_descriptor_table()
      oft_thunks = self.get_oft_thunks()

      for i in xrange(len(descriptor_table)):
         entry = descriptor_table[i]
         name_addr = entry.Name.as_rva()

         if not name_addr.valid_rva():
            DBG2('hey! %s has an invalid name address!', repr(entry.address))
            name_value = repr(entry.address)
         else:
            name_value = name_addr.unpack_string()

         ret[name_value.upper()] = oft_thunks[i]

      return ret

   def map_imports(self):
      thunk_map = self.map_thunks()
      import_map = dict()

      for key in thunk_map.keys():
         import_map[key] = list()

         for thunk in thunk_map[key]:
            value = thunk.parse_import_thunk()

            if isinstance(value,ImportByName):
               import_map[key].append(str(value))
            else:
               import_map[key].append('<ordinal: 0x%04X>' % value)

      return import_map

   def write(self):
      DataDirectory.write(self)

      if getattr(self, 'entries', None):
         map(lambda x: x.write(), self.entries)

###############################################################################
## Stuff for unpacking
###############################################################################
class Unpacker: # TODO base-class for nastiness with things such as LZMA
   def __init__(self, image):
      self.image = image

   def rebuild_upx_imports(self, upx_table, library_base):
      import_dir = self.image.import_directory()
      addr = import_dir.VirtualAddress.as_rva()
      current_tables = ImportDescriptorArray.aggro_parse_descriptor_table(addr)
      current_tables = current_tables.map_entries()

      optional_header = self.image.IMAGE_OPTIONAL_HEADER
      image_base = int(optional_header.ImageBase)
      code_base = int(optional_header.BaseOfCode)
      code_start = self.image.va(image_base+code_base)

      DBG3('image base is 0x%x', image_base)
      DBG3('code base is 0x%x', code_base)
      DBG3('code starts at %s', repr(code_start))

      thunk_arrays = [ThunkData32Array,ThunkData64Array]
      thunk_types = [ThunkData32,ThunkData64]
      arch = self.image.architecture()

      DBG1('rebuilding imports')

      while not upx_table.unpack_dword() == 0:
         library_offset = upx_table.unpack_dword()
         library_name = (library_base+library_offset).unpack_string().upper()

         storage_offset = (upx_table+4).unpack_dword()
         storage_addr = code_start+storage_offset

         upx_table += 8

         DBG3('storage offset is 0x%x', storage_offset)
         DBG3('storage address is %s', repr(storage_addr))

         ent = current_tables[library_name]
         ent.FirstThunk.set_value(storage_addr.rva())
         ent.OriginalFirstThunk.set_value(storage_addr.rva())
         thunk_type = thunk_arrays[arch]
         new_iat = thunk_type(address=storage_addr.address())

         DBG2('rebuilding imports for %s', library_name)

         while not upx_table.unpack_byte() == 0:
            byte = upx_table.unpack_byte()
            upx_table += 1
            thunk_type = thunk_types[arch]
            entry = thunk_type(address=new_iat.end_address())

            if byte == 1:
               (upx_table-2).pack_word(0) # zero hints!
               entry.AddressOfData.set_value((upx_table-2).rva())
               import_val = upx_table.unpack_string()

               upx_table += len(upx_table.unpack_string())+1
            else:
               if arch:
                  value = upx_table.unpack_dword()
                  mask = 0x8000000000000000
                  size = 4
               else:
                  value = upx_table.unpack_word()
                  mask = 0x80000000
                  size = 2

               import_val = value
               entry.Ordinal.set_value(value | mask)
               upx_table += size # FIXME I've never seen a 64-bit upx table!

            DBG2('... %s => %s', repr(entry.address), repr(import_val))
            new_iat.append_element(entry)

         upx_table += 1

      DBG1('imports rebuilt')

###############################################################################
## Classes for dealing with the underlying data in the PE image
###############################################################################
# it's called PEBufferError because BufferError was already taken. sorry. :(
class PEBufferError(PEELError): # TODO some contextual stuff
   pass

class PEBuffer:
   DEFAULT_BASE_SIZE = 0x20000 # 128 kilobytes
   FLUSH_THRESHHOLD = 6 # 2 ** x stages triggers a full flush
   BUFF_R = 1
   BUFF_V = 2
   BUFF_A = 3 # hee hee hee... RVA. totally not intentional. A = ALL. :D

   # there are three buffers: 
   #     * raw (aka disk)
   #     * virtual (aka the executable image)
   #     * staged (although admittedly it's not really a buffer)
   #  
   # writes are reflected in the raw and virtual buffers-- however, they are
   # placed instead in the staging area to only be written when one of the 
   # following conditions is met:
   #     * a subsequent write or read collides with a node in the staging tree
   #     * the staging area is flushed
   #
   # the staging area is flushed if:
   #     * the height of the tree is greater than its flush threshold
   #     * an address is manually flushed
   # 
   # because this is essentially a new thing, options should be:
   #     * raw_image:      the image as if it were loaded from disk
   #     * virtual_image:  the image as if it came from memory
   #     * filename:       the filename of the PE file
   #     * map_image:      boolean flag that says whether or not to actually 
   #                       create a virtual version of the image. this applies
   #                       when receiving either a virtual image or a raw image.
   #     * base_size:      for creating a buffer. 
   #     * autoparse:      automatically parse image type when not present
   #
   # new functionality:
   #     * mirror_virtual_image

   def __init__(self, **kwargs):
      self.image = kwargs['image']

      self.autoparse = kwargs.setdefault('autoparse', 0)
      kwargs.setdefault('base_size', PEBuffer.DEFAULT_BASE_SIZE)

      DBG4("oh man! you're going extreme? my condolences!")

      if kwargs.has_key('filename'):
         self.filename = kwargs['filename']
         fp = open(kwargs['filename'], 'rb')
         self.set_raw_image(mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_COPY))
      elif kwargs.has_key('address'):
         # FIXME this sucks. seriously. why am I creating a NEW PE image object
         # FIXME to make a PE image object? there must be a better way.
         data = kwargs['address'].parse_pe()
         self.set_raw_image(data.get_raw_image()) 
      elif kwargs.has_key('raw_image'):
         self.set_raw_image(list(kwargs['raw_image']))
      elif kwargs.has_key('virtual_image'):
         self.set_virtual_image(list(kwargs['virtual_image']))
      elif kwargs.has_key('base_size'):
         self.set_raw_image(['\x00']*kwargs['base_size'])

   def md5(self):
      if not self.has_raw_image():
         raise ImageError("hash is based on raw image-- no raw image present")

      return hashlib.md5(''.join(self.raw_image[:len(self.raw_image)])).hexdigest()

   def sha1(self):
      if not self.has_raw_image():
         raise ImageError("hash is based on raw image-- no raw image present")

      return hashlib.sha1(''.join(self.raw_image[:len(self.raw_image)])).hexdigest()

   def sha256(self):
      if not self.has_raw_image():
         raise ImageError("hash is based on raw image-- no raw image present")

      return hashlib.sha256(''.join(self.raw_image[:len(self.raw_image)])).hexdigest()

   def close(self):
      if self.has_raw_image() and getattr(self.raw_image, 'close', None):
         try:
            self.raw_image.close()
         except: # don't care, sorry
            pass

         self.raw_image = None

      if self.has_virtual_image():
         self.virtual_image = None

   def resize_raw_image(self, new_size):
      if not self.has_raw_image():
         raise PEBufferError('buffer has no raw image')

      if getattr(self.raw_image, 'close', None):
         self.raw_image.resize(new_size)
         return

      current_size = len(self)
      shifted_size = new_size-current_size

      if shifted_size > 0:
         self.raw_image += ['\x00']*shifted_size
      else:
         self.raw_image = self.raw_image[:current_size-shifted_size]

   def set_raw_image(self, raw_image):
      # an object is mutable if it is unhashable.
      if getattr(raw_image, '__hash__', None) and not isinstance(raw_image, mmap.mmap):
         raw_image = list(raw_image)

      self.raw_image = raw_image
      return self.raw_image

   def set_virtual_image(self, virtual_image):
      if not isinstance(virtual_image, str):
         # let's assume it's a list. if it's not a list of ascii bytes, an exception will raise.
         try:
            virtual_image = ''.join(virtual_image)
         except TypeError: 
            raise PEBufferError("not only is the virtual image not a string, it's not even a list of strings! try again!")

      self.virtual_image = ctypes.create_string_buffer(virtual_image)
      return self.virtual_image

   def get_raw_image(self):
      if not self.has_raw_image():
         if not self.autoparse: 
            raise PEBufferError("buffer has no raw image")
         elif self.has_virtual_image():
            return self.parse_raw_image()
         else:
            raise PEBufferError("buffer has no raw or virtual image")

      return self.raw_image

   def get_virtual_image(self):
      if not self.has_virtual_image():
         if not self.autoparse: 
            raise PEBufferError("buffer has no virtual image")
         elif self.has_raw_image():
            return self.parse_virtual_image()
         else:
            raise PEBufferError("buffer has no raw or virtual image")

      return self.virtual_image

   def has_raw_image(self):
      return getattr(self, 'raw_image', None)

   def has_virtual_image(self):
      return getattr(self, 'virtual_image', None)

   def parse_raw_image(self, rewrite_sections=0):
      if not self.has_virtual_image():
         raise PEBufferError("no virtual image to parse from!")

      DBG3("getting sections")
      sections = list(self.image.get_sections())

      if rewrite_sections:
         DBG3("rewriting sections")
         for section in sections:
            section.SizeOfRawData.set_value(int(section.VirtualSize))
            section.PointerToRawData.set_value(int(section.VirtualAddress))

      DBG3("sorting sections")
      sections.sort(lambda x,y:cmp(int(x.PointerToRawData),int(y.PointerToRawData)))

      new_raw_image = list(self.virtual_image[:])

      for section in sections:
         DBG3("parsing section %s", str(section.Name))

         if int(section.PointerToRawData) == int(section.VirtualAddress):
            continue

         rva = section.VirtualAddress.as_rva()
         offset = section.PointerToRawData.as_offset()
         size = int(section.SizeOfRawData)

         write(new_raw_image, rva.rva(), '\x00'*size)
         write(new_raw_image, offset.offset(), self.read_virtual(rva, size))

      return self.set_raw_image(new_raw_image)

   def parse_virtual_image(self, rewrite_sections=0, max_addr=0x100000000):
      # thanks to Ero Carrera's pefile for making the function safe and stuff :)
      # although I think more research is in order... not *quite* sure if this
      # is the most accurate way to map offset data to memory
      if not self.has_raw_image():
         raise PEBufferError("no raw image to parse from!")

      optional = self.image.IMAGE_OPTIONAL_HEADER
      sections = list(self.image.get_sections())

      base = int(optional.ImageBase)
      virtual_image = self.raw_image[:len(self.raw_image)]

      if rewrite_sections:
         for section in sections:
            section.VirtualSize.set_value(int(section.SizeOfRawData))
            section.VirtualAddress.set_value(int(section.PointerToRawData))

      sections.sort(lambda x,y:cmp(int(x.VirtualAddress),int(y.VirtualAddress)))

      for section in sections:
         if not int(section.VirtualSize) or not int(section.SizeOfRawData):
            continue

         if int(section.SizeOfRawData) > self.raw_length():
            continue

         if self.image.align_to_file(int(section.PointerToRawData)) > self.raw_length():
            continue

         adjusted_addr = self.image.align_to_section(int(section.VirtualAddress))

         if adjusted_addr > max_addr:
            continue

         padding = adjusted_addr - len(virtual_image)

         if padding > 0:
            virtual_image += '\x00' * padding
         elif padding < 0:
            virtual_image = virtual_image[:padding]

         virtual_image += section.read_section()

      if not len(virtual_image) == int(optional.SizeOfImage):
         delta = int(optional.SizeOfImage) - len(virtual_image)

         if delta < 0:
            raise PEBufferError("the resize delta shouldn't be negative... report this, please.")

         # wtf why do I need the -1? what'd I mess up?
         virtual_image += '\x00' * (delta - 1)

      return self.set_virtual_image(virtual_image)

   def dump_raw_image(self, filename=None):
      if not self.has_raw_image():
         raise PEBufferError("can't dump a raw image that doesn't exist!")

      if not filename:
         filename = '%s.000' % self.image.md5().upper()

      fn = open(filename, 'wb')
      data = ''.join(self.raw_image[:len(self.raw_image)]) # duals for mmap/lists of strings
      fn.write(data)
      fn.close()

   def file_entropy(self):
      start = self.null()
      end = self.eof()
      return self.specific_entropy(start, end)

   def section_entropy(self):
      sections = self.get_section_map()
      ret = dict()

      for section in sections.keys():
         ret[section] = sections[section].entropy()

      return ret

   def specific_entropy(self, start_addr, end_addr):
      # algorithm lifted from ero's pefile

      data = self.get_raw_image()[start_addr.offset():end_addr.offset()]
      p_map = probability_map(data)
      data_size = len(data)*1.0
      entropy = 0

      for value in p_map.values():
         entropy -= value * math.log(x/data_size, 2)

      return abs(entropy)

   def write_virtual(self, address, data):
      self.write(address, data, PEBuffer.BUFF_V)

   def write_raw(self, address, data):
      self.write(address, data, PEBuffer.BUFF_R)

   # the 3 is PEBuffer.BUFF_R | PEBuffer.BUFF_V. I was too clever in trying to
   # be organized with my constants and shit. python was not very happy with
   # this and told me PEBuffer was undefined. jokes on you, python, now everyone
   # hates you.
   def write(self, address, data, writes=3, ignore_addrs=1, ignore_buffers=1):
      if not writes:
         raise PEBufferError("given no buffer to write to! you're nuts dude!")

      if writes > 3:
         raise PEBufferError("your buffer flags are whack! use PEBuffer.BUFF_R or PEBuffer.BUFF_V for raw and virtual respectively.")

      if writes & PEBuffer.BUFF_R:
         if not self.has_raw_image():
            DBG3("buffer doesn't have a raw image")
            if not ignore_buffers:
               raise PEBufferError("you want to write to the raw image but there isn't one!")
         elif not address.valid_offset():
            DBG3("address given isn't a valid offset")
            if not ignore_addrs:
               raise PEBufferError("you want to write to the raw image but your offset is bogus!")
         else:
            write(self.raw_image, address.offset(), data)

      if writes & PEBuffer.BUFF_V:
         if not self.has_virtual_image():
            DBG3("buffer doesn't have a virtual image")
            if not ignore_buffers:
               raise PEBufferError("you want to write to the virtual image, but there isn't one!")
         elif not address.valid_rva():
            DBG3("address given isn't a valid rva")
            if not ignore_addrs:
               raise PEBufferError("you want to write to the raw image, but your rva is bogus!")
         else:
            write(self.virtual_image, address.rva(), data)

   def read_virtual(self, address, length=0):
      return self.read(address, length, PEBuffer.BUFF_V)

   def read_raw(self, address, length=0):
      return self.read(address, length, PEBuffer.BUFF_R)

   # the 3 is PEBuffer.BUFF_R | PEBuffer.BUFF_V. I was too clever in trying to
   # be organized with my constants and shit. python was not very happy with
   # this and told me PEBuffer was undefined. jokes on you, python, now everyone
   # hates you.
   def read(self, address, length=0, reads=3):
      if not reads:
         raise PEBufferError("given no buffer to read from! this call cray!")

      if reads > 3:
         raise PEBufferError("your buffer flags are whack! use PEBuffer.BUFF_R or PEBuffer.BUFF_V for raw and virtual respectively.")

      if length < 0:
         raise PEBufferError("you can't read negative data! you're ridiculous!")

      if reads & PEBuffer.BUFF_R and self.has_raw_image():
         offset = address.offset()

         if not length:
            data = self.raw_image[offset:len(self.raw_image)]
         else:
            data = self.raw_image[offset:offset+length]
      elif reads & PEBuffer.BUFF_V and self.has_virtual_image():
         rva = address.rva()

         if not length:
            data = self.virtual_image[rva:len(self.virtual_image)]
         else:
            data = self.virtual_image[rva:rva+length]
      else:
         raise PEBufferError("couldn't find an appropriate location to read from")

      if not isinstance(data, str):
         data = ''.join(data)

      if length and not len(data) == length:
         data += '\x00' * (length - len(data))

      return data

   def raw_length(self):
      if not self.has_raw_image():
         raise PEBufferError("cannot get length of raw buffer when it doesn't exist!")

      return len(self.raw_image)

   def virtual_length(self):
      if not self.has_virtual_image():
         raise PEBufferError("cannot get length of virtual buffer when it doesn't exist!")

      return len(self.virtual_image)

   def virtual_base(self):
      if not self.has_virtual_image():
         raise PEBufferError("cannot get the base address of a virtual buffer that doesn't exist!")

      return ctypes.addressof(self.virtual_image)

   def __len__(self):
      if self.has_raw_image():
         return len(self.raw_image)
      elif self.has_virtual_image():
         return len(self.virtual_image)
      else:
         raise PEBufferError("can't get length of an image with no data!")

###############################################################################
## The star of the show
###############################################################################
LINK_IDENTIFIERS = set()

class ImageError(PEELError): # TODO some contextual stuff
   pass

class FunctionError(PEELError):
   pass

class AssemblyError(PEELError):
   pass

# TODO the error context class
class ExceptionError(FunctionError):
   def __init__(self, context):
      self.context = context

   def __str__(self):
      return 'Function prototype raised an exception; see context for details.'

class Link:
   DATA = '\x00\x00\x00\x00'
   SIZE = 4
   STORAGE = 0

   def __init__(self, **kwargs):
      self.storage = kwargs.setdefault('storage', self.STORAGE)
      self.data = kwargs.setdefault('data', self.DATA)
      self.size = kwargs.setdefault('size', self.SIZE)

   def linker(self, assembly):
      write(assembly.instructions, self.get_storage(assembly), self.get_data(assembly))

   def get_storage(self, assembly):
      return self.storage

   def get_data(self, assembly):
      return self.data

   def get_define(self):
      return 'dd     0x%08X' % self.get_identifier()

   def get_identifier(self):
      if not getattr(self, '_identifier', None):
         self._identifier = self._generate_identifier()

      return self._identifier

   def find_all_identifiers(self, assembly):
      ident_data = list()
      ident = self.get_identifier()

      for i in xrange(self.size):
         ident_data.append(chr(ident & 0xFF))
         ident >>= 8

      ident = ''.join(ident_data)
      data = assembly.instructions[:]
      indeces = list()
      index = 0

      while ident in data:
         index = data.index(ident)
         indeces.append(indeces[-1]+index if len(indeces) else index)
         data = data[index + len(ident):]

      return indeces

   def _generate_identifier(self):
      global LINK_IDENTIFIERS

      shifter = self.size-1
      identifier = random.randint(0x80 << shifter*8, 0xFF << shifter*8)

      while identifier in LINK_IDENTIFIERS:
         identifier = random.randint(0x80 << shifter*8, 0xFF << shifter*8)

      LINK_IDENTIFIERS.add(identifier)
      self._identifier = identifier
      return self._identifier

class DirectAddressLink(Link):
   def __init__(self, **kwargs):
      self.address = kwargs['address']
      Link.__init__(self, **kwargs)
      
   def linker(self, assembly):
      # TODO this should be handled outside this class to more efficiently make use of it
      identifiers = self.find_all_identifiers(assembly)

      for identifier in identifiers:
         self.storage = identifier
         Link.linker(self, assembly)

   def get_define(self):
      return '0x%08X' % self.get_identifier()

   def get_data(self, assembly):
      return pack_dword(self.address)

class IndirectAddressLink(DirectAddressLink):
   def __init__(self, **kwargs):
      DirectAddressLink.__init__(self, **kwargs)
      self.offset_from_storage = kwargs.setdefault('offset_from_storage', 4)

   def get_data(self, assembly):
      return pack_dword(calculate_delta(self.address,self.get_storage(assembly)+self.offset_from_storage))

# the assembly objects are a different beast entirely from the rest of this project
# (though in a wonderfully awesome way). I need to establish some common variables to
# be passed around between all the different classes:
#
#     * address:  a number of some kind. it's intended to be a pointer into some memory
#                 location.
#     * argc:     the number of arguments to be pushed onto the stack.
#
class Assembly:
   CODE_IDENT = '\x08\xEEPEELCODE\xEE\x0D'
   DATA_IDENT = '\x08\xEEPEELDATA\xEE\x0D'

   DEFINES = [
      ('PASM_CODE_IDENT',     "db 0x8,0xEE,'PEELCODE',0xEE,0x0D"),
      ('PASM_DATA_IDENT',     "db 0x8,0xEE,'PEELDATA',0xEE,0x0D"),
      ('PASM_ARG_REGISTER',   'ebp'),
      ('PASM_DATA_REGISTER',  'edx'),
      ('PASM_IDENT_SIZE',     '12'),
      ('PASM_OFFSET(o)',      '(o-PASM_DATA_SECTION)'),
      ('PASM_DATA(n)',        'PASM_DATA_REGISTER+PASM_OFFSET(n)'),
      ('PASM_ARG(o)',         'PASM_ARG_REGISTER+(o*4+(2*4))'),
      ('PASM_RETVAL',         'PASM_ARG(-3)'),
      ('PASM_PUSHAD_ARG(o)',  'PASM_ARG_REGISTER+(o*4+(9*4))'),
      ('PASM_PUSHAD_RETVAL',  'PASM_ARG(8)'),
      ('PASM_PUSHAD_EAX',     'PASM_ARG(7)'),
      ('PASM_PUSHAD_ECX',     'PASM_ARG(6)'),
      ('PASM_PUSHAD_EDX',     'PASM_ARG(5)'),
      ('PASM_PUSHAD_EBX',     'PASM_ARG(4)'),
      ('PASM_PUSHAD_ESP',     'PASM_ARG(3)'),
      ('PASM_PUSHAD_EBP',     'PASM_ARG(2)'),
      ('PASM_PUSHAD_ESI',     'PASM_ARG(1)'),
      ('PASM_PUSHAD_EDI',     'PASM_ARG(0)'),
      ('SIZEOF_CONTEXT',      '%d' % sizeof(CONTEXT)),
   ]

   MACROS = [
      ('PASM_PUSHLOOP', '2', '''
         mov   ecx,%1
         dec   ecx
         lea   eax,dword [%2]
         lea   eax,dword [eax+ecx*4]

%%pushloop:
         js    %%endloop 
         push  dword [eax]
         sub   eax,4
         dec   ecx
         jmp   %%pushloop
%%endloop:
      '''),

      ('PASM_FUNCTION', '0', '''
%%top:   push     PASM_ARG_REGISTER
         mov      PASM_ARG_REGISTER,esp
         push     PASM_DATA_REGISTER
         call     %%next
%%next:  pop      PASM_DATA_REGISTER
         sub      PASM_DATA_REGISTER,%%next-%%top
         add      PASM_DATA_REGISTER,PASM_DATA_SECTION-PASM_IDENT_SIZE
      '''),

      ('PASM_PUSHAD_FUNCTION', '0', '''
%%top:   pushad
         mov      PASM_ARG_REGISTER,esp
         call     %%next
%%next:  pop      PASM_DATA_REGISTER
         sub      PASM_DATA_REGISTER,%%next-%%top
         add      PASM_DATA_REGISTER,PASM_DATA_SECTION-PASM_IDENT_SIZE
      '''),

      ('PASM_RET', '1', '''
         pop      PASM_DATA_REGISTER
         pop      PASM_ARG_REGISTER
         ret      %1*4
      '''),

      ('PASM_PUSHAD_RET', '1', '''
         popad
         ret      %1*4
      '''),
   ]

   DATA = list()
   LINKS = dict()
   ASSEMBLY = None
   ASSEMBLY_FILE = None

   def __init__(self, **kwargs):
      self.defines = kwargs.setdefault('defines', self.DEFINES[:])
      self.macros = kwargs.setdefault('macros', self.MACROS[:])
      self.data = kwargs.setdefault('data', self.DATA[:])
      self.assembly = kwargs.setdefault('assembly', self.ASSEMBLY)
      self.assembly_file = kwargs.setdefault('assembly_file', self.ASSEMBLY_FILE)
      self.links = kwargs.setdefault('links', dict(self.LINKS.items()[:]))

      if kwargs.has_key('instructions'):
         self.instructions = kwargs['instructions'][:]

   def add_define(self, name, value):
      self.defines.append((name, value))

   def add_macro(self, name, arguments, instructions):
      self.macros.append((name, arguments, instructions))

   def add_data(self, label, data):
      self.data.append((label, data))

   def add_link(self, name, link):
      self.links[name] = link

   def get_instructions(self):
      if not getattr(self, 'instructions', None):
         self.pre_build()
         self.instructions = executable_buffer(self.build_instructions())
         self.post_build()

         self.pre_link()
         self.link()
         self.post_link()

      return self.instructions

   def pre_build(self):
      for linkname in self.links.keys():
         self.add_define(linkname,self.links[linkname].get_define())

   def post_build(self):
      pass

   def build_instructions(self):
      final_assembly = ''';---------------------------------;
; PEEL NASM data
; defines
%s

; macros
%s
      
      PASM_CODE_IDENT
      ; assembly content
      %s

      PASM_DATA_IDENT
PASM_DATA_SECTION:
      %s
;---------------------------------;''' % (self.compile_defines(), self.compile_macros(), self.get_assembly(), self.compile_data())

      return assemble_code(final_assembly)

   def pre_link(self):
      pass

   def post_link(self):
      pass

   def link(self):
      for linkname in self.links.keys():
         self.links[linkname].linker(self)

   def get_assembly(self):
      if self.assembly:
         return self.assembly
      elif self.assembly_file:
         fp = open(self.assembly_file)
         self.assembly = fp.read()
         fp.close()
      else:
         raise AssemblyError('class has no assembly code')

      return self.assembly

   def compile_defines(self):
      ret = list()
      for define in self.get_defines(): ret.append('%%define\t%s\t%s' % define)
      return '\n'.join(ret)

   def compile_macros(self):
      ret = list()
      for macro in self.get_macros(): ret.append('%%macro\t%s\t%s\n%s\n%%endmacro' % macro)
      return '\n'.join(ret)

   def compile_data(self):
      ret = list()
      for data in self.get_data(): ret.append('%s: %s' % data)
      return '\n'.join(ret)

   def get_defines(self):
      return self.defines

   def get_macros(self):
      return self.macros

   def get_data(self):
      return self.data

   def get_offset_to_code(self):
      instructions_string = self.get_instructions().raw

      if not self.CODE_IDENT in instructions_string:
         if is_spicy():
            DBG3('code ident: %s', ' '.join(map(lambda x: '%02X' % x, map(ord,self.CODE_IDENT))))
            DBG3('instructions: %s', ' '.join(map(lambda x: '%02X' % x, map(ord,self.get_instructions()))))

         raise AssemblyError('magic value for data not found')

      return instructions_string.index(self.CODE_IDENT)+len(self.CODE_IDENT)

   def get_offset_to_data(self):
      instructions_string = self.get_instructions().raw

      if not self.DATA_IDENT in instructions_string:
         if is_spicy():
            DBG3('data ident: %s', ' '.join(map(lambda x: '%02X' % x, map(ord,self.DATA_IDENT))))
            DBG3('instructions: %s', ' '.join(map(lambda x: '%02X' % x, map(ord,self.get_instructions()))))

         raise AssemblyError('magic value for data not found')

      return instructions_string.index(self.DATA_IDENT)+len(self.DATA_IDENT)

   def get_address_of_code(self):
      return ctypes.addressof(self.get_instructions())+self.get_offset_to_code()

   def get_address_of_data(self):
      return ctypes.addressof(self.get_instructions())+self.get_offset_to_data()

class AssemblyList(Assembly):
   LIST_LINKS = list()

   def __init__(self, **kwargs):
      self.parent = None
      self.child = None

      list_links = kwargs.setdefault('list_links', self.LIST_LINKS[:])

      if len(list_links):
         list_link = list_links.pop(0)
         self.child = list_link(**kwargs)
         self.child.parent = self

      Assembly.__init__(self, **kwargs)

   def get_instructions(self):
      if self.child:
         instructions = self.child.get_instructions()
      else:
         instructions = Assembly.get_instructions(self)

      return instructions

   def map_parent_first(self, function):
      ret = list() 

      child = self

      while child:
         ret.append(function(child))
         child = child.child

      return ret

   def map_child_first(self, function):
      ret = list()

      child = self
      
      while child.child:
         child = child.child

      while child:
         ret.append(function(child))
         child = child.parent

      return ret

   @classmethod
   def static(cls, *args):
      class StaticList(cls):
         LIST_LINKS = cls.LIST_LINKS+list(args)

      return StaticList

class AddressChainedAssemblyList(AssemblyList):
   def post_build(self):
      DBG3('hit AddressChainedAssemblyList::post_build')

      if self.parent:
         DBG3('parent.address = 0x%08X' % self.get_address_of_code())
         self.parent.address = self.get_address_of_code()

      AssemblyList.post_build(self)

class ExceptionHandlerCode(Assembly):
   DEFINES = Assembly.DEFINES[:] + [
      ('HANDLER_STACK(n)',          'PASM_ARG(n)'),
      ('HANDLER_DATA(v)',           'PASM_DATA(v)'), 

      ('STRUCT(r,o)',               'r+o'),

      ('EXCEPTION_POINTERS',        'HANDLER_STACK(0)'),
      ('EXCEPTION_RECORD(r)',       'STRUCT(r,0x0)'),
         ('RECORD_FLAGS(r)',           'STRUCT(r,0x4)'),
      ('EXCEPTION_CONTEXT(r)',      'STRUCT(r,0x4)'),
         ('CONTEXT_ESP(r)',            'STRUCT(r,0xC4)'),
         ('CONTEXT_EIP(r)',            'STRUCT(r,0xB8)'),
         ('CONTEXT_EBP(r)',            'STRUCT(r,0xB4)'),
         ('CONTEXT_EAX(r)',            'STRUCT(r,0xB0)'),
         ('CONTEXT_ECX(r)',            'STRUCT(r,0xAC)'),
         ('CONTEXT_EDX(r)',            'STRUCT(r,0xA8)'),
         ('CONTEXT_EBX(r)',            'STRUCT(r,0xA4)'),
         ('CONTEXT_ESI(r)',            'STRUCT(r,0xA0)'),
         ('CONTEXT_EDI(r)',            'STRUCT(r,0x9C)'),

      ('HANDLER_EAX',              'PASM_DATA(lastcall_eax)'),
      ('HANDLER_ECX',              'PASM_DATA(lastcall_ecx)'),
      ('HANDLER_EBX',              'PASM_DATA(lastcall_ebx)'),
      ('HANDLER_EDX',              'PASM_DATA(lastcall_edx)'),
      ('HANDLER_ESI',              'PASM_DATA(lastcall_esi)'),
      ('HANDLER_EDI',              'PASM_DATA(lastcall_edi)'),
      ('HANDLER_EBP',              'PASM_DATA(lastcall_ebp)'),
      ('HANDLER_ESP',              'PASM_DATA(lastcall_esp)'),

      ('HANDLER_STACK_CONTEXT(r)', 'STRUCT(r,0x0)'),
      ('HANDLER_STACK_EXIT(r)',    'STRUCT(r,0x4)'),
      ('HANDLER_STACK_EDI(r)',     'STRUCT(r,0x8)'),
      ('HANDLER_STACK_ESI(r)',     'STRUCT(r,0xC)'),
      ('HANDLER_STACK_EBP(r)',     'STRUCT(r,0x10)'),
      ('HANDLER_STACK_ESP(r)',     'STRUCT(r,0x14)'),
      ('HANDLER_STACK_EBX(r)',     'STRUCT(r,0x18)'),
      ('HANDLER_STACK_EDX(r)',     'STRUCT(r,0x1C)'),
      ('HANDLER_STACK_ECX(r)',     'STRUCT(r,0x20)'),
   ]

   ASSEMBLY = '''
PASM_FUNCTION
      mov      eax,dword [EXCEPTION_POINTERS]

      mov      ecx,dword [EXCEPTION_CONTEXT(eax)]
      mov      dword [HANDLER_DATA(context_pointer)],ecx
      test     ecx,ecx
      jz       handler_continue_search

      mov      eax,dword [EXCEPTION_RECORD(eax)]
      test     eax,eax
      jz       handler_continue_search

      mov      ecx,dword [RECORD_FLAGS(eax)]
      test     ecx,ecx
      jnz      handler_cant_continue 

      push     esi
      mov      esi,dword [HANDLER_DATA(context_pointer)]
      push     edi
      lea      edi,dword [HANDLER_DATA(context_data)]
      mov      ecx,SIZEOF_CONTEXT
      repne    movsb
      pop      edi
      pop      esi

handler_continue_search:
      xor      eax,eax                               ; EXCEPTION_CONTINUE_SEARCH

handler_quit:
      PASM_RET 1

handler_cant_continue:
      ; transfer control back to right after ctypes originally called our code
      push     esi
      lea      esi,dword [HANDLER_DATA(lastcall_edi)]
      push     edi
      mov      edi,dword [HANDLER_DATA(context_pointer)]

      ; set eax to 0
      mov      dword [CONTEXT_EAX(edi)],0

      ; set the registers to what they were before the call in the context structure
      mov      eax,dword [HANDLER_STACK_ESP(esi)]
      mov      dword [CONTEXT_ESP(edi)],eax
      mov      eax,dword [HANDLER_STACK_EBP(esi)]
      mov      dword [CONTEXT_EBP(edi)],eax
      mov      eax,dword [HANDLER_STACK_ESI(esi)]
      mov      dword [CONTEXT_ESI(edi)],eax
      mov      eax,dword [HANDLER_STACK_EDI(esi)]
      mov      dword [CONTEXT_EDI(edi)],eax
      mov      eax,dword [HANDLER_STACK_EBX(esi)]
      mov      dword [CONTEXT_EBX(edi)],eax
      mov      eax,dword [HANDLER_STACK_ECX(esi)]
      mov      dword [CONTEXT_ECX(edi)],eax
      mov      eax,dword [HANDLER_STACK_EDX(esi)]
      mov      dword [CONTEXT_EDX(edi)],eax

      ; set the original exit as the context's eip
      mov      eax,dword [HANDLER_STACK_EXIT(esi)]
      mov      dword [CONTEXT_EIP(edi)],eax

      ; because of the return value
      add      dword [CONTEXT_ESP(ecx)],4

      xor      eax,eax
      dec      eax                                 ;  EXCEPTION_CONTINUE_EXECUTION

      jmp      handler_quit
   '''

   DATA = [
      ('context_pointer',     'dd 0'),
      ('function_exit',       'dd 0'),
      ('lastcall_edi',        'dd 0'),
      ('lastcall_esi',        'dd 0'),
      ('lastcall_ebp',        'dd 0'),
      ('lastcall_esp',        'dd 0'),
      ('lastcall_ebx',        'dd 0'),
      ('lastcall_edx',        'dd 0'),
      ('lastcall_ecx',        'dd 0'),
      ('lastcall_eax',        'dd 0'),
      ('context_data',        'resb SIZEOF_CONTEXT'),
   ]

   EXCEPTION_HANDLER = None

   def __init__(self, **kwargs):
      self.exception_handler = kwargs.setdefault('exception_handler', self.EXCEPTION_HANDLER)
      Assembly.__init__(self, **kwargs)

   def handle_stolen_exception(self):
      target = self.get_offset_to_data()
      data = self.get_instructions()[target:]

      DBG4('target=0x%08X data=%s', target, ' '.join(map(lambda x: '%02X' % x, map(ord, data))))
      context_record = unpack_dword(data[0:4])

      if not context_record:
         return

      context_record = self.get_address_of_data()+0x28
      context_data = ctypes.string_at(context_record, sizeof(CONTEXT))
      DBG4('context_data=%s', ' '.join(map(lambda x: '%02X' % x, map(ord, context_data))))

      context_object = CONTEXT(data=context_data)

      if not self.exception_handler or self.exception_handler(context_object) == 1:
         raise ExceptionError(context_object)

class ExceptionWrapperCode(AddressChainedAssemblyList):
   DEFINES = AddressChainedAssemblyList.DEFINES[:] + ExceptionHandlerCode.DEFINES[:] + [
      ('WRAPPER_STACK(n)',          'PASM_ARG(n)'),
      ('WRAPPER_DATA(v)',           'PASM_DATA(v)'), 
   ]

   ASSEMBLY = '''
PASM_PUSHAD_FUNCTION
      ; store the current stack state at the time of the call, accounting for arguments
      mov      eax,dword [WRAPPER_DATA(handler_stack_state)]
      mov      ecx,dword [PASM_PUSHAD_RETVAL]
      mov      dword [HANDLER_STACK_EXIT(eax)],ecx

      lea      esi,dword [PASM_PUSHAD_EDI]
      lea      edi,dword [HANDLER_STACK_EDI(eax)]
      lea      ecx,dword [PASM_PUSHAD_RETVAL]
      sub      ecx,esi
      repnz    movsb

%ifdef WRAPPER_ARGS
      PASM_PUSHLOOP WRAPPER_ARGS,WRAPPER_STACK(0)
%endif

      lea      eax,dword [WRAPPER_DATA(return_wrapper)]
      push     eax
      mov      eax,OriginalAddress           ; the underlying function we're wrapping
      jmp      eax
   '''

   DATA = [
      ('handler_stack_state',    'dd   RemoteStackState'),
      ('return_wrapper', '''

      ; if we made it here, the function executed successfully.
      push     eax
      push     ecx

      mov      ecx,dword [WRAPPER_DATA(handler_stack_state)]
      xor      eax,eax
      mov      dword [HANDLER_STACK_CONTEXT(ecx)],eax

      pop      ecx
      pop      eax
      popad

%ifdef WRAPPER_ARGS
      ret      WRAPPER_ARGS*4
%else
      ret
%endif
      '''),
   ]

   HANDLER_CODE = ExceptionHandlerCode

   def __init__(self, **kwargs):
      self.handler_code = kwargs.setdefault('handler_code', self.HANDLER_CODE)

      AddressChainedAssemblyList.__init__(self, **kwargs)

      self.address = kwargs['address']
      self.argc = kwargs['argc']

      DBG3('ExceptionWrapperCode kwargs=%s', repr(kwargs))

      if self.handler_code:
         self.handler_code = self.handler_code(**kwargs)

   def pre_build(self):
      if getattr(self, 'argc', 0):
         self.add_define('WRAPPER_ARGS', '%d' % self.argc)

      self.add_link('OriginalAddress', DirectAddressLink(address=self.address))
      self.add_link('RemoteStackState', DirectAddressLink(address=self.handler_code.get_address_of_data()))

      AddressChainedAssemblyList.pre_build(self) 

class UsercallCode(AddressChainedAssemblyList):
   DEFINES = AddressChainedAssemblyList.DEFINES[:] + [
      ('USERCALL_MOV_ARG(r,o)',        'mov  r,dword [ebp+((o+2)*4)]'),
      ('USERCALL_PUSH_ARG(r,o)',       'push dword [ebp+((o+2)*4)]'),   
      ('USERCALL_MOV_RET_REG(r)',      'mov  r,eax'),
      ('USERCALL_REALIGN_STACK(c)',    'add  esp,c*4'),
      ('USERCALL_RET_STACK(c)',        'ret  c*4'),
      ('USERCALL_RET',                 'ret'),
   ]

   ASSEMBLY = '''
      push     ebp
      mov      ebp,esp
      USERCALL_MOV_INSTRUCTIONS
      USERCALL_PUSH_INSTRUCTIONS
      call     TargetAddress
      USERCALL_RETURN_REGISTER
      USERCALL_FIX_STACK
      pop      ebp
      USERCALL_RETURN
   '''

   REALIGN_STACK = 0

   def __init__(self, **kwargs):
      self.target_registers = kwargs.setdefault('target_registers', self.TARGET_REGISTERS[:])
      self.return_register = kwargs.setdefault('return_register', self.RETURN_REGISTER)
      self.realign_stack = kwargs.setdefault('realign_stack', self.REALIGN_STACK)

      AddressChainedAssemblyList.__init__(self, **kwargs)

   def pre_build(self):
      argc = len(self.argtypes)
      reg_args = len(self.target_registers)
      stack_args = 0

      if not reg_args == argc:
         stack_args = argc - reg_args

      movs = list()
      pushes = list()
      return_register = ''
      stack_fix = ''
      ret = 'USERCALL_RET'
      i = 0

      while i < reg_args:
         movs.append('USERCALL_MOV_ARG(%s,%d)' % (self.target_registers[i], i))
         i += 1

      while i < argc:
         pushes.append('USERCALL_PUSH_ARG(%d)' % i)

      if not self.return_register == 'eax':
         return_register = 'USERCALL_MOV_RET_REG(%s)' % self.return_register

      if stack_args:
         if self.realign_stack:
            stack_fix = 'USERCALL_REALIGN_STACK(%d)' % stack_args
         else:
            ret = 'USERCALL_RET_STACK(%d)' % stack_args

      self.add_define('USERCALL_MOV_INSTRUCTIONS',    '\n\t'.join(movs))
      self.add_define('USERCALL_PUSH_INSTRUCTIONS',   '\n\t'.join(pushes))
      self.add_define('USERCALL_RETURN_REGISTER',     self.return_register)
      self.add_define('USERCALL_FIX_STACK',           stack_fix)
      self.add_define('USERCALL_RETURN',              ret)

      self.links['TargetAddress'] = IndirectAddressLink(address=self.address)

      AddressChainedAssemblyList.pre_build(self)

class FunctionPrototype:
   ADDRESS = None
   RETTYPE = ctypes.c_ulong
   ARGTYPES = list()
   ENTRYPOINT = 0

   def __init__(self, **kwargs):
      self.address = kwargs.setdefault('address', self.ADDRESS)
      self.rettype = kwargs.setdefault('rettype', self.RETTYPE)
      self.argtypes = kwargs.setdefault('argtypes', self.ARGTYPES)
      self.entrypoint = kwargs.setdefault('entrypoint', self.ENTRYPOINT)

   def has_function(self):
      return getattr(self, 'function', None)

   def get_function(self):
      if self.has_function():
         return self.function
      else:
         return self.parse_function()

   def get_prototype(self):
      return ctypes.WINFUNCTYPE(self.rettype, *self.argtypes)

   def parse_function(self):
      prototype = self.get_prototype()
      self.function = prototype(self.get_prototype_target())

      if is_spicy():
         DBG3('function call: %s', repr(self))
         DBG3('prototype target: 0x%08X', self.get_prototype_target())

      return self.function

   def get_prototype_target(self):
      DBG3('FunctionPrototype::get_prototype_target')

      if not getattr(self, 'address', None):
         raise FunctionError("class has no address data")

      return self.address

   def __call__(self, *args):
      if is_spicy():
         DBG3('function call: %s', repr(self))

      return self.get_function()(*args)

   @classmethod
   def call(cls, *args, **kwargs):
      DBG3('hit FunctionPrototype::call')

      if not kwargs.has_key('address'):
         kwargs['address'] = getattr(cls, 'ADDRESS', None)

      return cls(**kwargs)(*args)

PythonSTDCALLPrototype = FunctionPrototype

class PythonCDECLPrototype(FunctionPrototype):
   def get_prototype(self):
      return ctypes.CDECLTYPE(self.rettype, *self.argtypes)

class ExecutableCode:
   CODE = None
   PROTOTYPE = PythonSTDCALLPrototype
   ENTRYPOINT = 0

   def __init__(self, **kwargs):
      self.code = kwargs.setdefault('code', self.CODE)
      self.prototype = kwargs.setdefault('prototype', self.PROTOTYPE)
      self.entrypoint = kwargs.setdefault('entrypoint', self.ENTRYPOINT)

      if not self.code:
         raise AssemblyError('no code to execute')

      if not self.prototype:
         raise AssemblyError('no prototype to apply to executable code')

      self.code = self.code(**kwargs)
      self.prototype = self.prototype(**kwargs)

   def get_entrypoint(self):
      return self.entrypoint

   def get_prototype(self):
      if not self.prototype:
         raise AssemblyError('no prototype to apply to executable code')

      return self.prototype.get_prototype()

   def get_function(self):
      if getattr(self, 'function', None):
         return self.function
      else:
         return self.parse_function()

   def parse_function(self):
      prototype = self.get_prototype()
      self.function = prototype(self.get_prototype_target())

      if is_spicy():
         DBG3('function call: %s', repr(self))
         DBG3('prototype target: 0x%08X', self.get_prototype_target())
         DBG3('address of code: 0x%08X', self.code.get_address_of_code())

      return self.function

   def get_prototype_target(self):
      DBG3('ExecutableCode::get_prototype_target')
      return self.code.get_address_of_code()+self.get_entrypoint()

   def __call__(self, *args):
      if is_spicy():
         DBG3('function call: %s', repr(self))

      return self.get_function()(*args)

   @classmethod
   def call(cls, *args, **kwargs):
      DBG3('hit ExecutableAssembly::call')
      return cls(**kwargs)(*args)

class ExceptedPrototype(FunctionPrototype, ExecutableCode):
   CODE = AddressChainedAssemblyList.static(ExceptionWrapperCode)

   def __init__(self, **kwargs):
      FunctionPrototype.__init__(self, **kwargs)

      self.argc = kwargs.setdefault('argc', len(kwargs.setdefault('argtypes', FunctionPrototype.ARGTYPES)))

      ExecutableCode.__init__(self, **kwargs)

   def get_prototype_target(self):
      return ExecutableCode.get_prototype_target(self)

   def get_function(self):
      if not getattr(self, 'function', None):
         self.function = self.parse_function()

      return self._exception_handler

   def _exception_handler(self, *args):
      DBG3('hit ExceptedPrototype::_exception_handler')
      AddVectoredExceptionHandler(1, self.code.child.handler_code.get_address_of_code())

      child = self.code

      while child:
         if not getattr(child, 'instructions', None):
            DBG3('%s has no instructions', repr(child))
         else:
            DBG3('%s instruction length: %d', repr(child), len(child.get_instructions()))

         child = child.child

      DBG3('function target=0x%08X', self.get_prototype_target())
      DBG3('handler target=0x%08X', self.code.child.handler_code.get_address_of_code())

      try:
         DBG3('executing')
         retval = self.function(*args)
         DBG3('success; returning')
         return retval
      except WindowsError: # python got it first
         DBG3('python got the error before us')
         pass
      finally:
         DBG3('removing exception handler')
         RemoveVectoredExceptionHandler(self.get_prototype_target())

      DBG3('attempting to raise custom exception...')
      self.code.child.handler_code.handle_stolen_exception()
      DBG3('no exception to raise')
      return retval

STDCALLPrototype = ExceptedPrototype

class CDECLPrototype(ExceptedPrototype):
   FUNC_PROTOTYPE = PythonCDECLPrototype

class UsercallPrototype(ExceptedPrototype):
   CODE = ExceptedPrototype.CODE.static(UsercallCode)
   TARGET_REGISTERS = list()
   RETURN_REGISTER = 'eax'
   REALIGN_STACK = 0

   def __init__(self, **kwargs):
      self.target_registers = kwargs.setdefault('target_registers', self.TARGET_REGISTERS[:])
      self.return_register = kwargs.setdefault('return_register', self.RETURN_REGISTER)
      self.realign_stack = kwargs.setdefault('realign_stack', self.REALIGN_STACK)

      ExceptedPrototype.__init__(self, **kwargs)

class ThiscallPrototype(UsercallPrototype):
   TARGET_REGISTERS = ['ecx']

class MSFastcallPrototype(UsercallPrototype):
   TARGET_REGISTERS = ['ecx', 'edx']

class BorlandFastcallPrototype(UsercallPrototype):
   TARGET_REGISTERS = ['eax', 'edx', 'ecx']

class WatcomPrototype(UsercallPrototype):
   TARGET_REGISTERS = ['eax', 'edx', 'ebx', 'ecx']

if WIN32_COMPATIBLE:
   class WinMainPrototype(STDCALLPrototype):
      ARGTYPES = [ctypes.wintypes.HINSTANCE, ctypes.wintypes.HINSTANCE, ctypes.wintypes.LPSTR, ctypes.c_ulong]

      @classmethod
      def call(cls, *args, **kwargs):
         kwargs.setdefault('address', cls.ADDRESS)

         if len(args) == 0:
            instance = self.address.image.virtual_base()
            args = ctypes.windll.GetCommandLineA()
            return cls(**kwargs)(instance, 1, args, 1)
         else:
            return cls(**kwargs)(*args)

class GetModuleHandleCode(Assembly):
   ASSEMBLY = '''
      mov      eax,  [fs:0x18]
      mov      eax,  [eax+0x30]
      mov      eax,  [eax+8]
      ret
   '''

class GetModuleHandlePrototype(STDCALLPrototype):
   CODE = STDCALLPrototype.CODE.static(GetModuleHandleCode)

class SetModuleHandleCode(Assembly):
   ASSEMBLY = '''
      mov      eax,  [fs:0x18]
      mov      eax,  [eax+0x30]
      mov      ecx,  [esp+4]
      mov      [eax+8],ecx
      ret      4
   '''

class SetModuleHandlePrototype(STDCALLPrototype):
   ARGTYPES = [ctypes.c_ulong]
   CODE = STDCALLPrototype.CODE.static(SetModuleHandleCode)

class PEImage:
   XP_COMPATABILITY = 1
   VISTA_COMPATABILITY = 2
   WIN7_COMPATABILITY = 4
   X86_COMPATABILITY = 8
   X64_COMPATABILITY = 16

   def __init__(self, **kwargs):
      self.buff = PEBuffer(image=self, **kwargs)
      self.is_executable = 0

      self._offset_pool = dict()
      self._rva_pool = dict()
      self._va_pool = dict()
      self._handle = 0
      self._hijacked = 0

      if kwargs.setdefault('make_executable', 0):
         kwargs['map_image'] = 1
      else:
         kwargs.setdefault('map_image', 0)

      if kwargs['map_image']: 
         rewrite = kwargs.setdefault('rewrite_sections', 0)

         if self.has_virtual_image():
            self.parse_raw_image(rewrite)
         elif self.has_raw_image():
            self.parse_virtual_image(rewrite)

         if kwargs['make_executable']:
            self.make_executable()

      if kwargs.setdefault('basic_headers', 0):
         dos_header = IMAGE_DOS_HEADER(address=self.offset(0), set_defaults=1)
         nt_headers = IMAGE_NT_HEADERS32(address=dos_header.e_lfanew.as_offset(), set_defaults=1)

   def __repr__(self):
      headers = self.get_headers()
      return_data = list()

      for header in headers:
         return_data.append(repr(header))

      return '\n'.join(return_data)

   # TODO def make_32bit_stub_header()
   # TODO def make_64bit_stub_header()

   def md5(self):
      return self.buff.md5()

   def sha1(self):
      return self.buff.sha1()

   def sha256(self):
      return self.buff.sha256()

   def close(self):
      self.buff.close()

   def resize_raw_image(self, new_size):
      self.buff.resize_raw_image(new_size)

   def set_raw_image(self, raw_image):
      return self.buff.set_raw_image(raw_image)

   def set_virtual_image(self, virtual_image):
      return self.buff.set_virtual_image(virtual_image)

   def get_raw_image(self):
      return self.buff.get_raw_image()

   def get_virtual_image(self):
      return self.buff.get_virtual_image()

   def has_raw_image(self):
      return self.buff.has_raw_image()

   def has_virtual_image(self):
      return self.buff.has_virtual_image()

   def parse_raw_image(self, rewrite_sections=0):
      return self.buff.parse_raw_image(rewrite_sections)

   def parse_virtual_image(self, rewrite_sections=0, max_addr=0x100000000):
      return self.buff.parse_virtual_image(rewrite_sections, max_addr)

   def file_entropy(self):
      return self.buff.file_entropy()

   def section_entropy(self):
      return self.buff.section_entropy()

   def specific_entropy(self, start_addr, end_addr):
      return self.buff.specific_entropy(start_addr, end_addr)

   def parse_headers(self):
      self.parse_dos_header()
      self.parse_nt_header()
      self.parse_file_header()
      self.parse_optional_header()
      self.parse_data_directories()
      self.parse_sections()

   def get_headers(self):
      return [self.get_dos_header(), self.get_nt_header(),
              self.get_file_header(), self.get_optional_header()]

   def parse_dos_header(self):
      # we manually set the offset and the rva here because at this point the
      # rva and the offset are equal. since there's a possibility that either
      # the virtual image or the raw image can be present, both of these values
      # are necessary to be set because of how addresses work.
      addr = self.offset(0)
      addr._rva = 0

      self.dos_header = parse_dos_header_from_address(addr)
      return self.dos_header

   def get_dos_header(self):
      if not self.has_dos_header():
         return self.parse_dos_header()

      return self.dos_header

   def has_dos_header(self):
      return getattr(self, 'dos_header', None)

   def set_dos_header(self, dos_header):
      if not isinstance(dos_header, DOSHeader):
         raise ImageError("dos_header not a DOSHeader instance")

      self.dos_header = dos_header
      return self.dos_header

   def parse_nt_header(self):
      dos_header = self.get_dos_header()

      # XXX HACK this rva thing might cause bugs.
      nt_offset = dos_header.e_lfanew.as_offset()
      nt_offset._rva = nt_offset._offset

      if get_verbosity() > 1:
         DBG2('assuming NT header at 0x%x', int(nt_offset))

      if self.has_raw_image() and not nt_offset.valid_offset() or self.has_virtual_image() and not nt_offset.valid_rva():
         raise HeaderError("e_lfanew is not a valid address")

      self.nt_header = parse_nt_header_from_address(nt_offset)
      return self.nt_header

   def get_nt_header(self):
      if not self.has_nt_header():
         return self.parse_nt_header()

      return self.nt_header

   def has_nt_header(self):
      return getattr(self, 'nt_header', None)

   def set_nt_header(self, nt_header):
      if not isinstance(nt_header, NTHeader):
         raise ImageError("nt_header not a DOSHeader instance")

      self.nt_header = nt_header
      return self.nt_header

   def parse_file_header(self):
      nt_header = self.get_nt_header()

      # XXX HACK this rva thing might cause bugs.
      file_offset = nt_header.end_address()
      file_offset._rva = file_offset._offset

      if get_verbosity() > 1:
         DBG2('assuming file header at 0x%x', int(file_offset))

      self.file_header = parse_file_header_from_address(file_offset)
      return self.file_header

   def get_file_header(self):
      if not self.has_file_header():
         return self.parse_file_header()

      return self.file_header

   def has_file_header(self):
      return getattr(self, 'file_header', None)

   def set_file_header(self, file_header):
      if not isinstance(file_header, FileHeader):
         raise ImageError("file_header not a FileHeader instance")

      self.file_header = file_header
      return self.file_header

   def parse_optional_header(self):
      file_header = self.get_file_header()

      # XXX HACK this rva thing might cause bugs.
      optional_offset = file_header.end_address()
      optional_offset._rva = optional_offset._offset

      if get_verbosity() > 1: # FIXME use the spice constants!
         DBG2('assuming optional header at 0x%x', int(optional_offset))

      self.optional_header = parse_optional_header_from_address(optional_offset)
      return self.optional_header

   def get_optional_header(self):
      if not self.has_optional_header():
         return self.parse_optional_header()

      return self.optional_header

   def has_optional_header(self):
      return getattr(self, 'optional_header', None)

   def set_optional_header(self, optional_header):
      if not isinstance(optional_header, (OptionalHeader32, OptionalHeader64)):
         raise ImageError("optional_header not an OptionalHeader32/64 instance")

      self.optional_header = optional_header
      return self.optional_header

   def parse_data_directories(self):
      file_header = self.get_file_header()
      optional_header = self.get_optional_header()
      
      # XXX HACK the rva thing might cause bugs.
      data_offset = optional_header.end_address()
      data_offset._rva = data_offset._offset

      end_data_offset = data_offset+int(file_header.SizeOfOptionalHeader)
      self.data_directories = list()

      if get_verbosity() > MILD_VERBOSITY:
         DBG2('assuming data directories at 0x%x', data_offset.offset())

      self.data_directories = parse_data_directories_from_address(data_offset, int(optional_header.NumberOfRvaAndSizes))
      return self.data_directories

   def get_data_directories(self):
      if not getattr(self, 'data_directories', None):
         return self.parse_data_directories()

      return self.data_directories

   def parse_sections(self):
      file_header = self.get_file_header()
      optional_header = self.get_optional_header()
      self.sections = list()

      section_address = optional_header.address.copy()
      section_address += int(file_header.SizeOfOptionalHeader)

      if get_verbosity() > MILD_VERBOSITY:
         DBG2('assuming sections at 0x%x', int(section_address))

      self.sections = parse_sections_from_address(section_address, int(file_header.NumberOfSections))
      return self.sections

   def get_sections(self):
      if not getattr(self, 'sections', None):
         return self.parse_sections()

      return self.sections

   def get_section_map(self):
      sections = self.get_sections()
      ret = dict()

      for sect in sections:
         ret[str(sect.Name).strip('\x00')] = sect

      return ret

   def parse_image_at_address(self, addr):
      data_chunk = self.buff.read_raw(addr)
      new_image = PEImage(raw_image=data_chunk)

      # FIXME data can exist outside sections, the best way to parse all of this
      # FIXME is to be able to parse all directories and all data and find the
      # FIXME very last address. until then, this will do.
      last_address = map(lambda x: getattr(x, 'end_address')(), 
                                   new_image.get_headers())
      sections = new_image.get_sections()
      last_address += map(Section.end_raw_address, sections)
      max_address = max(last_address)

      real_image = new_image.get_raw_image()[:max_address.offset()]
      new_image.set_raw_image(real_image)

      return new_image

   def find_embedded_images(self):
      dos_header = self.get_dos_header()
      start_address = dos_header.end_address() # skip the first dos header
      end_address = self.eof()-2
      images = list()

      # HACK I don't think I'm parsing mapped images correctly. in events where
      # HACK the mapped image is smaller than the raw image, this raises an
      # HACK an exception (when going offset2rva). so, refuse to convert and 
      # HACK use the values instead.
      while start_address.offset() <= end_address.offset():
         if start_address.unpack_word() == IMAGE_DOS_SIGNATURE:
            DBG1("found MZ header at 0x%x", start_address.offset())

            try:
               new_image = self.parse_image_at_address(start_address)
            except (AddressError, HeaderError), e:
               DBG1("not a PE file:")
               DBG1(repr(e))
               start_address += 1
               continue

            DBG1("...it's a PE file!")
            images.append((start_address.address(),new_image))

         start_address += 1

      return images
   
   def architecture(self):
      optional = self.get_optional_header()

      if int(optional.Magic) == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
         return 1
      elif int(optional.Magic) == IMAGE_NT_OPTIONAL_HDR32_MAGIC:
         return 0
      else:
         raise HeaderError("OptionalHeader.Magic not a recognized value")

   def get_base_delta(self, current_base=None):
      if not current_base:
         current_base = self.virtual_base()

      return self.calculate_delta(current_base,int(self.IMAGE_OPTIONAL_HEADER.ImageBase))

   def calculate_delta(self, left, right):
      return calculate_delta(left, right, self.architecture())

   def relocate(self, address, target_base=None, buff=None):
      if not buff:
         unpack_dword = Address.unpack_dword
         pack_dword = Address.pack_dword
      elif buff == PEBuffer.BUFF_R:
         unpack_dword = Address.unpack_dword_raw
         pack_dword = Address.pack_dword_raw
      elif buff == PEBuffer.BUFF_V:
         unpack_dword = Address.unpack_dword_virtual
         pack_dword = Address.pack_dword_virtual
      else:
         raise ImageError("bad buffer value")

      value = unpack_dword(address)
      pack_dword(address, (value+self.get_base_delta(target_base)) & 0xFFFFFFFF)

   def relocate_raw(self, address, target_base=None):
      return self.relocate(address, target_base, PEBuffer.BUFF_R)

   def relocate_virtual(self, address, target_base=None):
      return self.relocate(address, target_base, PEBuffer.BUFF_V)

   def relocate_image(self, current_base=None, buff=None):
      reloc = self.relocation_directory()
      reloc_values = reloc.get_relocation_values(current_base)

      if not buff:
         pack_dword = Address.pack_dword
      elif buff == PEBuffer.BUFF_R:
         pack_dword = Address.pack_dword_raw
      elif buff == PEBuffer.BUFF_V:
         pack_dword = Address.pack_dword_virtual
      else:
         raise ImageError("bad buffer value")

      map(lambda x: pack_dword(x, reloc_values[x]), reloc_values.keys())

   def relocate_image_raw(self, current_base=None):
      self.relocate_image(current_base, PEBuffer.BUFF_R)

   def relocate_image_virtual(self, current_base=None):
      self.relocate_image(current_base, PEBuffer.BUFF_V)

   def load_imports(self):
      if not GetProcAddress or not LoadLibraryA:
         raise ImageError("host system isn't Windows or doesn't have Wine")

      if not int(self.IMAGE_DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress):
         DBG1('hey! the image has no import directory! what gives?')
         return

      DBG1("mapping imports to virtual image")
      import_directory = self.import_directory()
      import_directory.parse_imports()
      import_map = import_directory.map_descriptor_table()

      if not self.has_virtual_image():
         raise ImageError("image has no virtual image to load into")

      for dll in import_map.keys():
         library = LoadLibraryA(dll)

         if self.architecture():
            thunk_class = ThunkData64Array
         else:
            thunk_class = ThunkData32Array

         if library == 0:
            raise ImageError("couldn't load %s: 0x%08X" % (dll, GetLastError()))

         DBG1("loaded %s successfully", dll)

         iat = import_map[dll].FirstThunk.as_rva()

         if iat.is_null() or not iat.valid_rva():
            raise ImageError("address %s is not a valid IAT address" % repr(iat))

         oft = import_map[dll].OriginalFirstThunk.as_rva()

         if oft.is_null() or not oft.valid_rva():
            raise ImageError("address %s is not a valid OFT address" % repr(oft))

         thunks = thunk_class.parse_import_thunk_table(oft)

         for thunk in thunks:
            thunk_entry = thunk.parse_import_thunk()

            if isinstance(thunk_entry, ImportByName):
               if is_medium():
                  DBG2("grabbing %s!%s" % (dll, str(thunk_entry)))

               addr = GetProcAddress(library, str(thunk_entry))
            else:
               if is_medium():
                  DBG2("grabbing %s!#%d" % (dll, thunk_entry))

               addr = GetProcAddress(library, thunk_entry)

            if not addr:
               raise ImageError("couldn't import %s!%s: 0x%08X" % (dll, str(thunk_entry), GetLastError()))

            if is_spicy():
               DBG3("packing %s!%s into %s", dll, str(thunk_entry), iat)

            # FIXME I need a 64-bit binary to test this on.
            if self.architecture():
               iat.pack_qword_virtual(addr)
               iat += 8
            else:
               iat.pack_dword_virtual(addr)
               iat += 4

      DBG1("successfully parsed and mapped the import table")

   def hijack_module_handle(self):
      if not GetModuleHandleW:
         raise ImageError("host system isn't Windows or doesn't have Wine")

      if self._hijacked:
         return

      if not self._handle:
         self._handle = self.virtual_base()
      
      old_handle = GetModuleHandleP.call()
      SetModuleHandle.call(self._handle)
      self._handle = old_handle

      self._hijacked = 1

   def return_module_handle(self):
      if not GetModuleHandleW:
         raise ImageError("host system isn't Windows or doesn't have Wine")

      if not self._hijacked:
         return

      original_handle = GetModuleHandleP.call()
      SetModuleHandle.call(self._handle)
      self._handle = original_handle

      self._hijacked = 0

   def make_executable(self):
      # FIXME this won't work on 64-bit systems if the underlying image is 32-bit
      self.load_imports()

      try:
         self.relocate_image_virtual(self.virtual_base())
      except HeaderError:
         DBG1("image has no relocation directory! be careful, functions probably won't work.")

      mark_executable(self.buff.virtual_image, self.buff.virtual_length())
      self.is_executable = 1

   def create_function(self, address, function_class):
      if not self.is_executable:
         raise ImageError("image has not been made executable")

      if not self.has_virtual_image():
         raise ImageError("you can't manually set is_executable! this isn't magic! :P")

      return function_class(address)

   def compare_headers(self, other):
      if not isinstance(other, PEImage):
         raise TypeError("argument must be a PEImage type")

      result = cmp(self.get_dos_header(),other.get_dos_header())

      if result:
         return result

      result = cmp(self.get_nt_header(),other.get_nt_header())

      if result:
         return result

      result = cmp(self.get_file_header(),other.get_file_header())

      if result:
         return result

      result = cmp(self.get_optional_header(),other.get_optional_header())

      if result:
         return result

      my_directories = self.get_data_directories()
      their_directories = other.get_data_directories()

      result = cmp(len(my_directories),len(their_directories))

      if result:
         return result

      for i in xrange(len(my_directories)):
         result = cmp(my_directories[i],their_directories[i])

         if result:
            return result

         result = my_directories[i].compare_data(their_directories[i])

         if result:
            return result

      my_sections = self.get_sections()
      their_sections = other.get_sections()

      result = cmp(len(my_sections),len(their_sections))

      for i in xrange(len(my_sections)):
         result = cmp(my_sections[i],their_sections[i])

         if result:
            return result

         result = my_sections[i].compare_data(their_sections[i])

         if result:
            return result

      return 0

   def offset_to_first_diff(self, other):
      if not isinstance(other, PEImage):
         raise TypeError("argument must be a PEImage type")

      my_data = self.get_raw_image()
      their_data = other.raw_image

      for i in xrange(min(len(my_data),len(their_data))):
         if not my_data[i] == their_data[i]:
            return i

      if not len(my_data) == len(their_data):
         return i+1
      else:
         return -1

   def align_to_file(self, value):
      optional = self.get_optional_header()
      return align_address_forward(value, int(optional.FileAlignment))

   def align_to_section(self, value):
      optional = self.get_optional_header()
      if int(optional.SectionAlignment) < 0x1000:
         return align_address_forward(value, int(optional.SectionAlignment))
      else:
         return align_address_forward(value, int(optional.FileAlignment))

   def export_directory(self):
      datadir = self.get_data_directories()
      return ExportDirectory.from_directory(datadir[IMAGE_DIRECTORY_ENTRY_EXPORT])

   def dll_name(self):
      export_directory = self.export_directory()

      if not export_directory:
         return

      return export_directory.dll_name()

   def import_directory(self):
      datadir = self.get_data_directories()
      return ImportDirectory.from_directory(datadir[IMAGE_DIRECTORY_ENTRY_IMPORT])

   def relocation_directory(self):
      datadir = self.get_data_directories()
      return RelocationDirectory.from_directory(datadir[IMAGE_DIRECTORY_ENTRY_BASERELOC])

   def entrypoint(self):
      optional = self.get_optional_header()
      return optional.AddressOfEntryPoint.as_rva()

   def unpacker(self):
      return Unpacker(self)

   def dump_raw_image(self, filename=None):
      self.buff.dump_raw_image(filename)

   def va_to_rva(self,va):
      DBG4("converting VA 0x%X to an RVA", va)

      optional = self.get_optional_header()
      return va_to_rva(int(optional.ImageBase),va)

   def va_to_offset(self,va):
      DBG4("converting VA 0x%X to an offset", va)

      optional = self.get_optional_header()
      base = int(optional.ImageBase)
      sect = self.section_by_rva(self.va_to_rva(va))

      if sect is None:
         if not va - base < len(self.get_raw_image()):
            raise AddressError("virtual address not in section; can't convert")

         return va - base

      return va_to_offset(base,
                          int(sect.VirtualAddress),
                          int(sect.PointerToRawData),
                          va)

   def rva_to_va(self,rva):
      DBG4("converting RVA 0x%X to a VA", rva)

      optional = self.get_optional_header()
      return rva_to_va(int(optional.ImageBase),rva)

   def rva_to_offset(self,rva):
      DBG4("converting RVA 0x%X to an offset", rva)

      try:
         sect = self.section_by_rva(rva)
      except ImageError:
         sect = None

      if sect is None:
         if not rva < self.raw_length():
            raise AddressError("RVA has no section and is larger than raw image; can't convert")

         return rva

      return rva_to_offset(int(sect.VirtualAddress),
                           int(sect.PointerToRawData),
                           rva)

   def offset_to_va(self,offset):
      DBG4("converting offset 0x%X to a VA", offset)

      optional = self.get_optional_header()
      base = int(optional.ImageBase)

      # we don't catch the exception here, because if you're going offset to va
      # this early on, something should have parsed. and if it didn't, you
      # should be a good samaritan and report the bug. :>
      sect = self.section_by_offset(offset)

      if sect is None:
         if not self.has_virtual_image():
            image_size = int(self.IMAGE_OPTIONAL_HEADER.SizeOfImage)
         else:
            image_size = len(self.get_virtual_image())

         mapped = self.get_virtual_image()

         if not offset < image_size:
            raise AddressError("offset has no section and is larger than mapped image; can't convert")

         return offset + base # FIXME don't need self.image_base

      return offset_to_va(base,
                          int(sect.VirtualAddress),
                          int(sect.PointerToRawData),
                          offset)

   def offset_to_rva(self,offset):
      DBG4("converting offset 0x%X to an RVA", offset)

      try:
         sect = self.section_by_offset(offset)
      except ImageError:
         sect = None

      if sect is None:
         if not self.has_virtual_image():
            if not self.has_optional_header():
               raise ImageError("attempting to convert offset to rva without having parsed the optional header. see PEImage.section_by_offset as to why this error is raised.")

            image_size = int(self.IMAGE_OPTIONAL_HEADER.SizeOfImage)
         else:
            image_size = self.virtual_length()

         if not offset < image_size:
            raise AddressError("offset larger than image; can't convert")

         return offset

      return offset_to_rva(int(sect.VirtualAddress),
                           int(sect.PointerToRawData),
                           offset)

   def null(self):
      return self.offset(0)

   def eof(self):
      return self.offset(len(self))

   def va(self,va):
      return VA(self,va)

   def rva(self,rva):
      return RVA(self,rva)

   def offset(self,offset):
      return Offset(self,offset)

   def section_by_offset(self, offset):
      # normally I wouldn't have this raise an exception. this kind of breaks
      # the rest of the design-flow of the image in the sense that everything
      # will "just parse" no matter what. however, this is an exceptional case.
      #
      # consider a PEImage that only has a virtual image and needs to have its
      # headers parsed. in order to do this, the image needs to be read. because
      # virtual images are checked by their rva, offsets are automatically
      # converted to rva objects. in order to verify that the rva is in fact a
      # valid one, it's checked against sections. in order to get sections, the
      # optional header must be parsed. in effect, this triggers a recursive
      # parsing loop that never breaks.
      #
      # however, an rva address will still be a valid address if it's under a
      # certain threshhold (i.e., it is not in a section). indeed, before the
      # first section, rva and offset addresses are equivalent. so, because this
      # function is primarily used by address conversion functions, this will
      # essentially close the loop.

      if not self.has_optional_header():
         raise ImageError("optional header hasn't been parsed yet. see PEImage.section_by_offset for an explanation as to why this was raised.")

      sections = self.get_sections()
      return section_by_offset(sections, offset)

   def section_by_rva(self, rva):
      if not self.has_optional_header():
         raise ImageError("optional header hasn't been parsed yet. see PEImage.section_by_offset for an explanation as to why this was raised.")

      sections = self.get_sections()
      return section_by_rva(sections, rva)

   def section_by_address(self, address):
      return self.section_by_rva(address.rva())

   def unpack_qword(self, addr, signed=0):
      return unpack_qword(self.buff.read(addr, 8), signed)

   def unpack_qword_raw(self, addr, signed=0):
      return unpack_qword(self.buff.read_raw(addr, 8), signed)

   def unpack_qword_virtual(self, addr, signed=0):
      return unpack_qword(self.buff.read_virtual(addr, 8), signed)

   def unpack_qwords(self, addr, qwords, signed=0):
      return unpack_qwords(self.buff.read(addr, 8*qwords), qwords, signed)

   def unpack_qwords_raw(self, addr, qwords, signed=0):
      return unpack_qwords(self.buff.read_raw(addr, 8*qwords), qwords, signed)

   def unpack_qwords_virtual(self, addr, qwords, signed=0):
      return unpack_qwords(self.buff.read_virtual(addr, 8*qwords), qwords, signed)

   def unpack_dword(self, addr, signed=0):
      return unpack_dword(self.buff.read(addr, 4), signed)

   def unpack_dword_raw(self, addr, signed=0):
      return unpack_qword(self.buff.read_raw(addr, 4), signed)

   def unpack_dword_virtual(self, addr, signed=0):
      return unpack_qword(self.buff.read_virtual(addr, 4), signed)

   def unpack_dwords(self, addr, dwords, signed=0):
      return unpack_dwords(self.buff.read(addr, 4*dwords), dwords, signed)

   def unpack_dwords_raw(self, addr, dwords, signed=0):
      return unpack_dwords(self.buff.read_raw(addr, 4*dwords), dwords, signed)

   def unpack_dwords_virtual(self, addr, dwords, signed=0):
      return unpack_dwords(self.buff.read_virtual(addr, 4*dwords), dwords, signed)

   def unpack_word(self, addr, signed=0):
      return unpack_word(self.buff.read(addr, 2), signed)

   def unpack_word_raw(self, addr, signed=0):
      return unpack_word(self.buff.read_raw(addr, 2), signed)

   def unpack_word_virtual(self, addr, signed=0):
      return unpack_word(self.buff.read_virtual(addr, 2), signed)

   def unpack_words(self, addr, words, signed=0):
      return unpack_words(self.buff.read(addr, 2*words), words, signed)

   def unpack_words_raw(self, addr, words, signed=0):
      return unpack_words(self.buff.read_raw(addr, 2*words), words, signed)

   def unpack_words_virtual(self, addr, words, signed=0):
      return unpack_words(self.buff.read_virtual(addr, 2*words), words, signed)

   def unpack_byte(self, addr, signed=0):
      return unpack_byte(self.buff.read(addr, 1), signed)

   def unpack_byte_raw(self, addr, signed=0):
      return unpack_byte(self.buff.read_raw(addr, 1), signed)

   def unpack_byte_virtual(self, addr, signed=0):
      return unpack_byte(self.buff.read_virtual(addr, 1), signed)

   def unpack_bytes(self, addr, bytecount, signed=0):
      return unpack_bytes(self.buff.read(addr, bytecount), bytecount, signed)

   def unpack_bytes_raw(self, addr, bytecount, signed=0):
      return unpack_bytes(self.buff.read_raw(addr, bytecount), bytecount, signed)

   def unpack_bytes_virtual(self, addr, bytecount, signed=0):
      return unpack_bytes(self.buff.read_virtual(addr, bytecount), bytecount, signed)

   def unpack_string(self, addr, limit=-1, buff=None):
      s = list()
      i = 0

      while not i == limit:
         try:
            if not buff:
               byte = self.unpack_byte(addr+i)
            elif buff == PEBuffer.BUFF_R:
               byte = self.unpack_byte_raw(addr+i)
            elif buff == PEBuffer.BUFF_V:
               byte = self.unpack_byte_virtual(addr+i)
            else:
               raise ImageError("bad buff value passed to unpack_string")
         except PEBufferError:
            break

         if byte == 0:
            break

         s.append(chr(byte))
         i += 1

      return ''.join(s)

   def unpack_string_raw(self, addr, limit=-1):
      return self.unpack_string(addr, limit, PEBuffer.BUFF_R)

   def unpack_string_virtual(self, addr, limit=-1):
      return self.unpack_string(addr, limit, PEBuffer.BUFF_V)

   def unpack_string_limit(self, addr, limit):
      return self.unpack_string(addr, limit)

   def unpack_string_limit_raw(self, addr, limit):
      return self.unpack_string(addr, limit, PEBuffer.BUFF_R)

   def unpack_string_limit_virtual(self, addr, limit):
      return self.unpack_string(addr, limit, PEBuffer.BUFF_V)

   def unpack_wide_string(self, addr, limit=-1, buff=None):
      s = list()
      i = 0

      while not i == limit:
         try:
            if not buff:
               word = self.unpack_word(addr+i)
            elif buff == PEBuffer.BUFF_R:
               word = self.unpack_word_raw(addr+i)
            elif buff == PEBuffer.BUFF_V:
               word = self.unpack_word_virtual(addr+i)
            else:
               raise ImageError("bad buff value passed to unpack_wide_string")
         except PEBufferError:
            break

         if word == 0:
            break

         # FIXME THIS DOESN'T CONFORM TO ENDIANNESS FUCK FUCK ASS PISS BALLS
         s.append(chr(word & 0xFF))
         s.append(chr((word >> 8) & 0xFF))
         i += 2

      return ''.join(s)

   def unpack_wide_string_raw(self, addr, limit=-1):
      return self.unpack_wide_string(addr, limit, PEBuffer.BUFF_R)

   def unpack_wide_string_virtual(self, addr, limit=-1):
      return self.unpack_wide_string(addr, limit, PEBuffer.BUFF_V)

   def unpack_wide_string_limit(self, addr, limit):
      return self.unpack_wide_string(addr, limit)

   def unpack_wide_string_limit_raw(self, addr, limit):
      return self.unpack_wide_string(addr, limit, PEBuffer.BUFF_R)

   def unpack_wide_string_limit_virtual(self, addr, limit):
      return self.unpack_wide_string(addr, limit, PEBuffer.BUFF_V)

   def read(self, addr, length=0):
      return self.buff.read(addr, length)

   def read_raw(self, addr, length=0):
      return self.buff.read_raw(addr, length)

   def read_virtual(self, addr, length=0):
      return self.buff.read_virtual(addr, length)

   def pack_qword(self, addr, qword, signed=0):
      data = pack_qword(qword, signed)
      self.buff.write(addr, data)

   def pack_qword_raw(self, addr, qword, signed=0):
      data = pack_qword(qword, signed)
      self.buff.write_raw(addr, data)

   def pack_qword_virtual(self, addr, qword, signed=0):
      data = pack_qword(qword, signed)
      self.buff.write_virtual(addr, data)

   def pack_qwords(self, addr, qwords, signed=0):
      data = pack_qwords(qwords, signed)
      self.buff.write(addr, data)

   def pack_qwords_raw(self, addr, qwords, signed=0):
      data = pack_qwords(qwords, signed)
      self.buff.write_raw(addr, data)

   def pack_qwords_virtual(self, addr, qwords, signed=0):
      data = pack_qwords(qwords, signed)
      self.buff.write_virtual(addr, data)

   def pack_dword(self, addr, dword, signed=0):
      data = pack_dword(dword, signed)
      self.buff.write(addr, data)

   def pack_dword_raw(self, addr, dword, signed=0):
      data = pack_dword(dword, signed)
      self.buff.write_raw(addr, data)

   def pack_dword_virtual(self, addr, dword, signed=0):
      data = pack_dword(dword, signed)
      self.buff.write_virtual(addr, data)

   def pack_dwords(self, addr, dwords, signed=0):
      data = pack_dwords(dwords, signed)
      self.buff.write(addr, data)

   def pack_dwords_raw(self, addr, dwords, signed=0):
      data = pack_dwords(dwords, signed)
      self.buff.write_raw(addr, data)

   def pack_dwords_virtual(self, addr, dwords, signed=0):
      data = pack_dwords(dwords, signed)
      self.buff.write_virtual(addr, data)

   def pack_word(self, addr, word, signed=0):
      data = pack_word(word, signed)
      self.buff.write(addr, data)

   def pack_word_raw(self, addr, word, signed=0):
      data = pack_word(word, signed)
      self.buff.write_raw(addr, data)

   def pack_word_virtual(self, addr, word, signed=0):
      data = pack_word(word, signed)
      self.buff.write_virtual(addr, data)

   def pack_words(self, addr, words, signed=0):
      data = pack_words(words, signed)
      self.buff.write(addr, data)

   def pack_words_raw(self, addr, words, signed=0):
      data = pack_words(words, signed)
      self.buff.write_raw(addr, data)

   def pack_words_virtual(self, addr, words, signed=0):
      data = pack_words(words, signed)
      self.buff.write_virtual(addr, data)

   def pack_byte(self, addr, byte, signed=0):
      data = pack_byte(byte, signed)
      self.buff.write(addr, data)

   def pack_byte_raw(self, addr, byte, signed=0):
      data = pack_byte(byte, signed)
      self.buff.write_raw(addr, data)

   def pack_byte_virtual(self, addr, byte, signed=0):
      data = pack_byte(byte, signed)
      self.buff.write_virtual(addr, data)

   def pack_bytes(self, addr, bytelist, signed=0):
      data = pack_bytes(bytelist, signed)
      self.buff.write(addr, data)

   def pack_bytes_raw(self, addr, bytelist, signed=0):
      data = pack_bytes(bytelist, signed)
      self.buff.write_raw(addr, data)

   def pack_bytes_virtual(self, addr, bytelist, signed=0):
      data = pack_bytes(bytelist, signed)
      self.buff.write_virtual(addr, data)

   def pack_string(self, addr, string):
      self.buff.write(addr, string+'\x00')

   def pack_string_raw(self, addr, string):
      self.buff.write_raw(addr, string+'\x00')

   def pack_string_virtual(self, addr, string):
      self.buff.write_virtual(addr, string+'\x00')

   def pack_wide_string(self, addr, widestring):
      widestring = widestring.encode('utf-16')[2:]+'\x00\x00'
      self.buff.write(addr, widestring)

   def pack_wide_string_raw(self, addr, widestring):
      widestring = widestring.encode('utf-16')[2:]+'\x00\x00'
      self.buff.write_raw(addr, widestring)

   def pack_wide_string_virtual(self, addr, widestring):
      widestring = widestring.encode('utf-16')[2:]+'\x00\x00'
      self.buff.write_raw(addr, widestring)

   def write(self, addr, data):
      self.buff.write(addr, data)

   def write_raw(self, addr, data):
      self.buff.write_raw(addr, data)

   def write_virtual(self, addr, data):
      self.buff.write_virtual(addr, data)

   def is_windows_compatible(self):
      # thanks to Daeken for the idea
      compatibility = 0x1F

      xp_incompat = 0x1E
      vista_incompat = 0x1D
      win7_incompat = 0x1B
      x86_incompat = 0x17
      x64_incompat = 0xF

      valid_platforms = (IMAGE_SUBSYSTEM_NATIVE, IMAGE_SUBSYSTEM_WINDOWS_GUI,
                         IMAGE_SUBSYSTEM_WINDOWS_CUI)

      valid_machines = (IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_IA64, 
                        IMAGE_FILE_MACHINE_AMD64)

      try:
         self.parse_headers()
      except Exception,e:
         DBG1('tried to parse headers, got an exception: %s' % str(e))
         return 0

      machine = int(self.IMAGE_FILE_HEADER.Machine)

      if not machine in valid_machines:
         DBG1('IMAGE_FILE_HEADER.Machine value is suspicious-- not i386/AMD64/IA64. Assuming incompatible.')
         compatibility = 0

      sections = int(self.IMAGE_FILE_HEADER.NumberOfSections)

      if sections == 0:
         DBG1('IMAGE_FILE_HEADER.Sections cannot be zero on Vista/7')
         compatibility &= vista_incompat
         compatibility &= win7_incompat

      if sections > 96: 
         DBG1('IMAGE_FILE_HEADER.NumberOfSections incompatible with XP (must be less than or equal to 96)')
         compatibility &= xp_incompat

      # TODO TLS directory can circumvent this
      entry = self.IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint.as_rva()

      if not entry.valid_va() or int(entry) & 0x80000000 or int(entry) & 0x8000000000000000:
         DBG1('IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint has an invalid value')
         compatibility = 0

      image_base = int(self.IMAGE_OPTIONAL_HEADER.ImageBase)
      image_size = int(self.IMAGE_OPTIONAL_HEADER.SizeOfImage)

      if image_base % 0x10000:
         DBG1('IMAGE_OPTIONAL_HEADER.ImageBase must be a multiple of 0x10000')
         compatibility = 0

      elif image_base == 0:
         DBG1('IMAGE_OPTIONAL_HEADER.ImageBase can only be null under XP')
         compatibility &= vista_incompat
         compatibility &= win7_incompat

      if (image_base+image_size) & 0x80000000:
         DBG1('IMAGE_OPTIONAL_HEADER.ImageBase plus IMAGE_OPTIONAL_HEADER.ImageSize incompatible with 32-bit windows (must be less than 0x80000000)')
         compatibility &= x86_compat

      if (image_base+image_size) & 0x8000000000000000:
         DBG1('IMAGE_OPTIONAL_HEADER.ImageBase plus IMAGE_OPTIONAL_HEADER.ImageSize incompatible with 64-bit windows (must be less than 0x8000000000000000)')
         compatibility &= x64_compat

      sect_align = int(self.IMAGE_OPTIONAL_HEADER.SectionAlignment)

      # fuck readability, this algorithm is cool as shit
      if sect_align & (sect_align - 1):
         DBG1('IMAGE_OPTIONAL_HEADER.SectionAlignment not a power of 2')
         compatibility = 0

      file_align = int(self.IMAGE_OPTIONAL_HEADER.FileAlignment)

      if file_align & (file_align - 1):
         DBG1('IMAGE_OPTIONAL_HEADER.FileAlignment not a power of 2')
         compatibility = 0

      major_subsystem = int(self.IMAGE_OPTIONAL_HEADER.MajorSubsystemVersion)

      if major_subsystem < 3:
         DBG1('IMAGE_OPTIONAL_HEADER.MajorSubsystemVersion must be less than 3')
         compatibility = 0

      minor_subsystem = int(self.IMAGE_OPTIONAL_HEADER.MinorSubsystemVersion)

      if major_subsystem == 3 and minor_subsystem < 10:
         DBG1('If IMAGE_OPTIONAL_HEADER.MajorSubsystemVersion is 3, then IMAGE_OPTIONAL_HEADER.MinorSubsystemVersion must be greater than or equal to 10')
         compatibility = 0

      img_size = self.calculate_size_of_image()

      if img_size > int(self.IMAGE_OPTIONAL_HEADER.SizeOfImage):
         DBG1('IMAGE_OPTIONAL_HEADER.SizeOfImage is wrong; expecting 0x%08X' % img_size)
         compatibility = 0

      elif img_size < int(self.IMAGE_OPTIONAL_HEADER.SizeOfImage):
         DBG1("though not necessarily incompatible, it's suspicious that the image size is bigger than it should be.")

      subsystem = int(self.IMAGE_OPTIONAL_HEADER.Subsystem)

      if not subsystem in valid_platforms:
         DBG1('IMAGE_OPTIONAL_HEADER.Subsystem is suspicious; expecting native, GUI or CUI.')
         compatibility = 0

      if int(self.IMAGE_FILE_HEADER.NumberOfSections):
         executable = 0

         for section in self.get_sections():
            sect_align = int(self.IMAGE_OPTIONAL_HEADER.SectionAlignment)
            file_align = int(self.IMAGE_OPTIONAL_HEADER.FileAlignment)

            sect_name = str(section.Name).rstrip('\x00')

            vs_align = int(section.VirtualAddress) % sect_align

            if vs_align:
               DBG1('Section "%s" is not section aligned' % sect_name)
               compatibility = 0

            fs_align = int(section.PointerToRawData) % file_align

            if fs_align:
               DBG1('Section "%s" is not file aligned' % sect_name)
               compatibility = 0

            executable |= int(section.Characteristics) & IMAGE_SCN_MEM_EXECUTE

         if not executable:
            DBG1('at least one of the sections must be marked executable to run')
            compatibility = 0

         if executable and not int(self.IMAGE_FILE_HEADER.Characteristics) & IMAGE_FILE_EXECUTABLE_IMAGE:
            DBG1('executable section found in an image not marked for execution')
            compatibility = 0

      return compatibility

   def is_xp_compatible(self):
      return self.is_windows_compatible() & PEImage.XP_COMPATABILITY

   def is_vista_compatible(self):
      return self.is_windows_compatible() & PEImage.VISTA_COMPATABILITY

   def is_win7_compatible(self):
      return self.is_windows_compatible() & PEImage.WIN7_COMPATABILITY

   def is_x86_compatible(self):
      return self.is_windows_compatible() & PEImage.X86_COMPATABILITY

   def is_x64_compatible(self):
      return self.is_windows_compatible() & PEImage.X64_COMPATABILITY

   def calculate_size_of_headers(self):
      self.parse_headers()

      end_addrs = [self.IMAGE_DOS_HEADER.end_address(),
                   self.IMAGE_NT_HEADER.end_address(),
                   self.IMAGE_FILE_HEADER.end_address(),
                   self.IMAGE_OPTIONAL_HEADER.end_address()]

      if len(self.get_data_directories()):
         end_addrs.append(self.get_data_directories()[-1].end_address())

      if len(self.get_sections()):
         end_addrs.append(self.get_sections()[-1].end_address())

      end_addrs = map(Address.offset, end_addrs)
      return max(end_addrs)

   def calculate_size_of_image(self):
      top_value = 0
      header_size = self.calculate_size_of_headers()

      if len(self.get_sections()):
         base_address = 0xFFFFFFFFFFFFFFFF
      else:
         base_address = 0

      for section in self.get_sections():
         value_check = int(section.VirtualSize) + int(section.VirtualAddress)

         if int(section.VirtualAddress) < base_address:
            base_address = int(section.VirtualAddress)

         if value_check > top_value:
            top_value = value_check

      if header_size > base_address:
         top_value += header_size

      return top_value + (int(self.IMAGE_OPTIONAL_HEADER.SectionAlignment) - (top_value % int(self.IMAGE_OPTIONAL_HEADER.SectionAlignment)))

   def raw_length(self):
      return self.buff.raw_length()

   def virtual_length(self):
      return self.buff.virtual_length()

   def virtual_base(self):
      return self.buff.virtual_base()

   def __getattr__(self, attr):
      if self.__dict__.has_key(attr):
         return self.__dict__[attr]

      virtual_attrs = ['IMAGE_DOS_HEADER', 'IMAGE_NT_HEADER',
                       'IMAGE_FILE_HEADER', 'IMAGE_OPTIONAL_HEADER',
                       'IMAGE_DATA_DIRECTORY', 'IMAGE_SECTION_HEADER',
                       'PIMAGE_DATA_DIRECTORY', 'PIMAGE_SECTION_HEADER']

      if not attr in virtual_attrs:
         raise AttributeError('PE image has no element named "%s"' % attr)

      if attr == 'IMAGE_DOS_HEADER':
         return self.get_dos_header()
      elif attr == 'IMAGE_NT_HEADER':
         return self.get_nt_header()
      elif attr == 'IMAGE_FILE_HEADER':
         return self.get_file_header()
      elif attr == 'IMAGE_OPTIONAL_HEADER':
         return self.get_optional_header()
      elif attr == 'IMAGE_DATA_DIRECTORY' or attr == 'PIMAGE_DATA_DIRECTORY':
         return self.get_data_directories()
      elif attr == 'IMAGE_SECTION_HEADER' or attr == 'PIMAGE_SECTION_HEADER':
         return self.get_sections()

   def __len__(self):
      return len(self.buff)

def get_signer(size, signed):
   if signed:
      return {1: 'b', 2: 'h', 4: 'l', 8: 'q'}[size]
   else:
      return {1: 'B', 2: 'H', 4: 'L', 8: 'Q'}[size]

def unpack_qwords(data, qwords, signed=0):
   maxim = qwords * 8

   if len(data) < maxim:
      data += '\x00' * (maxim-len(data))

   signer = get_signer(8, signed)
   return struct.unpack('<'+(signer*qwords),''.join(data[:maxim]))

def unpack_qword(data, signed=0):
   if len(data) < 8:
      data += '\x00' * (8-len(data))

   signer = get_signer(8, signed)
   return struct.unpack('<%s' % (signer,), ''.join(data[:8]))[0]

def unpack_dwords(data, dwords, signed=0):
   maxim = dwords * 4
   if len(data) < maxim:
      data += '\x00' * (maxim-len(data))

   signer = get_signer(4, signed)
   return struct.unpack('<'+(signer*dwords),''.join(data[:maxim]))

def unpack_dword(data, signed=0):
   if len(data) < 4:
      data += '\x00' * (4-len(data))

   signer = get_signer(4, signed)
   return struct.unpack('<%s' % (signer,), ''.join(data[:4]))[0]

def unpack_words(data, words, signed=0):
   maxim = words * 2
   if len(data) < maxim:
      data += '\x00' * (maxim-len(data))

   signer = get_signer(2, signed)
   return struct.unpack('<'+(signer*words), ''.join(data[:maxim]))

def unpack_word(data, signed=0):
   if len(data) < 2:
      data += '\x00' * (2-len(data))

   signer = get_signer(2, signed)
   return struct.unpack('<%s' % signer, ''.join(data[:2]))[0]

def unpack_bytes(data, bytecount, signed=0):
   if len(data) < bytecount:
      data += '\x00'*(bytecount - len(data))

   signer = get_signer(1, signed)
   return struct.unpack('<'+(signer*bytecount), ''.join(data[:bytecount]))

def unpack_byte(data, signed=0):
   if not len(data):
      return 0

   signer = get_signer(1, signed)
   return struct.unpack('<%s' % (signer,), data[0])[0]

def mbcs2ucs(mbcs): # FIXME this still doesn't feel right.
   return mbcs.decode('utf-16')

def write(data, offset, res):
   DBG4("here be dragons! data[0x%x] = %s", offset, repr(res))
   data[offset:offset+len(res)] = res

def pack_qwords(qwords, signed=0):
   return struct.pack('<'+(get_signer(8, signed)*len(qwords)), *qwords)

def pack_qword(qword, signed=0):
   return struct.pack('<%s' % get_signer(8, signed), qword)

def pack_dwords(dwords, signed=0):
   return struct.pack('<'+(get_signer(4, signed)*len(dwords)),*dwords)

def pack_dword(dword, signed=0):
   return struct.pack('<%s' % get_signer(4, signed), dword)

def pack_words(words, signed=0):
   return struct.pack('<'+(get_signer(2, signed)*len(words)),*words)

def pack_word(word, signed=0):
   return struct.pack('<%s' % get_signer(2, signed), word)

def pack_bytes(bytelist, signed=0):
   return struct.pack(get_signer(1, signed)*len(bytelist), *bytelist)

def pack_byte(byte, signed=0):
   return struct.pack('<%s' % get_signer(1, signed), byte)

def rva_to_va(base,rva):
   return base+rva

def rva_to_offset(rva_section,raw_section,rva):
   return rva - rva_section + raw_section

def va_to_rva(base,va):
   return va-base

def va_to_offset(base,rva_section,raw_section,va):
   return va - base - rva_section + raw_section

def offset_to_rva(rva_section,raw_section,offset):
   return offset - raw_section + rva_section 

def offset_to_va(base,rva_section,raw_section,offset):
   return offset - raw_section + rva_section + base

def align_address_forward(value, alignment):
   """
   This trick is brought to you by the letter `Pi`
   and the number `align forward to offset using ones' compliment bitmask`
   """
   aligned = int((value + (alignment - 0x1)) & ~(alignment - 0x1))
   if value > aligned:
      raise AddressError("Value or Alignment should not be negative.")
   return aligned

def section_by_offset(sections, offset):
   DBG4('section by offset: 0x%x', offset)

   for section in sections:
      if in_section(int(section.PointerToRawData),int(section.SizeOfRawData),offset):
         DBG4('offset 0x%x found in %s',offset,str(section.Name).rstrip('\x00'))
         return section

   DBG4('offset 0x%x not found', offset)

def section_by_rva(sections, rva):
   DBG4('section by rva: 0x%x', rva)

   for section in sections:
      if in_section(int(section.VirtualAddress),int(section.VirtualSize),rva):
         DBG4('rva 0x%x found in %s', rva, str(section.Name).rstrip('\x00'))
         return section

   DBG4('rva 0x%x not found', rva)

def in_section(section_addr, section_size, target_addr):
   DBG4('... checking if 0x%x is between 0x%x and 0x%x', target_addr, section_addr, section_addr+section_size)
   return section_addr <= target_addr < (section_addr+section_size)

def probability_map(byte_stream):
   # I don't know shit about math
   max_bytes = len(byte_stream)*1.0
   p_map = dict()

   for c in byte_stream:
      p_map.setdefault(c, 0)
      p_map[c] += 1

   for c in p_map.keys():
      p_map[c] /= max_bytes

   return p_map

def parse_dos_header_from_address(address):
   DBG1('parsing DOS header via address %s', repr(address))

   dos_header = DOSHeader(address=address)

   if not int(dos_header.e_magic) == IMAGE_DOS_SIGNATURE:
      raise HeaderError("PE image does not start with a DOS header")

   if get_verbosity() > 0:
      DBG1('successfully parsed DOS header')
      DBG2("here's the full header:")
      DBG2(repr(dos_header))

   return dos_header

def parse_dos_header_from_data(data):
   DBG1('parsing DOS header via data')

   dos_header = DOSHeader(data=data)

   if not int(dos_header.e_magic) == IMAGE_DOS_SIGNATURE:
      raise HeaderError("data does not contain a DOS header")

   if get_verbosity() > 0:
      DBG1('successfully parsed DOS header')
      DBG2("here's the full header:")
      DBG2(repr(dos_header))

   return dos_header

def parse_nt_header_from_address(address):
   DBG1('parsing NT header')

   nt_header = NTHeader(address=address)

   if not int(nt_header.Signature) == IMAGE_NT_SIGNATURE:
      raise HeaderError("MZ image is not a PE file")

   if get_verbosity() > 0:
      DBG1('successfully parsed NT header')
      DBG2("here's the full header:")
      DBG2(repr(nt_header))

   return nt_header

def parse_nt_header_from_data(data):
   DBG1('parsing NT header')

   nt_header = NTHeader(data=data)

   if not int(nt_header.Signature) == IMAGE_NT_SIGNATURE:
      raise HeaderError("underlying data does not imply a PE image")

   if get_verbosity() > 0:
      DBG1('successfully parsed NT header')
      DBG2("here's the full header:")
      DBG2(repr(nt_header))

   return nt_header

def parse_file_header_from_address(address):
   DBG1('parsing file header')

   file_header = FileHeader(address=address)

   if get_verbosity() > 0:
      DBG1('successfully parsed file header')
      DBG2("here's the full header")
      DBG2(repr(file_header))

   return file_header

def parse_file_header_from_data(data):
   DBG1('parsing file header')

   file_header = FileHeader(data=data)

   if get_verbosity() > 0:
      DBG1('successfully parsed file header')
      DBG2("here's the full header")
      DBG2(repr(file_header))

   return file_header

def parse_optional_header_from_address(address):
   DBG1('parsing NT header')

   magic_value = address.unpack_word()

   if magic_value == IMAGE_NT_OPTIONAL_HDR32_MAGIC:
      optional_header=OptionalHeader32(address=address)
   elif magic_value == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
      optional_header=OptionalHeader64(address=address)
   else:
      if get_verbosity() > 0:
         DBG1('bad magic number: %s', repr(optional_header.Magic))
         DBG2("here's the full header:")
         DBG2(repr(optional_header))

      raise HeaderError("Optional.Magic not a PE/PE+ magic number.")

   if get_verbosity() > 0:
      DBG1('successfully parsed optional header')
      DBG2("here's the full header:")
      DBG2(repr(optional_header))

   return optional_header

def parse_optional_header_from_data(data):
   DBG1('parsing NT header')

   magic_value = unpack_word(data, 0)

   if magic_value == IMAGE_NT_OPTIONAL_HDR32_MAGIC:
      optional_header=OptionalHeader32(data=data)
   elif magic_value == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
      optional_header=OptionalHeader64(data=data)
   else:
      if get_verbosity() > 0:
         DBG1('bad magic number: %s', repr(optional_header.Magic))
         DBG2("here's the full header:")
         DBG2(repr(optional_header))

      raise HeaderError("Optional.Magic not a PE/PE+ magic number.")

   if get_verbosity() > 0:
      DBG1('successfully parsed optional header')
      DBG2("here's the full header:")
      DBG2(repr(optional_header))

   return optional_header

def parse_data_directories_from_address(address, directories):
   DBG1('parsing data directories')

   # data directories come right after the optional header and can be anywhere
   # between Optional.NumberOfRvaAndSizes and 16.
   #
   # thanks to Corkami's PE research for helping in parsing this properly.

   address = address.address()
   directories = min(directories,0x10)
   data_directories = DataDirectoryArray(address=address, length=directories)

   if get_verbosity() > 0:
      DBG1('successfully parsed data directories')

      if get_verbosity() > 1:
         DBG2('have some directories:')

         for directory in data_directories:
            DBG2(repr(directory))

   return data_directories

def parse_data_directories_from_data(data, directories):
   DBG1('parsing data directories')

   # data directories come right after the optional header and can be anywhere
   # between Optional.NumberOfRvaAndSizes and 16.
   #
   # thanks to Corkami's PE research for helping in parsing this properly.

   i = 0
   directories = min(directories,0x10)
   data_directories = DataDirectoryArray(data=data, length=directories)

   if get_verbosity() > 0:
      DBG1('successfully parsed data directories')

      if get_verbosity() > 1:
         DBG2('have some directories:')

         for directory in data_directories:
            DBG2(repr(directory))

   return data_directories

def parse_sections_from_address(address, sections):
   DBG1('parsing sections')

   # sections do not directly follow after the directories. rather, they
   # come right after FileHeader.SizeOfOptionalHeader.
   #
   # thanks to Alexander Sotirov's TinyPE research for helping in parsing
   # this properly as well as Corkami's page on PE header stuff.

   section_address = address.address()
   parsed_sections = SectionArray(address=section_address, length=sections)

   if get_verbosity() > 0:
      DBG1('successfully parsed sections')

      if get_verbosity() > 1:
         DBG2('have some sections:')

         for section in parsed_sections:
            DBG2(repr(section))

   return parsed_sections

def parse_sections_from_data(data, sections):
   DBG1('parsing sections')

   # sections do not directly follow after the directories. rather, they
   # come right after FileHeader.SizeOfOptionalHeader.
   #
   # thanks to Alexander Sotirov's TinyPE research for helping in parsing
   # this properly as well as Corkami's page on PE header stuff.

   parsed_sections = SectionArray(data=data, length=sections)

   if get_verbosity() > 0:
      DBG1('successfully parsed sections')

      if get_verbosity() > 1:
         DBG2('have some sections:')

         for section in sections:
            DBG2(repr(section))

   return parsed_sections

# FIXME this only returns unsigned integers. that's not what delta implies.
def calculate_delta(left,right,arch=0):
   result = left - right

   if result < 0:
      result += 0x100000000 << (32 * arch)
      result &= (0x100000000 << (32 * arch)) - 1

   return result

def mark_executable(buff, size):
   if not VirtualProtect:
      raise FunctionError("host system isn't Windows or doesn't have Wine")

   VirtualProtect(buff, size, 0x40, ctypes.byref(ctypes.c_int()))

def executable_buffer(str_or_num):
   if not VirtualProtect:
      raise FunctionError("host system isn't Windows or doesn't have Wine")

   ret = ctypes.create_string_buffer(str_or_num)

   if isinstance(str_or_num, basestring):
      size = len(str_or_num)
   else:
      size = str_or_num

   mark_executable(ret, size)
   return ret

def find_bin_in_path(bin_name):
   paths = os.environ['PATH'].split(';')

   if '.' in bin_name:
      bin_regex = '^%s$' % bin_name
   else:
      bin_regex = '^%s(\\.exe)?$' % bin_name

   if len(paths) == 1: # linux environment, likely
      paths = os.environ['PATH'].split(':')

      if not len(paths) == 1:
         bin_regex = '^%s$' % bin_name

   bin_regex = re.compile(bin_regex)

   for execpath in paths:
      execpath = execpath.rstrip('/').rstrip('\\')

      if ExpandEnvironmentStringsA: 
         buff = ctypes.create_string_buffer(0x102)
         ExpandEnvironmentStringsA(execpath, buff, 0x101)
         execpath = buff.value

      try:
         files = os.listdir(execpath)
         files.sort()
      except:
         continue
      
      for filename in files:
         if ExpandEnvironmentStringsA:
            match_obj = bin_regex.match(filename.lower())

            if match_obj:
               return '%s\\%s' % (execpath, filename)
         else:
            match_obj = bin_regex.match(filename)

            if match_obj:
               return '%s/%s' % (execpath, filename)

   return None

def find_assembler():
   yasm = find_bin_in_path('yasm')

   if not yasm:
      yasm = find_bin_in_path('nasm')

   if not yasm:
      raise AssemblyError("couldn't find assembler in PATH")

   return yasm

def assemble_file(nasm_file):
   fp = open(nasm_file)
   data = fp.read()
   fp.close()

   return assemble_code(data)

def assemble_code(nasm_code):
   temp_asm = tempfile.NamedTemporaryFile(mode='w+', prefix='peelasm', delete=False)
   temp_obj = tempfile.NamedTemporaryFile(prefix='peelasmobj', delete=False)

   temp_asm.write(nasm_code)
   temp_asm.close()
   temp_obj.close()

   worked = True

   try:
      assembler = find_assembler()

      proc = subprocess.Popen([assembler, '-f', 'win32', temp_asm.name, '-o', temp_obj.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      stdout, stderr = proc.communicate()

      if stdout:
         DBG1('assembler stdout:')
         for chunk in stdout.split('\n'): DBG1('... %s' % chunk)

      if stderr:
         DBG1('assembler stderr:')
         for chunk in stderr.split('\n'): DBG1('... %s' % chunk)
         worked = False # halt on any error from the assembler

      if is_medium():
         DBG2('the assembly code:')
         chunks = re.split('\r?\n', nasm_code)
         
         for i in xrange(len(chunks)):
            DBG2('... [%5d] %s', i+1, chunks[i])

      if not proc.returncode == 0:
         raise AssemblyError('nasm failed to compile')

      obj_file = open(temp_obj.name, 'rb')
      obj_data = obj_file.read()
      obj_file.close()
   finally:
      os.remove(temp_asm.name)
      if worked:
         os.remove(temp_obj.name)
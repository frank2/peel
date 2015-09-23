#!/usr/bin/env python

from paranoia.types.structure import Structure

from .file import IMAGE_FILE_HEADER
from .optional import IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64
from .win32 import *

class NTHeaders32(Structure.simple([
   ('Signature',       DWORD)
   ,('FileHeader',      IMAGE_FILE_HEADER)
   ,('OptionalHeader',  IMAGE_OPTIONAL_HEADER32)])):

   def __init__(self, **kwargs):
      Structure.__init__(self, **kwargs)

      if kwargs.setdefault('set_defaults',0):
         self.set_defaults()

   def set_defaults(self):
      self.Signature.set_value(IMAGE_NT_SIGNATURE)
      self.FileHeader.set_defaults()
      self.OptionalHeader.set_defaults()

IMAGE_NT_HEADERS32 = NTHeaders32

class NTHeaders64(Structure.simple([
    ('Signature',       DWORD),
    ('FileHeader',      IMAGE_FILE_HEADER),
    ('OptionalHeader',  IMAGE_OPTIONAL_HEADER64)])):

   def __init__(self, **kwargs):
      Structure.__init__(self, **kwargs)

      if kwargs.setdefault('set_defaults',0):
         self.set_defaults()

   def set_defaults(self):
      self.Signature.set_value(IMAGE_NT_SIGNATURE)
      self.FileHeader.set_defaults()
      self.OptionalHeader.set_defaults()

IMAGE_NT_HEADERS64 = NTHeaders64

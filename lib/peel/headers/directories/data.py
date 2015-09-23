#!/usr/bin/env python

from paranoia.types.structure import Structure
from paranoia.base.abstract.array import Array

class DataDirectory(Structure.simple([
      ('VirtualAddress', DWORD)
      ,('Size',           DWORD)])):

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

class DataDirectoryArray(Array):
   BASE_CLASS = DataDirectory

   def __repr__(self):
      return '<DataDirectoryArray:\n%s\n>' % '\n'.join(map(repr, self))

PIMAGE_DATA_DIRECTORY = DataDirectoryArray

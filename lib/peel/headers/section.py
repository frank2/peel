#!/usr/bin/env python

from paranoia.base.abstract.structure import Structure
from paranoia.base.abstract.array import Array

from .file import IMAGE_FILE_HEADER
from .optional import IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64
from .win32 import *

class Section(Structure.simple([
    ('Name',                  LPBYTE,  {'elements': 8}),
    ('VirtualSize',           DWORD),
    ('VirtualAddress',        DWORD),
    ('SizeOfRawData',         DWORD),
    ('PointerToRawData',      DWORD),
    ('PointerToRelocations',  DWORD),
    ('PointerToLinenumbers',  DWORD),
    ('NumberOfRelocations',   WORD),
    ('NumberOfLinenumbers',   WORD),
    ('Characteristics',       DWORD)])):

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

class SectionArray(Array):
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

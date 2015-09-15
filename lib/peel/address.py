#!/usr/bin/env python

from peel import base
from peel import image

class AddressError(base.PEELError): # TODO some contextual stuff
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
         except (AddressError, base.HeaderError),e:
            DBG3("got error converting value: %s", str(e))
            return 0

      if self.image.has_virtual_image():
         return 0 < value_check < self.image.virtual_length()
      elif self.image.has_optional_header():
         size = int(self.image.IMAGE_OPTIONAL_HEADER.SizeOfImage)
         return 0 < value_check < size 
      else:
         raise image.ImageError("attempting to verify validity of an rva via SizeOfImage without an optional header present. see PEImage.section_by_offset as to why this error was raised.")

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
         except (AddressError, base.HeaderError),e:
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
         except (AddressError, base.HeaderError),e:
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

#!/usr/bin/env python

import ctypes

from paranoia.base import allocator
from paranoia.base import paranoia_agent
from paranoia.converters import *

class MemoryRegionError(paranoia_agent.ParanoiaError):
    pass

class MemoryRegion(paranoia_agent.ParanoiaAgent):
    BITSPAN = None
    MEMORY_BASE = None
    AUTO_ALLOCATE = True
    PARENT_REGION = None
    ALLOCATOR_CLASS = allocator.Allocator
    ALLOCATOR = None
    BITSHIFT = 0
    ALIGNMENT = 8
    ALIGN_BIT = 1
    ALIGN_BYTE = 8

    def __init__(self, **kwargs):
        paranoia_agent.ParanoiaAgent.__init__(self)

        self.allocator_class = kwargs.setdefault('allocator_class', self.ALLOCATOR_CLASS)
        self.allocator = kwargs.setdefault('allocator', self.ALLOCATOR)        
        self.alignment = kwargs.setdefault('alignment', self.ALIGNMENT)
        self.auto_allocate = kwargs.setdefault('auto_allocate', self.AUTO_ALLOCATE)
        self.parent_region = kwargs.setdefault('parent_region', self.PARENT_REGION)
        self.bitspan = kwargs.setdefault('bitspan', self.BITSPAN)
        self.memory_base = kwargs.setdefault('memory_base', self.MEMORY_BASE)
        self.bitshift = kwargs.setdefault('bitshift', self.BITSHIFT)

        if not issubclass(self.allocator_class, allocator.Allocator):
            raise MemoryRegionError('allocator class must implement allocator.Allocator')
        if self.alignment is None or self.alignment < 0:
            raise MemoryRegionError('alignment cannot be None or less than 0')

        if self.bitspan is None or self.bitspan == 0:
            raise MemoryRegionError('bitspan cannot be None or 0')

        if self.bitshift > 8 or self.bitshift < 0:
            raise MemoryRegionError('bitshift must be within the range of 0-8 noninclusive')

        if not self.parent_region is None and not isinstance(self.parent_region, MemoryRegion):
            raise MemoryRegionError('parent_region must implement MemoryRegion')

        if self.allocator is None:
            if self.parent_region is None:
                self.allocator = self.allocator_class(**kwargs)
            elif not self.allocator_class == self.parent_region.allocator_class:
                self.allocator = self.parent_region.allocator_class(**kwargs)
            else:
                parent_region = self.parent_region

                while not parent_region is None:
                    if not self.allocator_class == parent_region.allocator_class:
                        break

                    parent_region = parent_region.parent_region

                if parent_region is None:
                    self.allocator = self.allocator_class(**kwargs)
                else:
                    self.allocator = parent_region.allocator_class(**kwargs)
        elif not isinstance(self.allocator, allocator.Allocator):
            raise MemoryRegionError('allocator must implement allocator.Allocator')

        if self.memory_base is None and self.auto_allocate:
            self.memory_base = self.allocator.allocate(self.shifted_bytespan())
        elif self.memory_base is None:
            raise MemoryRegionError('memory_base cannot be None when allocate is False')

    def bytespan(self):
        return align(self.bitspan, self.alignment) / 8

    def shifted_bitspan(self):
        return self.bitspan + self.bitshift

    def shifted_bytespan(self):
        return align(self.shifted_bitspan(), self.alignment) / 8
    
    def read_bytes(self, byte_length, byte_offset=0):
        if (byte_length+byte_offset)*8 > align(self.bitspan, 8): 
            raise MemoryRegionError('byte length and offset exceed aligned bitspan (%d, %d, %d)' % (byte_length, byte_offset, align(self.bitspan, 8)))

        try:
            return map(ord, ctypes.string_at(self.memory_base+byte_offset, byte_length))
        except:
            raise MemoryRegionError('raw memory access failed')

    def read_bytelist_for_bits(self, bit_length, bit_offset=0):
        if bit_length + bit_offset > self.bitspan:
            raise MemoryRegionError('bit length and offset exceed bitspan')

        # true_offset represents where in the first byte to start reading bits
        true_offset = self.bitshift + bit_offset

        # get the number of bytes necessary to grab our contextual bits
        byte_length = align(bit_length+(true_offset % 8), 8)/8

        # convert the bytes into a string of bits
        return self.read_bytes(byte_length, true_offset/8)

    def read_bitlist_from_bytes(self, bit_length, bit_offset=0):
        if bit_length + bit_offset > self.bitspan:
            raise MemoryRegionError('bit length and offset exceed bitspan')

        unconverted_bytes = self.read_bytelist_for_bits(bit_length, bit_offset)
        return ''.join(map('{0:08b}'.format, unconverted_bytes))

    def read_bits_from_bytes(self, bit_length, bit_offset=0):
        # take only the contextual bits based on the bit_length
        if bit_length + bit_offset > self.bitspan:
            raise MemoryRegionError('bit length and offset exceed bitspan')

        # true_offset represents where in the first byte to start reading bits
        true_offset = self.bitshift + bit_offset

        converted_bytes = self.read_bitlist_from_bytes(bit_length, bit_offset)
        return map(int, converted_bytes)[true_offset:bit_length+true_offset]

    def read_bits(self, bit_length=None, bit_offset=0):
        if not bit_length:
            bit_length = self.bitspan
            
        return self.read_bits_from_bytes(bit_length, bit_offset)

    def read_bytes_from_bits(self, bit_length, bit_offset=0):
        return bitlist_to_bytelist(self.read_bits_from_bytes(bit_length, bit_offset))

    def write_bytes(self, byte_list, byte_offset=0):
        if (len(byte_list)+byte_offset)*8 > align(self.bitspan, 8):
            raise MemoryRegionError('list plus offset exceeds memory region boundary')

        string_buffer = ctypes.create_string_buffer(''.join(map(chr, byte_list)))

        try:
            ctypes.memmove(self.memory_base+byte_offset, ctypes.addressof(string_buffer), len(byte_list))
        except:
            raise MemoryRegionError('write exceeds region boundaries')

    def write_bits(self, bit_list, bit_offset=0):
        if len(bit_list) + bit_offset > self.bitspan:
            raise MemoryRegionError('list plus offset exceeds memory region boundary')

        true_offset = self.bitshift + bit_offset
        true_terminus = true_offset + len(bit_list)
        byte_start = true_offset/8
        byte_end = true_terminus/8

        # value represents the number of bits which overwrite the underlying byte

        if byte_start == byte_end:
            single_shift = ((8 - len(bit_list)) - true_offset)
            value_mask = ((2 ** len(bit_list)) - 1) << single_shift
            underlying_mask = 0xFF ^ value_mask
            underlying_value = self.read_bytes(1, byte_start)[0]
            bit_value = bitlist_to_numeric(bit_list) << single_shift
            mask_result = underlying_value & underlying_mask | bit_value

            self.write_bytes([mask_result], byte_start)
            return

        front_remainder = alignment_delta(true_offset, 8)

        if front_remainder:
            front_bits = bit_list[:front_remainder]
            front_byte_mask = (0xFF ^ (2 ** front_remainder) - 1)
            front_byte_value = self.read_bytes(1, byte_start)[0]
            front_bit_value = bitlist_to_numeric(front_bits)
            mask_result = front_byte_value & front_byte_mask | front_bit_value

            self.write_bytes([mask_result], byte_start)            
            byte_start += 1

        # value represents the number of bits which overwrite the underlying byte
        back_remainder = true_terminus % 8

        if back_remainder:
            back_bits = bit_list[len(bit_list) - back_remainder:]
            back_byte_mask = (2 ** back_remainder) - 1
            back_byte_value = self.read_bytes(1, byte_end)[0]
            back_bit_value = bitlist_to_numeric(back_bits)
            mask_result = back_byte_value & back_byte_mask | (back_bit_value << (8 - back_remainder))
            
            self.write_bytes([mask_result], byte_end)

        bytebound_list = bit_list[front_remainder:(len(bit_list) - back_remainder)]
        bytebound_list = bitlist_to_bytelist(bytebound_list)
        self.write_bytes(bytebound_list, byte_start)

    def write_bits_from_bytes(self, byte_list, bit_offset=0):
        self.write_bits(bytelist_to_bitlist(byte_list), bit_offset)

    def write_bytes_from_bits(self, bit_list, byte_offset=0):
        self.write_bytes(bitlist_to_bytelist(bit_list), byte_offset)

    def root_parent(self):
        root_parent = self

        while not root_parent.parent_region == None:
            root_parent = root_parent.parent_region

        return root_parent

    def __hash__(self):
        return hash('%X/%d/%d' % (self.memory_base, self.bitspan, self.bitshift))

    @classmethod
    def static_bitspan(cls):
        return cls.BITSPAN

    @classmethod
    def static_alignment(cls):
        return cls.ALIGNMENT

    @classmethod
    def static_bytespan(cls):
        bitspan = cls.static_bitspan()
        alignment = cls.static_alignment()
        return align(bitspan, alignment) / 8

    @classmethod
    def static_declaration(cls, **kwargs):
        kwargs.setdefault('auto_allocate', cls.AUTO_ALLOCATE)
        kwargs.setdefault('parent_region', cls.PARENT_REGION)
        kwargs.setdefault('allocator_class', cls.ALLOCATOR_CLASS)
        kwargs.setdefault('allocator', cls.ALLOCATOR)
        kwargs.setdefault('bitspan', cls.BITSPAN)
        kwargs.setdefault('memory_base', cls.MEMORY_BASE)
        kwargs.setdefault('bitshift', cls.BITSHIFT)

        class StaticMemoryRegion(cls):
            AUTO_ALLOCATE = kwargs['auto_allocate']
            PARENT_REGION = kwargs['parent_region']
            ALLOCATOR_CLASS = kwargs['allocator_class']
            ALLOCATOR = kwargs['allocator']
            BITSPAN = kwargs['bitspan']
            MEMORY_BASE = kwargs['memory_base']
            BITSHIFT = kwargs['bitshift']

        return StaticMemoryRegion

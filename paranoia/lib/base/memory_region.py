#!/usr/bin/env python

import ctypes

from paranoia.base import paranoia_agent
from paranoia.converters import *

class MemoryRegionError(paranoia_agent.ParanoiaError):
    pass

class MemoryRegion(paranoia_agent.ParanoiaAgent):
    BITSPAN = None
    MEMORY_BASE = None
    BITSHIFT = 0
    VIRTUAL_BASE = 0
    ALIGNMENT = 8
    ALIGN_BIT = 1
    ALIGN_BYTE = 8

    def __init__(self, **kwargs):
        self.alignment = kwargs.setdefault('alignment', self.ALIGNMENT)
        self.bitspan = kwargs.setdefault('bitspan', self.BITSPAN)
        self.memory_base = kwargs.setdefault('memory_base', self.MEMORY_BASE)
        self.bitshift = kwargs.setdefault('bitshift', self.BITSHIFT)
        self.virtual_base = kwargs.setdefault('virtual_base', self.VIRTUAL_BASE)

        if self.alignment is None or self.alignment < 0:
            raise MemoryRegionError('alignment cannot be None or less than 0')

        if self.bitspan is None or self.bitspan == 0:
            raise MemoryRegionError('bitspan cannot be None or 0')

        if self.memory_base is None:
            raise MemoryRegionError('memory_base cannot be None')

        if self.bitshift > 8 or self.bitshift < 0:
            raise MemoryRegionError('bitshift must be within the range of 0-8 noninclusive')

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

    def __hash__(self):
        return hash('%X/%d/%d' % (self.memory_base, self.bitspan, self.bitshift))

    @classmethod
    def static_bitspan(cls):
        return cls.BITSPAN

    @classmethod
    def static_alignment(cls):
        return cls.ALIGNMENT

    @classmethod
    def static_declaration(cls, **kwargs):
        kwargs.setdefault('bitspan', cls.BITSPAN)
        kwargs.setdefault('memory_base', cls.MEMORY_BASE)
        kwargs.setdefault('bitshift', cls.BITSHIFT)
        kwargs.setdefault('virtual_base', cls.VIRTUAL_BASE)

        class StaticMemoryRegion(cls):
            BITSPAN = kwargs['bitspan']
            MEMORY_BASE = kwargs['memory_base']
            BITSHIFT = kwargs['bitshift']
            VIRTUAL_BASE = kwargs['virtual_base']

        return StaticMemoryRegion

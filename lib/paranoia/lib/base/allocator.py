#!/usr/bin/env python

import ctypes

from . import paranoia_agent

class AllocatorError(paranoia_agent.ParanoiaError):
    pass

class Allocator(paranoia_agent.ParanoiaAgent):
    def __init__(self, **kwargs):
        self.address_map = dict()

    def allocate(self, byte_length):
        if not isinstance(byte_length, (int, long)):
            raise AllocatorError('integer value not given')

        c_string = ctypes.create_string_buffer(byte_length)
        c_address = ctypes.addressof(c_string)
        self.address_map[c_address] = c_string

        return c_address

    def allocate_string(self, string):
        if not isinstance(string, basestring):
            raise AllocatorError('string value not given')

        c_string = ctypes.create_string_buffer(string)
        c_address = ctypes.addressof(c_string)
        self.address_map[c_address] = c_string
        
        return c_address

    def deallocate(self, address):
        if not self.address_map.has_key(address):
            raise AllocatorError('no such address allocated: 0x%x' % address)

        c_string = self.address_map[address]

        del c_string
        del self.address_map[address]

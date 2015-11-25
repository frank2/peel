#!/usr/bin/env python

from paranoia.base.pointer import Pointer

class Offset(Pointer):
    def memory_value(self):
        root_parent = self.root_parent()
        offset_value = self.get_value()

        return root_parent.memory_base + offset_value

class Offset32(Offset):
    BITSPAN = 32

class Offset64(Offset):
    BITSPAN = 64

#!/usr/bin/env python

from . import memory_region
from . import numeric_region

class PointerError(numeric_region.NumericRegionError):
    pass

class Pointer(numeric_region.NumericRegion):
    CASTING_CLASS = None
    OFFSET_BASE = None

    def __init__(self, **kwargs):
        self.casting_class = kwargs.setdefault('casting_class', self.CASTING_CLASS)

        if self.casting_class is None:
            raise PointerError('no casting class given to pointer')
        
        self.offset_base = kwargs.setdefault('offset_base', self.OFFSET_BASE)

        if not issubclass(self.casting_class, memory_region.MemoryRegion):
            raise PointerError('casting class must implement MemoryRegion')
        
        numeric_region.NumericRegion.__init__(self, **kwargs)

    def deref(self, casting_class=None):
        address = self.get_value()
        
        if not self.offset_base == None:
            address += self.offset_base

        if casting_class is None:
            casting_class = self.casting_class

        if casting_class is None:
            raise PointerError('no casting class given for dereference')
        
        return casting_class(memory_base=address)

    @classmethod
    def cast(cls, casting_class):
        class CastedPointer(cls):
            CASTING_CLASS = casting_class

        return CastedPointer

class Pointer32(Pointer):
    BITSPAN = 32

class Pointer64(Pointer):
    BITSPAN = 64

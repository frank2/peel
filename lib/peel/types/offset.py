#!/usr/bin/env python

from paranoia.base.pointer import Pointer

from .peeler import *
from .raw import Raw
from .virtual import Virtual

class OffsetError(PeelError):
    pass

class Offset(Peeler, Pointer):
    def image(self):
        return self.root_parent().image
        
    def offset(self):
        parent_region = self.root_parent()

        if isinstance(parent_region, Virtual):
            return self.pva() - parent_region.image.raw.pva()
        elif isinstance(parent_region, Raw):
            return self.pva() - parent_region.pva()
        else:
            raise OffsetError('root parent must be a Virtual or Raw image')
    
    def rva(self):
        parent_region = self.root_parent()

        if isinstance(parent_region, Virtual):
            return parent_region.offset_to_rva(self.offset())
        elif isinstance(parent_region, Raw):
            return parent_region.image.virtual.offset_to_rva(self.offset())
        else:
            raise OffsetError('root parent must be a Virtual or Raw image')
            
    def va(self):
        parent_region = self.root_parent()

        if isinstance(parent_region, Virtual):
            return parent_region.offset_to_va(self.offset())
        elif isinstance(parent_region, Raw):
            return parent_region.image.virtual.offset_to_va(self.offset())
        else:
            raise OffsetError('root parent must be a Virtual or Raw image')

    def pva(self):
        return self.memory_base
            
class Offset16(Offset):
    BITSPAN = 16

class Offset32(Offset):
    BITSPAN = 32

class Offset64(Offset):
    BITSPAN = 64

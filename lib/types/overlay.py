#!/usr/bin/env python

from paranoia.base.memory_region import MemoryRegion

from peel.headers import *

class Overlay(MemoryRegion):
    OVERLAY_TYPE = None
    IMAGE_DATA = None
    IMAGE_SIZE = None

    OVERLAY_RAW = 0
    OVERLAY_VIRTUAL = 1
    
    def __init__(self, **kwargs):
        self.overlay_type = kwargs.setdefault('overlay_type', self.OVERLAY_TYPE)
        self.image_data = kwargs.setdefault('image_data', self.IMAGE_DATA)
        self.image_size = kwargs.setdefault('image_size', self.IMAGE_SIZE)

        kwargs['bitspan'] = self.image_size * 8

        MemoryRegion.__init__(self, **kwargs)
        

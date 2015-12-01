#!/usr/bin/env python

from paranoia.base.memory_region import MemoryRegion

from peel.headers.dos import *
from peel.headers.nt import *
from peel.headers.section import *
from peel.types.offset import *

class OverlayError(Exception):
    pass

class Overlay(MemoryRegion):
    OVERLAY_TYPE = None
    IMAGE_DATA = None
    IMAGE_SIZE = None

    OVERLAY_RAW = 0
    OVERLAY_VIRTUAL = 1
    
    def __init__(self, **kwargs):
        self.overlay_type = kwargs.setdefault('overlay_type', self.OVERLAY_TYPE)

        image_data = kwargs.setdefault('image_data', self.IMAGE_DATA)
        image_size = kwargs.setdefault('image_size', self.IMAGE_SIZE)

        if image_data:
            kwargs['string_data'] = image_data

        if image_size:
            kwargs['bitspan'] = image_size * 8

        MemoryRegion.__init__(self, **kwargs)

    def parse_dos_headers(self):
        offset = self.offset(0)

        self.dos_headers = offset.deref(casting_class=DOSHeader)

        if not int(self.dos_headers.e_magic) == 0x5A4D:
            raise OverlayError('bad DOS magic value')
        
        return self.dos_headers

    def get_dos_headers(self):
        if not getattr(self, 'dos_headers', None):
            self.parse_dos_headers()

        return self.dos_headers

    def parse_nt_headers(self):
        # TODO automatically parse 64-bit headers if 64-bit arch is set

        dos_header = self.get_dos_headers()
        self.nt_headers = dos_header.e_lfanew.deref(casting_class=NTHeader32)

        if not int(self.nt_headers.Signature) == 0x4550:
            raise OverlayError('bad NT signature value')
        
        return self.nt_headers

    def get_nt_headers(self):
        if not getattr(self, 'nt_headers', None):
            self.parse_nt_headers()

        return self.nt_headers

    def parse_section_table(self):
        nt_headers = self.get_nt_headers()
        sections = int(nt_headers.FileHeader.NumberOfSections)
        size = int(nt_headers.FileHeader.SizeOfOptionalHeader)
        base = nt_headers.OptionalHeader.memory_base + size

        self.section_table = SectionTable(memory_base=base, elements=sections, parent_region=self)
        return self.section_table

    def get_section_table(self):
        if not getattr(self, 'section_table', None):
            self.parse_section_table()

        return self.section_table

    def offset(self, value):
        return Offset32(value=value, parent_region=self)

    def rva(self, value):
        pass

    def va(self, value):
        pass

    def pva(self, value):
        pass

class RawOverlay(Overlay):
    OVERLAY_TYPE = Overlay.OVERLAY_RAW
        
class VirtualOverlay(Overlay):
    OVERLAY_TYPE = Overlay.OVERLAY_VIRTUAL
        

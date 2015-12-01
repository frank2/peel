#!/usr/bin/env python

from peel.overlay import RawOverlay, VirtualOverlay

class ImageError(Exception):
    pass

class Image(object):
    FILENAME = None
    BIAS = 0
    
    PARSE_RAW = False
    PARSE_VIRTUAL = False

    RAW_DATA = None
    VIRTUAL_DATA = None

    BIAS_RAW = 0
    BIAS_VIRTUAL = 1
    
    def __init__(self, **kwargs):
        self.filename = kwargs.setdefault('filename', self.FILENAME)
        self.bias = kwargs.setdefault('bias', self.BIAS)

        parse_raw = kwargs.setdefault('parse_raw', self.PARSE_RAW)
        parse_virtual = kwargs.setdefault('parse_virtual', self.PARSE_VIRTUAL)
        raw_data = kwargs.setdefault('raw_data', self.RAW_DATA)
        virtual_data = kwargs.setdefault('virtual_data', self.VIRTUAL_DATA)

        if self.filename and not raw_data:
            fp = open(self.filename, 'rb')
            raw_data = fp.read()
            fp.close()

        self.raw = None
        self.virtual = None

        if raw_data and not parse_raw:
            self.create_raw_overlay(image_data=raw_data)
        if virtual_data and not parse_virtual:
            self.create_virtual_overlay(image_data=virtual_data)

        if parse_raw:
            self.parse_raw_overlay()
        if parse_virtual:
            self.parse_virtual_overlay()

    def create_raw_overlay(self, **kwargs):
        self.raw = RawOverlay(**kwargs)
        return self.raw

    def create_virtual_overlay(self, **kwargs):
        self.virtual = VirtualOverlay(**kwargs)
        return self.virtual

    def parse_raw_overlay(self):
        if not self.virtual:
            raise ImageError('no virtual overlay to parse from')

        self.raw = self.virtual.parse_inverse()
        return self.raw

    def parse_virtual_overlay(self):
        if not self.raw:
            raise ImageError('no raw overlay to parse from')

        self.virtual = self.raw.parse_inverse()
        return self.virtual

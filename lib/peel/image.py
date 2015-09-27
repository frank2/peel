#!/usr/bin/env python

from .types.peeler import *
from .types.raw import *
from .types.virtual import *

class ImageError(PeelError):
    pass

class Image(Peeler):
    FILENAME = None
    DATA = None
    RAW = None
    VIRTUAL = None
    LOAD_VIRTUAL = 1
    LOAD_RAW = 0
    
    SKIP_VIRTUAL = 0
    PARSE_VIRTUAL = 1
    SKIP_RAW = 0
    PARSE_RAW = 1

    def __init__(self, **kwargs):
        filename = kwargs.setdefault('filename', self.FILENAME)
        data = kwargs.setdefault('data', self.RAW_DATA)
        load_virtual = kwargs.setdefault('load_virtual', self.LOAD_VIRTUAL)
        load_raw = kwargs.setdefault('load_raw', self.LOAD_RAW)        
        
        self.raw = kwargs.setdefault('raw', self.RAW)
        self.virtual = kwargs.setdefault('virtual', self.VIRTUAL)

        if filename is None and data is None and self.raw is None and self.virtual is None:
            raise ImageError('at least one argument must be provided: filename, data, raw, virtual')

        if not self.virtual is None and self.raw is None and load_raw == self.PARSE_RAW:
            self.raw = self.virtual.infer_raw_image()

        if not filename is None and data is None:
            fp = open(self.filename, 'rb')
            self.raw_data = fp.read()
            fp.close()

        if self.raw is None:
            self.raw = Raw(image_data=data)

        if self.virtual is None and load_virtual == self.PARSE_VIRTUAL:
            self.virtual = Virtual(raw_image=self.raw)

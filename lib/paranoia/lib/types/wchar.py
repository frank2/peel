#!/usr/bin/env python

from paranoia.base import numeric_region
from paranoia.base.abstract import array
from . import word

class WcharError(numeric_region.NumericRegionError):
    pass

class Wchar(word.Word):
    def get_wchar_value(self):
        return ''.join(map(chr, self.read_bytes_from_bits(2))).decode('utf-16')

    def set_wchar_value(self, wchar):
        if not isinstance(wchar, unicode):
            raise WcharError('input value must be a unicode string')

        if len(wchar) > 1:
            raise WcharError('input string can only be one character long')

        self.write_bits_from_bytes(map(ord, wchar.encode('utf-16be')))

class WcharArray(array.Array):
    BASE_CLASS = Wchar

#!/usr/bin/env python

from paranoia.base import numeric_region
from . import byte

class CharError(numeric_region.NumericRegionError):
    pass

class Char(byte.Byte):
    def get_char_value(self):
        return chr(self.get_value())

    def set_char_value(self, char):
        if not isinstance(char, basestring):
            raise CharError('input value must be a string')

        if len(char) > 1:
            raise CharError('input string can only be one character long')

        self.set_value(ord(char))

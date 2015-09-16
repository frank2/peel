#!/usr/bin/env python

from paranoia.base import numeric_region
from paranoia.base.abstract import array

class Byte(numeric_region.NumericRegion):
    BITSPAN = 8

class ByteArray(array.Array):
    BASE_CLASS = Byte

#!/usr/bin/env python

from paranoia.base import numeric_region
from paranoia.base.abstract import array

class Qword(numeric_region.NumericRegion):
    BITSPAN = 64

class QwordArray(array.Array):
    BASE_CLASS = Qword

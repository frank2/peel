#!/usr/bin/env python

from paranoia.base import numeric_region
from paranoia.base.abstract import array

class Word(numeric_region.NumericRegion):
    BITSPAN = 16

class WordArray(array.Array):
    BASE_CLASS = Word


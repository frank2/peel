#!/usr/bin/env python

from peel.types.offset import Offset

class RVA(Offset):
    pass

class RVA32(RVA):
    BITSPAN = 32

class RVA64(RVA):
    BITSPAN = 64

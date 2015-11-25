#!/usr/bin/env python

from paranoia.types.structure import Structure

from peel.types.offset import Offset32
from peel.types.typedefs import *

class DOSHeader(Structure.simple([
        ('e_magic',     WORD)
        ,('e_cblp',     WORD)
        ,('e_cp',       WORD)
        ,('e_crlc',     WORD)
        ,('e_cparhdr',  WORD)
        ,('e_minalloc', WORD)
        ,('e_maxalloc', WORD)
        ,('e_ss',       WORD)
        ,('e_sp',       WORD)
        ,('e_csum',     WORD)
        ,('e_ip',       WORD)
        ,('e_cs',       WORD)
        ,('e_lfarlc',   WORD)
        ,('e_ovno',     WORD)
        ,('e_res',      WORD_ARRAY.static_declaration(elements=4))
        ,('e_oemid',    WORD)
        ,('e_oeminfo',  WORD)
        ,('e_res2',     WORD_ARRAY.static_declaration(elements=10))
        ,('e_lfanew',   Offset32)])):
    pass

IMAGE_DOS_HEADER = DOSHeader

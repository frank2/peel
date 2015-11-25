#!/usr/bin/env python

from paranoia.types import *
from paranoia.base.abstract.array import Array

BYTE = Byte
WORD = Word
DWORD = Dword
QWORD = Qword

CHAR = Byte.static_declaration(signage=Byte.SIGNED)
SHORT = Word.static_declaration(signage=Word.SIGNED)
LONG = Dword.static_declaration(signage=Dword.SIGNED)
LONGLONG = Qword.static_declaration(signage=Qword.SIGNED)

BYTE_ARRAY = Array.static_declaration(base_class=BYTE)
WORD_ARRAY = Array.static_declaration(base_class=WORD)
DWORD_ARRAY = Array.static_declaration(base_class=DWORD)
QWORD_ARRAY = Array.static_declaration(base_class=QWORD)
CHAR_ARRAY = Array.static_declaration(base_class=CHAR)
SHORT_ARRAY = Array.static_declaration(base_class=SHORT)
LONG_ARRAY = Array.static_declaration(base_class=LONG)
LONGLONG_ARRAY = Array.static_declaration(base_class=LONGLONG)

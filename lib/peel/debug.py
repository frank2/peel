#!/usr/bin/env python

import sys

# debug logging verbosity (set_verbosity() to adjust)
VERBOSITY = 0

# some names for fancypants debugging
MILD_VERBOSITY = 1
MEDIUM_VERBOSITY = 2
SPICY_VERBOSITY = 3
XTREME_VERBOSITY = 4

def set_verbosity(verbosity):
   global VERBOSITY
   VERBOSITY = verbosity

def no_verbosity():
   return set_verbosity(0)

def mild_verbosity():
   return set_verbosity(MILD_VERBOSITY)

def medium_verbosity():
   return set_verbosity(MEDIUM_VERBOSITY)

def spicy_verbosity():
   return set_verbosity(SPICY_VERBOSITY)

def xtreme_verbosity():
   return set_verbosity(XTREME_VERBOSITY)

def is_mild():
   return get_verbosity() >= MILD_VERBOSITY

def is_medium():
   return get_verbosity() >= MEDIUM_VERBOSITY

def is_spicy():
   return get_verbosity() >= SPICY_VERBOSITY

def is_xtreme():
   return get_verbosity() >= XTREME_VERBOSITY

def get_verbosity(): # so we don't have to type "global VERBOSITY" everywhere
   global VERBOSITY
   return VERBOSITY

def DEBUG(level, fmt, *args):
   if level > get_verbosity():
      return

   return sys.stderr.write('[%.3f] [DEBUG=%d] %s\n' % (time.time(),level,fmt % tuple(args)))

def DBG1(fmt, *args):
   return DEBUG(1, fmt, *args)

def DBG2(fmt, *args):
   return DEBUG(2, fmt, *args)

def DBG3(fmt, *args):
   return DEBUG(3, fmt, *args)

def DBG4(fmt, *args):
   return DEBUG(4, fmt, *args)

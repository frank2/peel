#!/usr/bin/env python

# a structure is, for all intents and purposes, a mapping. this is simply
# syntactic sugar.

from paranoia.base.abstract import mapping

class StructureError(mapping.MappingError):
    pass

class Structure(mapping.Mapping):
    pass

#!/usr/bin/env python

from . import structure
from . import declaration
from .. import memory_region

class UnionError(structure.StructureError):
    pass

class Union(structure.Structure):
    def calculate_offsets(self, start_from=0):
        longest_object = 0
        self.declaration_offsets = dict()
        
        for i in xrange(len(self.declarations)):
            declaration = self.declarations[i]
            offset_dict = dict()

            bitspan = declaration.bitspan()
            alignment = declaration.alignment()

            offset_dict['memory_base'] = self.memory_base
            offset_dict['bitshift'] = self.bitshift

            self.declaration_offsets[i] = offset_dict

            if bitspan > longest_object:
                longest_object = bitspan

        self.bitspan = longest_object

    def __getattr__(self, attr):
        if attr == 'union_map':
            attr = 'struct_map'

        return structure.Structure.__getattr__(self, attr)

    @classmethod
    def static_bitspan(cls):
        return max(map(lambda x: x[1].bitspan(), cls.FIELDS))

    @classmethod
    def simple(cls, declarations):
        new_union_declaration = dict()

        if not isinstance(declarations, dict):
            raise UnionError('union declaration must be a dictionary of names mapping to either a declaration, a type or a tuple of type and initialization arguments')

        if len(declarations) == 0:
            raise UnionError('empty declaration dict given')

        for name, declare in declarations.items():
            if not isinstance(name, basestring):
                raise UnionError('first argument of the declaration must be a string')
            
            if getattr(declare, '__iter__', None) and len(declare) == 2:
                declare = declaration.Declaration(base_class=declare[0]
                                                  ,args=declare[1])
            elif issubclass(declare, memory_region.MemoryRegion):
                declare = declaration.Declaration(base_class=declare)
            elif not isinstance(declare, declaration.Declaration):
                raise UnionError('second argument of the declaration must be either a declaration, a type or a tuple containing a type and arguments')
                
            new_union_declaration[name] = declare

        class SimplifiedUnion(cls):
            FIELDS = new_union_declaration.items()[:]

        return SimplifiedUnion

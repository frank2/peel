#!/usr/bin/env python

from paranoia.base.abstract import mapping

class UnionError(mapping.MappingError):
    pass

class Union(mapping.Mapping):
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

    @classmethod
    def static_bitspan(cls):
        return max(map(lambda x: x[1].bitspan(), cls.FIELDS))

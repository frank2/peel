#!/usr/bin/env python

from . import list as d_list
from . import declaration
from .. import memory_region

class StructureError(d_list.ListError):
    pass

class Structure(d_list.List):
    FIELDS = None

    def __init__(self, **kwargs):
        fields = kwargs.setdefault('fields', self.FIELDS)

        if fields is None or not getattr(fields, '__iter__', None):
            raise StructureError('struct_declaration must be a sequence of names and DataDeclarations')

        self.parse_struct_fields(fields)
        kwargs['declarations'] = self.declarations # for initializing bitspan

        d_list.List.__init__(self, **kwargs)

    def parse_struct_fields(self, fields):
        self.declarations = list()
        self.struct_map = dict()

        for struct_pair in fields:
            if not len(struct_pair) == 2 or not isinstance(struct_pair[0], basestring) or not isinstance(struct_pair[1], declaration.Declaration):
                raise StructureError('struct_declaration element must be a pair consisting of a string and a Declaration.')
            
            name, declaration_obj = struct_pair
            index = len(self.declarations)
            self.declarations.append(declaration_obj)
            
            if self.struct_map.has_key(name):
                raise StructureError('%s already defined in structure' % name)

            self.struct_map[name] = index

        # XXX HACK bypass the potential for this function not to be there on init
        #if getattr(self, 'calculate_offsets', None):
        #    self.calculate_offsets()

    def __getattr__(self, attr):
        if not self.__dict__.has_key('struct_map') and not self.__dict__.has_key(attr):
            raise AttributeError(attr)
        elif not self.__dict__.has_key('struct_map'):
            return self.__dict__[attr]

        struct_map = self.__dict__['struct_map']

        if struct_map.has_key(attr):
            index = struct_map[attr]
            return self.instantiate(index)
        else:
            raise AttributeError(attr)

    @classmethod
    def static_bitspan(cls):
        return sum(map(lambda x: x[1].bitspan(), cls.FIELDS))

    @classmethod
    def simple(cls, declarations):
        new_struct_declaration = list()

        if not getattr(declarations, '__iter__', None):
            raise StructureError('declarations must be a sequence of names, a base class and optional arguments')

        if len(declarations) == 0:
            raise StructureError('empty declaration list given')

        for declaration_obj in declarations:
            if not len(declaration_obj) == 2 and not len(declaration_obj) == 3:
                raise StructureError('simple declaration item has invalid arguments')

            if not isinstance(declaration_obj[0], basestring):
                raise StructureError('first argument of the declaration must be a string')

            if not issubclass(declaration_obj[1], memory_region.MemoryRegion):
                raise StructureError('second argument must be a base class implementing MemoryRegion')

            if len(declaration_obj) == 3 and not isinstance(declaration_obj[2], dict):
                raise StructureError('optional third argument must be a dictionary of arguments')
                
            if not len(declaration_obj) == 3:
                args = dict()
            else:
                args = declaration_obj[2]

            new_struct_declaration.append([declaration_obj[0]
                                          ,declaration.Declaration(base_class=declaration_obj[1]
                                                                   ,args=args)])
        
        class SimplifiedDataStructure(cls):
            FIELDS = new_struct_declaration

        return SimplifiedDataStructure

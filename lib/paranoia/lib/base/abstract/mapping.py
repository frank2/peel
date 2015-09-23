#!/usr/bin/env python

from . import list as d_list
from . import declaration
from .. import memory_region

class MappingError(d_list.ListError):
    pass

class Mapping(d_list.List):
    FIELDS = None

    def __init__(self, **kwargs):
        fields = kwargs.setdefault('fields', self.FIELDS)

        if fields is None or not getattr(fields, '__iter__', None):
            raise StructureError('fields must be a sequence of names and DataDeclarations')

        self.parse_fields(fields)
        kwargs['declarations'] = self.declarations # for initializing bitspan

        d_list.List.__init__(self, **kwargs)

    def parse_fields(self, fields):
        self.declarations = list()
        self.field_map = dict()
        self.anon_map = dict()
        anonymous_fields = 0

        for pair in fields:
            if not len(pair) == 2 and not isinstance(pair[0], basestring) and not pair[0] == None and not isinstance(pair[1], declaration.Declaration):
                raise MappingError('field_declaration element must be a pair consisting of a string or None paired with a Declaration.')
            
            name, declaration_obj = pair

            if name == None:
                if not issubclass(declaration_obj.base_class, Mapping):
                    raise MappingError('only Mapping types can be anonymously named')
                
                name = '__anon_field%04d' % anonymous_fields
                anonymous_fields += 1
                found_fields = declaration_obj.args.get('fields', None) or declaration_obj.base_class.FIELDS

                if not found_fields:
                    raise MappingError('no fields in declaration object')

                for anon_field in found_fields:
                    anon_name, anon_decl = anon_field

                    if self.anon_map.has_key(anon_name) or self.field_map.has_key(anon_name):
                        raise MappingError('either another anonymously named mapping or another field is already taking up the name %s' % anon_name)

                    self.anon_map[anon_name] = name
                
            index = len(self.declarations)
            self.declarations.append(declaration_obj)
            
            if self.field_map.has_key(name):
                raise StructureError('%s already defined in structure' % name)

            self.field_map[name] = index

    def __getattr__(self, attr):
        if not self.__dict__.has_key('field_map') and not self.__dict__.has_key('anon_map') and not self.__dict__.has_key(attr):
            raise AttributeError(attr)

        field_map = self.__dict__['field_map']
        anon_map = self.__dict__['anon_map']

        if field_map.has_key(attr):
            index = field_map[attr]
            return self.instantiate(index)
        elif anon_map.has_key(attr):
            mapping = anon_map[attr]

            if not field_map.has_key(mapping):
                raise AttributeError(mapping)
            
            index = field_map[mapping]
            return getattr(self.instantiate(index), attr)
        elif self.__dict__.has_key(attr):
            return self.__dict__[attr]
        else:
            raise AttributeError(attr)

    @classmethod
    def static_bitspan(cls):
        return sum(map(lambda x: x[1].bitspan(), cls.FIELDS))

    @classmethod
    def simple(cls, declarations):
        new_mapping_declaration = list()

        if not getattr(declarations, '__iter__', None):
            raise MappingError('declarations must be a sequence of names, a base class and optional arguments')

        if len(declarations) == 0:
            raise MappingError('empty declaration list given')

        for declaration_obj in declarations:
            if not len(declaration_obj) == 2 and not len(declaration_obj) == 3:
                raise MappingError('simple declaration item has invalid arguments')

            if not isinstance(declaration_obj[0], basestring) and not declaration_obj[0] == None:
                raise MappingError('first argument of the declaration must be a string or None')

            if not issubclass(declaration_obj[1], memory_region.MemoryRegion):
                raise MappingError('second argument must be a base class implementing MemoryRegion')

            if len(declaration_obj) == 3 and not isinstance(declaration_obj[2], dict):
                raise MappingError('optional third argument must be a dictionary of arguments')
                
            if not len(declaration_obj) == 3:
                args = dict()
            else:
                args = declaration_obj[2]

            new_mapping_declaration.append([declaration_obj[0]
                                            ,declaration.Declaration(base_class=declaration_obj[1]
                                                                     ,args=args)])
        
        class SimplifiedMapping(cls):
            FIELDS = new_mapping_declaration[:]

        return SimplifiedMapping    

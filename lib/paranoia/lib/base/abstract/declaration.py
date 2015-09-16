#!/usr/bin/env python

from .. import paranoia_agent

class DeclarationError(paranoia_agent.ParanoiaError):
    pass

class Declaration:
    BASE_CLASS = None
    ARGS = None

    def __init__(self, **kwargs):
        self.base_class = kwargs.setdefault('base_class', self.BASE_CLASS)

        if self.base_class is None:
            raise DeclarationError('base_class cannot be None')

        self.args = kwargs.setdefault('args', self.ARGS)

        if self.args is None:
            self.args = dict()

        if not isinstance(self.args, dict):
            raise DeclarationError('args must be a dictionary object')

    def instantiate(self, memory_base=None, bitshift=0):
        # make a copy of our argument instantiation
        arg_dict = dict(self.args.items()[:])
        arg_dict['memory_base'] = memory_base
        arg_dict['bitshift'] = bitshift

        return self.base_class(**arg_dict)

    def bitspan(self):
        if not self.args.has_key('bitspan'):
            return self.base_class.static_bitspan()

        return self.args['bitspan']

    def alignment(self):
        if not self.args.has_key('alignment'):
            return self.base_class.static_alignment()

        return self.args['alignment']

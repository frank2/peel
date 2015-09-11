#!/usr/bin/env python

import re

def module_hash(module):
    elements = getattr(module, '__all__', None)

    if not elements:
        elements = dir(module)

    return hash(frozenset(elements))

def module_enum(module, package, local_list):
    enum = __builtins__['list']()
    module_stack = [module]
    module_visited = set()

    while len(module_stack):
        current_module = module_stack.pop(0)
        current_elements = getattr(current_module, '__all__', None)
        current_hash = module_hash(current_module)

        if not current_elements:
            current_elements = dir(current_module)
            
        current_elements = filter(lambda x: not x.startswith('_') and not x.startswith('.'), current_elements)
        current_name = current_module.__name__
        current_name = re.sub('\\.+', '.', current_name)
        short_name = current_name.split('.')[-1]
        
        module_visited.add(current_hash)

        if not current_name.startswith('%s.' % package) and not current_name == '.':
            continue

        __import__(current_name, globals(), local_list)
        local_list[short_name] = current_module
        enum.append(current_name.split('.')[-1])

        for element in current_elements:
            element_object = getattr(current_module, element)

            if type(element_object) == type(module):
                new_module_hash = module_hash(element_object)

                if new_module_hash in module_visited or element_object in module_stack:
                    continue

                module_stack.append(element_object)
            else:
                __import__(current_name, globals(), local_list, [element])
                enum.append(element)
                local_list[element] = element_object

    return enum

def concat_modules(package_name, package_locals, init_list, module_list):
    results = [init_list]

    for module in module_list:
        results.append(module_enum(module, package_name, package_locals))

    results = __builtins__['list'](set(reduce(lambda x,y: x+y, results)))
    results.sort()

    return results

from . import base
from . import types
from . import converters

__all__ = concat_modules(__name__
                         ,locals()
                         ,['.', 'module_enum', 'module_hash', 'concat_modules']
                         ,[base
                           ,types
                           ,converters])

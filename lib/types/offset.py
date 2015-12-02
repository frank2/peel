#!/usr/bin/env python

from paranoia.base.pointer import Pointer

class OffsetError(Exception):
    pass

class Offset(Pointer):
    def memory_value(self):
        root_parent = self.root_parent()
        offset_value = self.get_value()

        return root_parent.memory_base + offset_value

    def to_rva(self):
        root_parent = self.root_parent()
        offset_value = self.get_value()

        # get the section table
        section_table = root_parent.get_section_table()
        
        # if the offset value is less than the start of the first section
        #     just convert it
        offset_base = int(section_table[0].PointerToRawData)

        if offset_value < offset_base:
            rva_value = offset_value
            
        # find the section it's in
        #     if it's not found, raise an error
        else:
            target_section = None
            
            for section in section_table:
                offset_base = int(section.PointerToRawData)
                offset_end = offset_base + int(section.SizeOfRawData)

                if offset_value >= offset_base and offset_value < offset_end:
                    target_section = section
                    break

            if target_section is None:
                raise OffsetError('offset not found in section table')

            virtual_base = int(target_section.VirtualAddress)
                
            # rva = rva_base + (offset - offset_base)
            rva_value = virtual_base + (offset_value - offset_base)

        return root_parent.image.rva(rva_value)
            
class Offset32(Offset):
    BITSPAN = 32

class Offset64(Offset):
    BITSPAN = 64

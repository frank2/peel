#!/usr/bin/env python

from peel.image import Image

def main():
    calc = Image(filename='calc.exe')
    print hex(calc.raw.get_dos_headers().e_lfanew.get_value())
    print hex(calc.raw.get_nt_headers().Signature.get_value())
    print str(calc.raw.get_section_table()[0].Name)
    
if __name__ == '__main__':
    main()

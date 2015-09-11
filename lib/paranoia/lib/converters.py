#!/usr/bin/env python

def aligned(base, alignment):
    return base % alignment == 0

def alignment_delta(base, alignment):
    return (alignment - (base % alignment)) * int(not aligned(base, alignment))

def align(base, alignment):
    return base + alignment_delta(base, alignment)

def bitlist_to_bytelist(bitlist):
    bitlist = bitlist[::-1]
    bytelist = list()
    byte_value = 0
    
    for i in xrange(len(bitlist)):
        if i % 8 == 0 and not i == 0:
            byte_value = 0

        byte_value |= bitlist[i] << (i % 8)

        # this is the last bit for the byte
        if (i+1) % 8 == 0:
            bytelist.append(byte_value)

    # that's all for the bits, add the last byte value found
    if not len(bitlist) % 8 == 0:
        bytelist.append(byte_value)

    # reverse the bytelist to match the original direction of the bits
    return bytelist[::-1]

def bytelist_to_bitlist(bytelist):
    return map(int, ''.join(map('{0:08b}'.format, bytelist)))

def bitlist_to_numeric(bitlist):
    bitlist = bitlist[::-1]

    byte_value = 0

    for i in xrange(len(bitlist)):
        byte_value |= bitlist[i] << i

    return byte_value

def numeric_to_bitlist(numeric):
    bitlist = list()

    while numeric > 0:
        bitlist.append(numeric & 1)
        numeric >>= 1

    return bitlist[::-1]

#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys

def ROR(data, shift, size=32):
    shift %= size
    body = data >> shift
    remains = (data << (size - shift)) - (body << size)
    return (body + remains)

if len(sys.argv) != 2:
    print("Enter  argument: string")
    sys.exit(0)

word = sys.argv[1]
result = 0

for i in word:
    result = ROR(result, 13)
    result += ord(i)

print(hex(result))

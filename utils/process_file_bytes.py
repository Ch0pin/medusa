#!/usr/bin/env python3
import sys


file1_b = bytearray(open(sys.argv[1], 'rb').read())


# Set the length to be the smaller one
offset = 9128
key = 180
size = len(file1_b) 

print("size: {}".format(size))

xord_byte_array = bytearray(size) 

for i in range(size):
	xord_byte_array[i] = file1_b[i] ^ key

final_byte_array = bytearray(size-9128)
# XOR between the files
for i in range(offset,size):
	final_byte_array[i-offset] = xord_byte_array[i]

# Write the XORd bytes to the output file	
open(sys.argv[2], 'wb').write(final_byte_array)
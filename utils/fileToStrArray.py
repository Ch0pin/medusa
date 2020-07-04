#!/usr/bin/env python3

import sys

if len(sys.argv) < 2:
    print('I: Converts a file with lines of strings to java script string array')
    print('I: Usage: {} [file]'.format(sys.argv[0]))
else:
    try:
        with open(sys.argv[1],'r') as f:
            lines = f.read()
        array = '['

        for line in lines.split('\n'):
            array +='"' + line + '"' + ','
        array1 = array[:-1]+']'
        print(array1)
    except Exception as e:
        print(e)



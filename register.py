#!/usr/bin/env python

# This is only for creating releases.
# pip install pypandoc
# brew install pandoc
import pypandoc
import os

output = pypandoc.convert_file('README.md', 'rst')
f = open('README.rst','w+')
f.write(output)
f.close()

#os.system("setup.py register")
#os.remove('README.rst')
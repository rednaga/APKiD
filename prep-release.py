#!/usr/bin/env python
import fnmatch
import os
from codecs import open

import pypandoc
import yara

rules_dir = 'apkid/rules/'
compiled_rules_path = os.path.join(rules_dir, 'rules.yarc')

print("[*] Converting Markdown README to reStructuredText")
rst = pypandoc.convert_file('README.md', 'rst')
with open('README.rst', 'w+', encoding='utf-8') as f:
    f.write(rst)
print("[*] Finished converting to README.rst ({} bytes)").format(len(rst))

yara_files = {}
for root, dirnames, filenames in os.walk(rules_dir):
    for filename in fnmatch.filter(filenames, '*.yara'):
        path = os.path.join(root, filename)
        yara_files[path] = path

print("[*] Compiling {} Yara rule files").format(len(yara_files))
rules = yara.compile(filepaths=yara_files)
rules.save(compiled_rules_path)

count = 0
for _ in rules:
    count += 1
print("[*] Saved {} rules to {}").format(count, compiled_rules_path)

# print("[*] Registering ...")
# os.system("python setup.py register")

# print "[*] Cleaning up ..."
# os.remove('README.rst')

print "[*] Done."

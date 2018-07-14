#!/usr/bin/env python
"""
 Copyright (C) 2018  RedNaga. https://rednaga.io
 All rights reserved. Contact: rednaga@protonmail.com


 This file is part of APKiD


 Commercial License Usage
 ------------------------
 Licensees holding valid commercial APKiD licenses may use this file
 in accordance with the commercial license agreement provided with the
 Software or, alternatively, in accordance with the terms contained in
 a written agreement between you and RedNaga.


 GNU General Public License Usage
 --------------------------------
 Alternatively, this file may be used under the terms of the GNU General
 Public License version 3.0 as published by the Free Software Foundation
 and appearing in the file LICENSE.GPL included in the packaging of this
 file. Please visit http://www.gnu.org/copyleft/gpl.html and review the
 information to ensure the GNU General Public License version 3.0
 requirements will be met.
"""

import os
import sys
from codecs import open

from apkid import rules


def convert_readme():
    print("[*] Converting Markdown README to reStructuredText")
    import pypandoc
    rst = pypandoc.convert_file('README.md', 'rst')
    with open('README.rst', 'w+', encoding='utf-8') as f:
        f.write(rst)
    print("[*] Finished converting to README.rst ({} bytes)".format(len(rst)))


if __name__ == '__main__':
    print("[*] Compiling Yara files")
    rulez = rules.compile()
    rules_count, rules_path = rules.save(rulez)
    print("[*] Saved {} rules to {}".format(rules_count, rules_path))

    tag_counts = {}
    for rule in rules.load():
        for t in rule.tags:
            if t not in tag_counts:
                tag_counts[t] = 1
            else:
                tag_counts[t] += 1
    print("[*] Rule tag counts:")
    for tag in sorted(tag_counts.keys()):
        count = tag_counts[tag]
        print(" |-> {}: {}".format(tag, count))

    if len(sys.argv) > 1:
        if sys.argv[1] == 'register':
            print("[*] Registering ...")
            os.system("python setup.py register")
        if sys.argv[1] == 'readme':
            convert_readme()

    print("[*] Finished prepping.")

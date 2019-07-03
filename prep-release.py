#!/usr/bin/env python
"""
 Copyright (C) 2019  RedNaga. https://rednaga.io
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
from typing import Dict, Set

from apkid.output import colorize_tag
from apkid.rules import RulesManager


def convert_readme():
    print("[*] Converting Markdown README to reStructuredText")
    import pypandoc
    rst = pypandoc.convert_file('README.md', 'rst')
    with open('README.rst', 'w+', encoding='utf-8') as f:
        f.write(rst)
    print(f"[*] Finished converting to README.rst ({len(rst)} bytes)")


if __name__ == '__main__':
    print("[*] Compiling Yara files")
    rules_manager = RulesManager()
    rules = rules_manager.compile()
    rules_count = rules_manager.save()
    print(f"[*] Saved {rules_count} rules to {rules_manager.rules_path}")
    print(f"[*] Rules hash: {rules_manager.hash}")

    tag_to_identifiers: Dict[str, Set[str]] = {}
    for rule in rules:
        for t in rule.tags:
            if t not in tag_to_identifiers:
                tag_to_identifiers[t] = set()
            tag_to_identifiers[t].add(rule.identifier)
    tag_counts = dict([(k, len(v)) for k, v in tag_to_identifiers.items()])
    print("[*] Rule tag counts:")
    for tag in sorted(tag_counts.keys()):
        count = tag_counts[tag]
        if sys.stdout.isatty():
            print(f" |-> {colorize_tag(tag)}: {count}")
        else:
            print(f" |-> {tag}: {count}")

    if len(sys.argv) > 1:
        if sys.argv[1] == 'register':
            print("[*] Registering ...")
            os.system('python setup.py register')
        if sys.argv[1] == 'readme':
            convert_readme()

    print("[*] Finished preparing APKiD for release.")

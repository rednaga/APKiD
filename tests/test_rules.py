"""
 Copyright (C) 2021  RedNaga. https://rednaga.io
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

import warnings


def test_rules_compile(rules_manager):
    rules = rules_manager.compile()
    assert rules


def test_lint_rules(rules_manager):
    for r in rules_manager.compile():
        if len(r.tags) == 0:
            warnings.warn(f"rule has no tags: {r.identifier}", stacklevel=0)

        if 'description' not in r.meta:
            warnings.warn(f"rule has no description: {r.identifier}", stacklevel=0)

        if ('packer' in r.tags or 'protector' in r.tags or 'obfuscator' in r.tags) \
                and 'sample' not in r.meta:
            warnings.warn(f"rule has no reference sample: {r.identifier}", stacklevel=0)

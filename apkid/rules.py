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

import hashlib
import os

import yara

RULES_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'rules')
RULES_PATH = os.path.join(RULES_DIR, 'rules.yarc')
RULES_EXT = '.yara'


def collect_yara_files():
    files = {}
    for root, dirnames, filenames in os.walk(RULES_DIR):
        for filename in filenames:
            if not filename.lower().endswith(RULES_EXT):
                continue
            path = os.path.join(root, filename)
            files[path] = path
    return files


def compile():
    yara_files = collect_yara_files()
    rules = yara.compile(filepaths=yara_files)
    rules.save(RULES_PATH)

    rules_count = sum(1 for _ in rules)
    return rules_count


def sha256():
    hashlib.sha256(open(RULES_PATH, 'rb').read()).hexdigest()


def load():
    return yara.load(RULES_PATH)


def match(file_path, timeout):
    yara_rules = load()
    matches = yara_rules.match(file_path, timeout=timeout)
    return build_match_dict(matches)


def build_match_dict(matches):
    results = {}
    for match in matches:
        tags = ', '.join(sorted(match.tags))
        value = match.meta.get('description', match)
        if tags in results:
            if value not in results[tags]:
                results[tags].append(value)
        else:
            results[tags] = [value]
    return results

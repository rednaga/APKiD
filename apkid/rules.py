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
RULES = None


def load():
    global RULES
    if not RULES:
        RULES = yara.load(RULES_PATH)
    return RULES


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
    return yara.compile(filepaths=yara_files)


def save(rules):
    rules.save(RULES_PATH)
    rules_count = sum(1 for _ in rules)
    return rules_count, RULES_PATH


def sha256():
    hashlib.sha256(open(RULES_PATH, 'rb').read()).hexdigest()


def match(file_path, timeout):
    load()
    matches = RULES.match(file_path, timeout=timeout)
    return build_match_dict(matches)


def build_match_dict(matches):
    results = {}
    for m in matches:
        tags = ', '.join(sorted(m.tags))
        description = m.meta.get('description', m)
        if tags in results:
            if description not in results[tags]:
                results[tags].append(description)
        else:
            results[tags] = [description]
    return results

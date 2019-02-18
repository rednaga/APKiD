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

import hashlib
import os
import yara
from typing import Dict


class RulesManager(object):
    def __init__(self, rules_dir=None, rules_ext='.yara'):
        if not rules_dir:
            rules_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'rules')
        self.rules_dir = rules_dir
        self.rules_path = os.path.join(self.rules_dir, 'rules.yarc')
        self.rules_ext = rules_ext
        self.rules = None

    def load(self) -> yara.Rules:
        self.rules = yara.load(self.rules_path)
        return self.rules

    def _collect_yara_files(self) -> Dict[str, str]:
        files = {}
        for root, dirnames, filenames in os.walk(self.rules_dir):
            for filename in filenames:
                if not filename.lower().endswith(self.rules_ext):
                    continue
                path = os.path.join(root, filename)
                files[path] = path
        return files

    def compile(self) -> yara.Rules:
        yara_files = self._collect_yara_files()
        self.rules = yara.compile(filepaths=yara_files)
        return self.rules

    def save(self) -> int:
        self.rules.save(self.rules_path)
        rules_count = sum(1 for _ in self.rules)
        return rules_count

    def hash(self) -> str:
        with open(self.rules_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()

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
from typing import Dict
from typing import Optional

import yara


class RulesManager(object):
    def __init__(self, rules_dir=None, rules_ext='.yara'):
        if not rules_dir:
            rules_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'rules')
        self.rules_dir: str = rules_dir
        self.rules_path: str = os.path.join(self.rules_dir, 'rules.yarc')
        self.rules_ext: str = rules_ext
        self.rules: Optional[yara.Rules] = None
        self.rules_hash: Optional[str] = None

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
        rules_count = len(set([r.identifier for r in self.rules]))
        return rules_count

    @property
    def hash(self) -> str:
        if not self.rules_hash:
            h = hashlib.sha256()
            for file_path in self._collect_yara_files():
                with open(file_path, 'rb') as f:
                    h.update(f.read())
            self.rules_hash = h.hexdigest()
        return self.rules_hash

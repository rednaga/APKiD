"""
 Copyright (C) 2023  RedNaga. https://rednaga.io
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
import re
from typing import Dict
from typing import Optional

import yara_x as yara


class RulesManager(object):
    def __init__(self, rules_dir=None, rules_ext='.yara', include_trackers=False):
        if not rules_dir:
            rules_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'rules')
        self.rules_dir: str = rules_dir
        self.include_trackers: bool = include_trackers
        self.rules_path: str = os.path.join(self.rules_dir, f'{"trackers.yarc" if self.include_trackers else "rules.yarc"}')
        self.rules_ext: str = rules_ext
        self.rules: Optional[yara.Rules] = None
        self.rules_hash: Optional[str] = None

    def load(self) -> yara.Rules:
        with open(self.rules_path, 'rb') as f:
            self.rules = yara.Rules.deserialize_from(f)
        return self.rules

    def _collect_yara_files(self) -> Dict[str, str]:
        files = {}
        for root, dirnames, filenames in os.walk(self.rules_dir):
            for filename in filenames:
                if not filename.lower().endswith(self.rules_ext):
                    continue
                if not self.include_trackers and filename.lower() == 'trackers.yara':
                    continue
                path = os.path.join(root, filename)
                files[path] = path
        return files

    @staticmethod
    def _strip_includes(source: str) -> str:
        return re.sub(r'^\s*include\s+"[^"]+"\s*\n?', '', source, flags=re.M)

    def compile(self) -> yara.Rules:
        yara_files = self._collect_yara_files()
        # Compile common.yara first so is_* helpers are defined before use,
        # then everything else deterministically sorted for stable builds.
        def _sort_key(p: str):
            return (0 if os.path.basename(p) == 'common.yara' else 1, p)
        sorted_paths = sorted(yara_files.keys(), key=_sort_key)
        # relaxed_re_syntax allows legacy yara regexes that yara-x strict
        # mode would reject (e.g. unescaped chars, invalid escapes treated
        # as literals in yara). APKiD rules were written for yara.
        compiler = yara.Compiler(relaxed_re_syntax=True)
        for path in sorted_paths:
            with open(path, 'r', encoding='utf-8') as f:
                src = f.read()
            src = self._strip_includes(src)
            compiler.add_source(src, origin=path)
        self.rules = compiler.build()
        return self.rules

    def save(self) -> int:
        assert self.rules is not None, "no rules to save, call compile() or load() first"
        with open(self.rules_path, 'wb') as f:
            self.rules.serialize_into(f)
        rules_count = len(set([r.identifier for r in self.rules]))
        return rules_count

    @property
    def hash(self) -> str:
        if not self.rules_hash:
            h = hashlib.sha256()
            for file_path in sorted(self._collect_yara_files()):
                with open(file_path, 'rb') as f:
                    h.update(f.read())
            self.rules_hash = h.hexdigest()
        return self.rules_hash

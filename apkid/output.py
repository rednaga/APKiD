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

import json
import os
import sys
from typing import Dict, List, Union

import yara

from .rules import RulesManager

prt_red = lambda s: f"\033[91m{s}\033[00m"
prt_green = lambda s: f"\033[92m{s}\033[00m"
prt_yellow = lambda s: f"\033[93m{s}\033[00m"
prt_light_purple = lambda s: f"\033[94m{s}\033[00m"
prt_purple = lambda s: f"\033[95m{s}\033[00m"
prt_cyan = lambda s: f"\033[36m{s}\033[00m"
prt_light_cyan = lambda s: f"\033[96m{s}\033[00m"
prt_light_gray = lambda s: f"\033[97m{s}\033[00m"
prt_orange = lambda s: f"\033[33m{s}\033[00m"
prt_pink = lambda s: f"\033[35m{s}\033[00m"


def colorize_tag(tag) -> str:
    if tag == 'compiler':
        return prt_cyan(tag)
    elif tag == 'manipulator':
        return prt_light_cyan(tag)
    elif tag == 'abnormal':
        return prt_light_gray(tag)
    elif tag in ['anti_vm', 'anti_disassembly', 'anti_debug']:
        return prt_purple(tag)
    elif tag in ['packer', 'protector']:
        return prt_red(tag)
    elif tag == 'obfuscator':
        return prt_yellow(tag)
    elif tag == 'dropper':
        return prt_green(tag)
    elif tag == 'embedded':
        return prt_light_purple(tag)
    elif tag == 'file_type':
        return prt_orange(tag)
    elif tag == 'internal':
        return prt_pink(tag)
    else:
        return tag


class OutputFormatter(object):
    def __init__(self, json_output: bool, output_dir: Union[str, None], rules_manager: RulesManager, include_types: bool):
        from apkid import __version__
        self.output_dir = output_dir
        self.json = json_output or output_dir
        self.version = __version__
        self.rules_hash = rules_manager.hash
        self.include_types = include_types

    def write(self, results: Dict[str, List[yara.Match]]) -> None:
        """
         Example yara.Match:
        {
          'tags': ['foo', 'bar'],
          'matches': True,
          'namespace': 'default',
          'rule': 'my_rule',
          'meta': {},
          'strings': [(81L, '$a', 'abc'), (141L, '$b', 'def')]
        }
        """

        if self.output_dir:
            # Result keys are file paths. Shortest key is base file in the case of archives.
            base_file = sorted(results.keys(), key=lambda k: len(k))[0]
            out_file = os.path.join(self.output_dir, *base_file.split(os.path.sep))
            out_path = os.path.dirname(out_file)
            if not os.path.exists(out_path):
                os.makedirs(out_path)
            output = self.build_json_output(results)
            with open(out_file, 'w') as f:
                f.write(json.dumps(output))
        else:
            if self.json:
                self._print_json(results)
            else:
                self._print_console(results)

    def build_json_output(self, results: Dict[str, List[yara.Match]]):
        output = {
            'apkid_version': self.version,
            'rules_sha256': self.rules_hash,
            'files': [],
        }
        for filename, matches in results.items():
            match_results = self._build_match_results(matches)
            if len(match_results) == 0:
                continue
            result = {
                'filename': filename,
                'matches': match_results,
            }
            output['files'].append(result)
        return output

    def _print_json(self, results: Dict[str, List[yara.Match]]) -> None:
        output = self.build_json_output(results)
        print(json.dumps(output, sort_keys=True))

    def _print_console(self, results: Dict[str, List[yara.Match]]) -> None:
        for key, raw_matches in results.items():
            match_results = self._build_match_results(raw_matches)
            if len(match_results) == 0:
                continue
            print(f"[*] {key}")
            for tags in sorted(match_results):
                descriptions = ', '.join(sorted(match_results[tags]))
                if sys.stdout.isatty():
                    tags_str = OutputFormatter._colorize_tags(tags)
                else:
                    tags_str = tags
                print(f" |-> {tags_str} : {descriptions}")

    def _build_match_results(self, matches) -> Dict[str, List[str]]:
        results: Dict[str, List[str]] = {}
        for m in matches:
            if 'file_type' in m.tags and not self.include_types:
                continue
            tags = ', '.join(sorted(m.tags))
            description = m.meta.get('description', m)
            if tags in results:
                if description not in results[tags]:
                    results[tags].append(description)
            else:
                results[tags] = [description]
        return results

    @staticmethod
    def _colorize_tags(tags) -> str:
        colored_tags = []
        for tag in tags.split(', '):
            colored_tag = colorize_tag(tag)
            colored_tags.append(colored_tag)
        return ', '.join(colored_tags)

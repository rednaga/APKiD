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
import yara
from typing import Dict, List, Union

from .rules import RulesManager

prt_red = lambda s: "\033[91m{}\033[00m".format(s)
prt_green = lambda s: "\033[92m{}\033[00m".format(s)
prt_yellow = lambda s: "\033[93m{}\033[00m".format(s)
prt_light_purple = lambda s: "\033[94m{}\033[00m".format(s)
prt_purple = lambda s: "\033[95m{}\033[00m".format(s)
prt_cyan = lambda s: "\033[36m{}\033[00m".format(s)
prt_light_cyan = lambda s: "\033[96m{}\033[00m".format(s)
prt_light_gray = lambda s: "\033[97m{}\033[00m".format(s)
prt_orange = lambda s: "\033[33m{}\033[00m".format(s)
prt_pink = lambda s: "'\033[95m'{}\033[00m".format(s)


def colorize_tag(tag):
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
    else:
        return tag


class OutputFormatter(object):
    def __init__(self, json_output: bool, output_dir: Union[str, None], rules_manager: RulesManager):
        from apkid import __version__
        self.output_dir = output_dir
        self.json = json_output or output_dir
        self.version = __version__
        self.rules_hash = rules_manager.hash()

    def write(self, results: Dict[str, List[yara.Match]]):
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
            if not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)
            output = self._build_json_output(results)
            out_file = sorted(results.keys(), key=lambda k: len(k))[0]
            out_path = os.path.join(self.output_dir, out_file)
            with open(out_path, 'w') as f:
                f.write(output)
        else:
            if self.json:
                self._print_json(results)
            else:
                self._print_console(results)

    def _print_json(self, results: Dict[str, List[yara.Match]]):
        output = self._build_json_output(results)
        print(json.dumps(output, sort_keys=True))

    def _build_json_output(self, results: Dict[str, List[yara.Match]]):
        output = {
            'apkid_version': self.version,
            'rules_sha256': self.rules_hash,
            'files': [],
        }
        for filename, matches in results.items():
            result = {
                'filename': filename,
                'matches': self._build_match_dict(matches),
            }
            output['files'].append(result)
        return output

    def _print_console(self, results: Dict[str, List[yara.Match]]):
        for key, raw_matches in results.items():
            matches = self._build_match_dict(raw_matches)
            print(f"[*] {key}")
            for tags in sorted(matches):
                descriptions = ', '.join(sorted(matches[tags]))
                if sys.stdout.isatty():
                    tags_str = self._colorize_tags(tags)
                else:
                    tags_str = tags
                print(f" |-> {tags_str} : {descriptions}")

    def _build_match_dict(self, matches):
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

    def _colorize_tags(self, tags):
        colored_tags = []
        for tag in tags.split(', '):
            colored_tag = colorize_tag(tag)
            colored_tags.append(colored_tag)
        colored_tags = ', '.join(colored_tags)
        return colored_tags

# def get_json_output(results):
#     from . import __version__, rules
#     output = {
#         'apkid_version': __version__,
#         'rules_sha256': rules.sha256(),
#         'files': [],
#     }
#     for filename in results:
#         result = {
#             'filename': filename,
#             'results': results[filename],
#         }
#         output['files'].append(result)
#     return output
#
#
# def build_match_dict(matches):
#     results = {}
#     for m in matches:
#         tags = ', '.join(sorted(m.tags))
#         description = m.meta.get('description', m)
#         if tags in results:
#             if description not in results[tags]:
#                 results[tags].append(description)
#         else:
#             results[tags] = [description]
#     return results
#
#
# def print_json_results(results):
#     output = get_json_output(results)
#     print(json.dumps(output))

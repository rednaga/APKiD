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

import json
import sys


def print_matches(key_path, matches):
    """
     example matches dict
    [{
      'tags': ['foo', 'bar'],
      'matches': True,
      'namespace': 'default',
      'rule': 'my_rule',
      'meta': {},
      'strings': [(81L, '$a', 'abc'), (141L, '$b', 'def')]
    }]
    """
    print("[*] {}".format(key_path))
    for tags in sorted(matches):
        descriptions = ', '.join(sorted(matches[tags]))
        if sys.stdout.isatty():
            tags_str = colorize_tags(tags)
        else:
            tags_str = tags
        print(" |-> {} : {}".format(tags_str, descriptions))


def colorize_tags(tags):
    colored_tags = []
    for tag in tags.split(', '):
        if tag == 'compiler':
            colored_tag = prt_cyan(tag)
        elif tag == 'manipulator':
            colored_tag = prt_lightCyan(tag)
        elif tag == 'abnormal':
            colored_tag = prt_lightGray(tag)
        elif tag in ['anti_vm', 'anti_disassembly', 'anti_debug']:
            colored_tag = prt_purple(tag)
        elif tag in ['packer', 'protector']:
            colored_tag = prt_red(tag)
        elif tag == 'obfuscator':
            colored_tag = prt_yellow(tag)
        else:
            colored_tag = tag
        colored_tags.append(colored_tag)
    colored_tags = ', '.join(colored_tags)
    return colored_tags


def get_json_output(results):
    from . import __version__, rules
    output = {
        'apkid_version': __version__,
        'rules_sha256': rules.sha256(),
        'files': [],
    }
    for filename in results:
        result = {
            'filename': filename,
            'results': results[filename],
        }
        output['files'].append(result)
    return output


def print_json_results(results):
    output = get_json_output(results)
    print(json.dumps(output))


prt_red = lambda s: "\033[91m{}\033[00m".format(s)
prt_green = lambda s: "\033[92m{}\033[00m".format(s)
prt_yellow = lambda s: "\033[93m{}\033[00m".format(s)
prt_lightPurple = lambda s: "\033[94m{}\033[00m".format(s)
prt_purple = lambda s: "\033[95m{}\033[00m".format(s)
prt_cyan = lambda s: "\033[36m{}\033[00m".format(s)
prt_lightCyan = lambda s: "\033[96m{}\033[00m".format(s)
prt_lightGray = lambda s: "\033[97m{}\033[00m".format(s)
prt_orange = lambda s: "\033[33m{}\033[00m".format(s)
prt_pink = lambda s: "'\033[95m'{}\033[00m".format(s)

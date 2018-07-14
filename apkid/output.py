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
        values = ', '.join(sorted(matches[tags]))
        print(" |-> {} : {}".format(tags, values))


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

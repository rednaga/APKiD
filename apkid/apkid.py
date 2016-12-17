'''
 Copyright (C) 2016  RedNaga. http://rednaga.io
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
'''

import json
import logging
import os
import shutil
import tempfile
import traceback
import zipfile
import sys

import yara

LOGGING_LEVEL = logging.INFO
logging.basicConfig(level=LOGGING_LEVEL,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    stream=sys.stdout)

# Magic doesn't need to be perfect. Just used to filter likely scannable files.
ZIP_MAGIC = ['PK\x03\x04', 'PK\x05\x06', 'PK\x07\x08']
DEX_MAGIC = ['dex\n', 'dey\n']
ELF_MAGIC = ['\x7fELF']
AXML_MAGIC = []  # TODO


def get_file_type(file_path):
    # Don't scan links
    if not os.path.isfile(file_path):
        return 'invalid'
    with open(file_path, 'rb') as f:
        magic = f.read(4)
    if magic in ZIP_MAGIC:
        return 'zip'
    elif magic in DEX_MAGIC:
        return 'dex'
    elif magic in ELF_MAGIC:
        return 'elf'
    elif magic in AXML_MAGIC:
        return 'axml'
    return 'invalid'


def collect_files(input):
    files = []
    if os.path.isfile(input):
        files.append(input)
    else:
        for root, dirnames, filenames in os.walk(input):
            for filename in filenames:
                filepath = os.path.join(root, filename)
                files.append(filepath)
    files.sort()
    types_and_paths = map(lambda f: (get_file_type(f), f), files)
    types_and_paths = filter(lambda e: e[0] != 'invalid', types_and_paths)
    files = {}
    for file_type, file_path in types_and_paths:
        if file_type in files:
            files[file_type].append(file_path)
        else:
            files[file_type] = [file_path]
    return files


def get_rules():
    rules_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'rules/rules.yarc')
    return yara.load(rules_path)


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


def print_matches(key_path, match_dict):
    ''' example matches dict
    [{
      'tags': ['foo', 'bar'],
      'matches': True,
      'namespace': 'default',
      'rule': 'my_rule',
      'meta': {},
      'strings': [(81L, '$a', 'abc'), (141L, '$b', 'def')]
    }]
    '''
    print("[*] {}".format(key_path))
    for tags in sorted(match_dict):
        values = ', '.join(sorted(match_dict[tags]))
        print(" |-> {} : {}".format(tags, values))


def is_target_member(name):
    if name.startswith('classes') or name.startswith('AndroidManifest.xml') or name.startswith(
            'lib/'):
        return True
    return False


def do_yara(file_path, rules, timeout):
    matches = rules.match(file_path, timeout=timeout)
    return build_match_dict(matches)


def scan_apk(apk_path, rules, timeout, output_json):
    td = None
    results = {}
    try:
        zf = zipfile.ZipFile(apk_path, 'r')
        target_members = filter(lambda n: is_target_member(n), zf.namelist())
        td = tempfile.mkdtemp()
        zf.extractall(td, members=target_members)
        zf.close()
        for file_type, file_paths in collect_files(td).iteritems():
            for file_path in file_paths:
                entry_name = file_path.replace('{}/'.format(td), '')
                key_path = '{}!{}'.format(apk_path, entry_name)
                match_dict = do_yara(file_path, rules, timeout)
                if len(match_dict) > 0:
                    results[key_path] = match_dict
                    if not output_json:
                        print_matches(key_path, match_dict)
    except Exception as e:
        tb = traceback.format_exc()
        logging.error("error extracting {}: {}\n{}".format(apk_path, e, tb))

    if td: shutil.rmtree(td)
    return results


def print_json_results(results):
    import pkg_resources
    output = {
        'apkid_version': pkg_resources.get_distribution('apkid').version,
        'files': [],
    }
    for filename in results:
        result = {
            'filename': filename,
            'results': results[filename],
        }
        output['files'].append(result)
    print(json.dumps(output))


def scan(input, timeout, output_json):
    rules = get_rules()
    results = {}
    for file_type, file_paths in collect_files(input).iteritems():
        for file_path in file_paths:
            try:
                match_dict = do_yara(file_path, rules, timeout)
                if len(match_dict) > 0:
                    results[file_path] = match_dict
                    if not output_json:
                        print_matches(file_path, match_dict)

                if 'zip' == file_type:
                    apk_matches = scan_apk(file_path, rules, timeout, output_json)
                    results.update(apk_matches)
            except yara.Error as e:
                logging.error("error scanning: {}".format(e))
    if output_json:
        print_json_results(results)

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
import logging
import os
import shutil
import sys
import tempfile
import traceback
import zipfile

import yara

from . import rules, output

LOGGING_LEVEL = logging.INFO
logging.basicConfig(level=LOGGING_LEVEL,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    stream=sys.stdout)

FILE_MAGICS = {
    'zip': [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'],
    'dex': [b'dex\n', b'dey\n'],
    'elf': [b'\x7fELF'],
    'axml': [],
}


def scan(input, timeout, use_json, output_dir, quiet):
    all_results = {}
    out_file = None
    for file_type, file_path in collect_files(input):
        file_results = {}

        if output_dir:
            filename = os.path.basename(file_path)
            out_file = os.path.join(output_dir, '{}_apkid.json'.format(filename))
            if os.path.exists(out_file):
                if not quiet:
                    print("Match result {} already exists; skipping {}".format(out_file, file_path))
                continue

        if output_dir and not quiet:
            print("Processing: {}".format(file_path))

        try:
            matches = rules.match(file_path, timeout)

            if len(matches) > 0:
                file_results[file_path] = matches

            if 'zip' == file_type:
                apk_matches = scan_apk(file_path, timeout, use_json)
                file_results.update(apk_matches)

            if output_dir:
                with open(out_file, 'w') as f:
                    f.write(json.dumps(file_results))
            else:
                all_results.update(file_results)

            if not use_json:
                output.print_matches(file_path, matches)

            if output_dir and not quiet:
                print("Finished: {}".format(file_path))
        except yara.Error as e:
            tb = traceback.format_exc()
            logging.error("error scanning {}: {}\n{}".format(file_path, e, tb))
            if output_dir and not os.path.exists(out_file):
                with open(out_file, 'w') as f:
                    f.write(json.dumps({'error': e, 'trace': tb}))

    if not output_dir and use_json:
        print(json.dumps(all_results))


def get_file_type(file_path):
    if not os.path.isfile(file_path):
        return 'invalid'

    with open(file_path, 'rb') as f:
        magic = f.read(4)

    for file_type, magics in FILE_MAGICS.items():
        if magic in magics:
            return file_type
    return 'invalid'


def collect_files(input):
    if os.path.isfile(input):
        file_type = get_file_type(input)
        if file_type != 'invalid':
            yield (file_type, input)
    else:
        for root, _, filenames in os.walk(input):
            for filename in filenames:
                filepath = os.path.join(root, filename)
                file_type = get_file_type(filepath)
                if file_type != 'invalid':
                    yield (file_type, filepath)


def is_likely_supported_file(name):
    if name.startswith('classes') \
            or name.startswith('AndroidManifest.xml') \
            or name.startswith('lib/') \
            or name.endswith('.so') \
            or name.endswith('.dex') \
            or name.endswith('.apk'):
        return True
    return False


def scan_apk(apk_path, timeout, output_json):
    td = None
    results = {}
    try:
        zf = zipfile.ZipFile(apk_path, 'r')
        target_members = filter(lambda n: is_likely_supported_file(n), zf.namelist())
        td = tempfile.mkdtemp()
        zf.extractall(td, members=target_members)
        zf.close()
        for file_type, file_path in collect_files(td):
            entry_name = file_path.replace('{}/'.format(td), '')
            key_path = '{}!{}'.format(apk_path, entry_name)
            matches = rules.match(file_path, timeout)
            if len(matches) > 0:
                results[key_path] = matches
                if not output_json:
                    output.print_matches(key_path, matches)
    except Exception as e:
        tb = traceback.format_exc()
        logging.error("error extracting {}: {}\n{}".format(apk_path, e, tb))

    if td: shutil.rmtree(td)
    return results

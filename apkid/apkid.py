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
import os
import shutil
import tempfile
import traceback
import yara
import zipfile

ZIP_MAGIC = ['PK\x03\x04', 'PK\x05\x06', 'PK\x07\x08']


class APKiD:
    def __init__(self, input, timeout, output_json):
        self.files = APKiD.collect_files(input)
        self.files.sort()

        rules_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'rules/rules.yarc')
        self.rules = yara.load(rules_path)
        self.timeout = timeout
        self.output_json = output_json

    def scan(self):
        results = {}
        for filename in self.files:
            try:
                matches = self.rules.match(filename, timeout=self.timeout)
                if self.output_json:
                    collected = APKiD.collect_matches(matches)
                    if len(collected) > 0:
                        results[filename] = collected
                else:
                    self.print_matches(filename, matches)

                if not os.path.isfile(filename):
                    continue

                with open(filename, 'rb') as f:
                    magic = f.read(4)
                if magic not in ZIP_MAGIC:
                    continue

                try:
                    zip_ref = zipfile.ZipFile(filename, 'r')
                    td = tempfile.mkdtemp()
                    zip_ref.extractall(td)
                    zip_ref.close()
                    zip_files = APKiD.collect_files(td)

                    for zip_file in zip_files:
                        matches = self.rules.match(zip_file, timeout=self.timeout)
                        key_path = zip_file.replace('%s/' % td, '%s!' % filename)
                        if self.output_json:
                            collected = APKiD.collect_matches(matches)
                            if len(collected) > 0:
                                results[key_path] = collected
                        else:
                            self.print_matches(key_path, matches)
                    shutil.rmtree(td)
                except Exception as e:
                    tb = traceback.format_exc()
                    print "error extracting %s: %s\n%s" % (filename, e, tb)
            except yara.Error as e:
                print "error scanning: %s" % e

        if self.output_json:
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
            print json.dumps(output)

    @staticmethod
    def collect_matches(matches):
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

    def print_matches(self, file, matches):
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
        # TODO: https://pypi.python.org/pypi/colorama
        # Convert to set in case there are weird duplicate matchesd
        if len(matches) == 0:
            return

        results = self.collect_matches(matches)

        print "[*] %s" % file
        for tags in sorted(results):
            print " |-> %s : %s" % (tags, ', '.join(sorted(results[tags])))

    @staticmethod
    def collect_files(input_files):
        if os.path.isfile(input_files):
            return [input_files]
        files = []
        for root, dirnames, filenames in os.walk(input_files):
            for filename in filenames:
                files.append(os.path.join(root, filename))
        return files

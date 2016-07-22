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

import os
import yara
import zipfile
import tempfile
import shutil

ZIP_MAGIC = ['PK\x03\x04', 'PK\x05\x06', 'PK\x07\x08']

class APKiD:
  def __init__(self, input_files, timeout=30):
    self.files = self.collect_files(input_files)
    self.files.sort()
    self.rules = yara.load('apkid/rules/rules.yarc')
    self.timeout = timeout
    # if verbose
    # print sum(1 for _ in self.rules)
    # reload rules because the above breaks the iterator

  def scan(self):
    results = {}
    for file in self.files:
      try:
        matches = self.rules.match(file, timeout=self.timeout)
        self.print_matches(file, matches)

        if not os.path.isfile(file):
          continue

        magic = None
        with open(file, 'rb') as f:
          magic = f.read(4)
        if magic not in ZIP_MAGIC:
          continue

        try:
          zip_ref = zipfile.ZipFile(file, 'r')
          td = tempfile.mkdtemp()
          zip_ref.extractall(td)
          zip_ref.close()
          zip_files = self.collect_files([td])

          for zip_file in zip_files:
            matches = self.rules.match(zip_file, timeout=self.timeout)
            key_path = zip_file.replace('%s/' % td, '%s!' % file)
            self.print_matches(key_path, matches)
          shutil.rmtree(td)
        except Exception as e:
          print "error extracting %s: %s" % (file, e)

      except yara.Error as e:
        print "error scanning: %s" % e

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
    descriptions = list(set([match.meta.get('description', match) for match in matches]))
    if len(descriptions) == 0:
      return

    print "[*] %s" % file
    descriptions.sort()

    for desc in descriptions:
      print " |-> %s" % desc

  def collect_files(self, input_files):
    files = []
    for  input_file in input_files:
      if not os.path.exists(input_file):
        raise Exception("File does not exist: %s" % input_file)
      if os.path.isfile(input_file):
        files.append(input_file)
        continue

    for root, directories, filenames in os.walk(input_file):
      for filename in filenames:
        path = os.path.join(root, filename)
        files.append(path)

    return files
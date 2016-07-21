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

class APKiD:
  def __init__(self, input_files, timeout=30):
    self.files = self.collect_files(input_files)
    self.rules = yara.load('apkid/rules/rules.yarc')
    self.timeout = timeout
    # if verbose
    # print sum(1 for _ in self.rules)
    # reload rules

    print input_files

  def scan(self):
    results = {}
    for file in self.files:
      try:
        print file
        matches = self.rules.match(file, timeout=self.timeout)
        results[file] = matches

# [{
#   'tags': ['foo', 'bar'],
#   'matches': True,
#   'namespace': 'default',
#   'rule': 'my_rule',
#   'meta': {},
#   'strings': [(81L, '$a', 'abc'), (141L, '$b', 'def')]
# }]

# if verbose, print meta data?

      except yara.Error as e:
        print e
      print results

  def scan_stream(fileobj):
    return

  def zip_entries(zip_path):
    # yield each entry in the zipfile
    return

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
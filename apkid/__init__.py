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

import argparse
import yara
import apkid
import pkg_resources


def main():
  parser = argparse.ArgumentParser(description="APKiD - Android Application Identifier")
  parser.add_argument('files', metavar='FILE', type=str, nargs='+',
    help="apk, dex, or dir")
  parser.add_argument('-j', '--json', action='store_true',
    help="output results in JSON",)
  parser.add_argument('-t', '--timeout', type=int, default=30,
    help="Yara scan timeout in seconds")

  args = parser.parse_args()

  aid = apkid.APKiD(args.files, args.timeout, args.json)

  if not args.json:
    version = pkg_resources.get_distribution("apkid").version
    print "[!] APKiD %s :: from RedNaga :: rednaga.io" % version
  aid.scan()

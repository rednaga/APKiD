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

def main():
  parser = argparse.ArgumentParser(description='Android Application Identifier')
  parser.add_argument('files', metavar='FILE', type=str, nargs='+',
                      help='an integer for the accumulator')
  #parser.add_argument('-v', dest='accumulate', action='store_const',
  #                    const=sum, default=max,
  #                    help='sum the integers (default: find the max)')

# timeout
# verbose

  args = parser.parse_args()
  #print args.accumulate(args.integers)
  print args.files

  aid = apkid.APKiD(args.files)
  aid.scan()


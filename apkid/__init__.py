#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
 Copyright (C) 2017  RedNaga. http://rednaga.io
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

__title__ = 'apkid'
__version__ = '1.0.0'
__author__ = 'Caleb Fenton & Tim Strazzere'
__license__ = 'GPL & Commercial'
__copyright__ = 'Copyright (C) 2017 RedNaga'

import argparse

import apkid


def main():
    parser = argparse.ArgumentParser(
        description="APKiD - Android Application Identifier v{}".format(__version__))
    parser.add_argument('input', metavar='FILE', type=str, nargs='*',
                        help="apk, dex, or directory")
    parser.add_argument('-j', '--json', action='store_true',
                        help="output results in JSON format", )
    parser.add_argument('-t', '--timeout', type=int, default=30,
                        help="Yara scan timeout (in seconds)")
    parser.add_argument('-o', '--output-dir', metavar='DIR', type=str,
                        help="write individual JSON results to this directory")
    args = parser.parse_args()

    if not args.json:
        print "[+] APKiD %s :: from RedNaga :: rednaga.io" % __version__

    for input in args.input:
        if args.output_dir:
            apkid.scan_singly(input, args.timeout, args.output_dir)
        else:
            apkid.scan(input, args.timeout, args.json)

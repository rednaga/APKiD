"""
 Copyright (C) 2019  RedNaga. https://rednaga.io
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

import argparse

from apkid.apkid import Scanner, Options
from . import __version__


def get_parser():
    formatter = lambda prog: argparse.ArgumentDefaultsHelpFormatter(prog, max_help_position=50, width=100)

    parser = argparse.ArgumentParser(
        description=f"APKiD - Android Application Identifier v{__version__}",
        formatter_class=formatter
    )
    parser.add_argument('input', metavar='FILE', type=str, nargs='*',
                        help="apk, dex, or directory")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="log debug messages")

    scanning = parser.add_argument_group('scanning')
    scanning.add_argument('-t', '--timeout', type=int, default=30,
                          help="Yara scan timeout (in seconds)")
    scanning.add_argument('-r', '--recursive', action='store_true', default=False,
                          help="recurse into subdirectories")
    scanning.add_argument('--scan-depth', type=int, default=2,
                          help="how deep to go when scanning nested zips")
    scanning.add_argument('--entry-max-scan-size', type=int, default=100 * 1024 * 1024,
                          help="max zip entry size to scan in bytes, 0 = no limit")
    scanning.add_argument('--typing', choices=('magic', 'filename', 'none'), default='magic',
                          help="method to decide which files to scan")

    output = parser.add_argument_group('output')
    output.add_argument('-j', '--json', action='store_true',
                        help="output scan results in JSON format", )
    output.add_argument('-o', '--output-dir', metavar='DIR', default=None,
                        help="write individual results here (implies --json)")
    output.add_argument('--include-types', action='store_true', default=False,
                        help="include file type info for matched files")

    return parser


def build_options(args) -> Options:
    return Options(
        timeout=args.timeout,
        verbose=args.verbose,
        json=args.json,
        output_dir=args.output_dir,
        typing=args.typing,
        entry_max_scan_size=args.entry_max_scan_size,
        scan_depth=args.scan_depth,
        recursive=args.recursive,
        include_types=args.include_types,
    )


def main():
    parser = get_parser()
    args = parser.parse_args()
    options = build_options(args)

    if not options.output.json:
        print(f"[+] APKiD {__version__} :: from RedNaga :: rednaga.io")

    rules = options.rules_manager.load()
    scanner = Scanner(rules, options)

    for input in args.input:
        scanner.scan(input)


if __name__ == '__main__':
    main()

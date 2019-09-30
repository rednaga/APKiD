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

from apkid.apkid import Scanner
from .factories import make_temp_zip, make_temp_file, make_zip


def test_scan_with_dummy_zip(scanner: Scanner):
    zip_entries = {'dummy': b'hello'}
    with make_temp_zip(zip_entries) as tz:
        results = scanner.scan_file(tz.name)

    assert tz.name in results
    assert len(results) == 1
    assert len(results[tz.name]) > 0


def test_scan_with_unscannable_file(scanner: Scanner):
    with make_temp_file(b'hello') as tz:
        results = scanner.scan_file(tz.name)

    assert len(results) == 0


def test_scan_with_zip_with_dex(scanner: Scanner):
    zip_entries = {'classes.dex': b'dex\nnot a real dex!'}
    with make_temp_zip(zip_entries) as tz:
        results = scanner.scan_file(tz.name)

    for key in (tz.name, f'{tz.name}!classes.dex'):
        assert key in results
        assert len(results[key]) > 0


def test_scan_with_nested_zips(scanner: Scanner):
    third_layer = {
        '3.dex': b'dex\n'
    }
    second_layer = {
        '3.zip': make_zip(third_layer).read(),
        '2.dex': b'dex\n',
    }
    first_layer = {
        '2.zip': make_zip(second_layer).read(),
        '1.dex': b'dex\n',
    }
    zero_layer = {
        '1.zip': make_zip(first_layer).read(),
        '0.dex': b'dex\n',
    }

    scanner.options.scan_depth = 2
    with make_temp_zip(zero_layer) as tz:
        results = scanner.scan_file(tz.name)

    for key in (
            tz.name, f'{tz.name}!0.dex', f'{tz.name}!1.zip', f'{tz.name}!1.zip!1.dex', f'{tz.name}!1.zip!2.zip',
            f'{tz.name}!1.zip!2.zip!2.dex', f'{tz.name}!1.zip!2.zip!3.zip'
    ):
        assert key in results
        assert len(results[key]) > 0

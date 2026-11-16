"""
 Copyright (C) 2023  RedNaga. https://rednaga.io
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

import io
import lzma
import zipfile

from apkid.apkid import MIN_DECODER_MEMORY, Scanner
from .factories import make_temp_zip, make_temp_xz_zip, make_temp_file, make_zip


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


def test_scan_with_xz_entry(scanner: Scanner):
    entries = {'classes.dex': b'dex\n' + b'A' * 128}
    with make_temp_xz_zip(entries) as tz:
        results = scanner.scan_file(tz.name)

    assert f'{tz.name}!classes.dex' in results
    assert len(results[f'{tz.name}!classes.dex']) > 0


def test_scan_scans_xz_entry_at_max_scan_size(scanner: Scanner):
    scanner.options.entry_max_scan_size = 1024
    entries = {'classes.dex': b'dex\n' + b'A' * (1024 - 4)}
    with make_temp_xz_zip(entries) as tz:
        results = scanner.scan_file(tz.name)

    assert f'{tz.name}!classes.dex' in results


def test_scan_skips_xz_entry_over_max_scan_size(scanner: Scanner):
    scanner.options.entry_max_scan_size = 1024
    entries = {'classes.dex': b'dex\n' + b'A' * (1025 - 4)}
    with make_temp_xz_zip(entries) as tz:
        results = scanner.scan_file(tz.name)

    assert f'{tz.name}!classes.dex' not in results


def test_scan_skips_xz_entry_with_lying_declared_size(scanner: Scanner):
    scanner.options.entry_max_scan_size = 1024
    entries = {'classes.dex': b'dex\n' + b'A' * (64 * 1024)}
    with make_temp_xz_zip(entries, declared_sizes={'classes.dex': 16}) as tz:
        results = scanner.scan_file(tz.name)

    assert f'{tz.name}!classes.dex' not in results


def test_decompress_xz_entry_handles_concatenated_streams(scanner: Scanner):
    payload = lzma.compress(b'AAAA') + lzma.compress(b'BBBB')
    info = zipfile.ZipInfo('classes.dex')
    info.file_size = 8
    info.compress_size = len(payload)

    assert scanner._decompress_xz_entry(io.BytesIO(payload), info, 0) == b'AAAABBBB'


def test_decompress_xz_entry_applies_memory_limit_to_later_streams(scanner: Scanner, monkeypatch):
    # Every decoder, including the one rebuilt for each concatenated stream, has
    # to carry the memory limit. Encoding a stream that declares a large
    # dictionary is not an option here: the encoder allocates roughly ten times
    # the dictionary size just to compress a few bytes, so the test records the
    # limit each decoder is constructed with instead.
    scanner.options.entry_max_scan_size = 1024
    limits = []
    real_decompressor = lzma.LZMADecompressor

    def recording_decompressor(*args, **kwargs):
        limits.append(kwargs.get('memlimit'))
        return real_decompressor(*args, **kwargs)

    monkeypatch.setattr('apkid.apkid.lzma.LZMADecompressor', recording_decompressor)

    payload = lzma.compress(b'AAAA') + lzma.compress(b'BBBBBBBB')
    info = zipfile.ZipInfo('classes.dex')
    info.file_size = 12
    info.compress_size = len(payload)

    assert scanner._decompress_xz_entry(io.BytesIO(payload), info, 0) == b'AAAABBBBBBBB'
    assert limits == [MIN_DECODER_MEMORY, MIN_DECODER_MEMORY]


def test_decompress_xz_entry_zero_disables_budget(scanner: Scanner):
    scanner.options.entry_max_scan_size = 0
    payload = lzma.compress(b'A' * 4096)
    info = zipfile.ZipInfo('classes.dex')
    info.file_size = 4096
    info.compress_size = len(payload)

    assert scanner._decompress_xz_entry(io.BytesIO(payload), info, 0) == b'A' * 4096


def test_decompress_xz_entry_bounds_concatenated_streams(scanner: Scanner):
    scanner.options.entry_max_scan_size = 1024
    payload = lzma.compress(b'A' * 600) + lzma.compress(b'B' * 600)
    info = zipfile.ZipInfo('classes.dex')
    info.file_size = 600
    info.compress_size = len(payload)

    assert scanner._decompress_xz_entry(io.BytesIO(payload), info, 0) is None

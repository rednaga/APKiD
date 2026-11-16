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
import json
import lzma
import os
import struct
import tempfile
import zipfile
import zlib
from typing import Dict, Optional, Union, IO

XZ_COMPRESSION_TYPE = 95


def load_data(file_path: str, is_json: bool = False) -> Union[str, dict]:
    data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
    full_path = os.path.join(data_path, file_path)
    with open(full_path, 'r') as f:
        data = f.read()

    if is_json:
        return json.loads(data)
    return data


def make_zip(entries: Dict[str, bytes]) -> io.BytesIO:
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'a', zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)

        for entry in zf.filelist:
            entry.create_system = 0
    memory_file.seek(0)
    return memory_file


def make_xz_zip(entries: Dict[str, bytes], declared_sizes: Optional[Dict[str, int]] = None) -> io.BytesIO:
    """Build a ZIP archive whose entries use XZ compression (method 95).

    `zipfile` can only write stored and deflated entries, so the archive is
    assembled by hand. APKiD handles method 95 through its own lzma branch
    because `zipfile` raises NotImplementedError for it.

    `declared_sizes` overrides the uncompressed size recorded in the ZIP
    headers, which lets tests build entries whose headers lie about their size.
    """
    declared_sizes = declared_sizes or {}
    local_headers = b''
    central_directory = b''
    for name, content in entries.items():
        name_bytes = name.encode()
        compressed = lzma.compress(content)
        crc = zlib.crc32(content) & 0xffffffff
        declared_size = declared_sizes.get(name, len(content))
        offset = len(local_headers)
        local_headers += struct.pack(
            '<IHHHHHIIIHH', 0x04034b50, 20, 0, XZ_COMPRESSION_TYPE, 0, 0,
            crc, len(compressed), declared_size, len(name_bytes), 0) + name_bytes + compressed
        central_directory += struct.pack(
            '<IHHHHHHIIIHHHHHII', 0x02014b50, 20, 20, 0, XZ_COMPRESSION_TYPE, 0, 0,
            crc, len(compressed), declared_size, len(name_bytes), 0, 0, 0, 0, 0, offset) + name_bytes
    end_of_central_directory = struct.pack(
        '<IHHHHIIH', 0x06054b50, 0, 0, len(entries), len(entries),
        len(central_directory), len(local_headers), 0)
    memory_file = io.BytesIO(local_headers + central_directory + end_of_central_directory)
    memory_file.seek(0)
    return memory_file


def make_temp_xz_zip(entries: Dict[str, bytes], declared_sizes: Optional[Dict[str, int]] = None) -> IO:
    with make_xz_zip(entries, declared_sizes) as file_obj:
        tz = tempfile.NamedTemporaryFile()
        tz.write(file_obj.read())
    tz.flush()
    return tz


def make_temp_zip(entries: Dict[str, bytes]) -> IO:
    with make_zip(entries) as file_obj:
        tz = tempfile.NamedTemporaryFile()
        tz.write(file_obj.read())
    tz.flush()
    return tz


def make_temp_file(content: bytes) -> IO:
    tz = tempfile.NamedTemporaryFile()
    tz.write(content)
    tz.flush()
    return tz

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

import io
import json
import os
import tempfile
import zipfile
from typing import Dict, Union, IO


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

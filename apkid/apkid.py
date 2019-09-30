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
import os
import traceback
import zipfile
from typing import Union, IO, List, Dict, Set

import yara

from .output import OutputFormatter
from .rules import RulesManager

SCANNABLE_FILE_MAGICS: Dict[str, Set[bytes]] = {
    'zip': {b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'},
    'dex': {b'dex\n', b'dey\n'},
    'elf': {b'\x7fELF'},
    # TODO: implement axml yara module
    # 'axml': set(),
}


class Options(object):

    def __init__(self, timeout: int = 10, verbose: bool = False, json: bool = False, output_dir: Union[str, None] = None,
                 typing: Union[str, None] = 'magic', entry_max_scan_size: int = 0, scan_depth=2, recursive: bool = False,
                 include_types: bool = False):
        """Scan options.
        Holds user-supplied options governing how APKiD behaves.

        Parameters
        ----------
        timeout : integer, optional (default=10)
            The number of seconds before Yara match should time out.
        json : boolean, optional (default=False)
            If the output should be JSON format.
        output_dir : string or None, optional (default=None)
            Directory to write individual scan results to. If this is true, it implies `json_output=True`.
            Note: This is useful for feature extraction of a bunch of APKs.
        verbose : boolean, optional (default=False)
            When set to `True`, log warnings and other debug information.
        typing : string or None, optional (default="magic")
            Determines how the scanner decides if a file should be scanned.
            If "magic", then require the file match a built-in list of supported file magics
            If "filename", then scan files which have names known to be supported (e.g. ".dex")
            If None, pass every file to Yara for matching.
            Note: This option defines a trade-off between performance and accuracy. For example, if you're scanning a large APK file, it is expensive
            to uncompress every ZIP entry for Yara matching. It's much faster to only decompress files which have a known extension such as ".dex".
            But in many cases files may not have the correct extension, e.g. a DEX file may be named "notmalware.gif". On the other extreme, one could
            simply decompress every file and scan it, but this is wasteful because most files in an APK are typically not interesting, e.g. images.
            The default behavior of "magic" only needs to read a few bytes to decide if a file should be completely uncompressed.
        entry_max_scan_size : integer, optional (default=0)
            If > 0, only scan APK entries if their uncompressed size is less than this value.
        scan_depth : integer, optional (default=2)
            Determines how many times scanner should recurse into nested archives.
            If 0, don't recurse into nested archives.
            Note: It's possible to construct a malicious ZIP which can be infinitely nested. It's therefore necessary to limit the scan depth.
            Don't get cheeky and think you can set this value to 1000 and scan random malware without blowing up your memory.
        recursive : boolean, optional (default=True)
            If true, when scanning a directory, will recurse into subdirectories.
        """
        self.timeout = timeout
        self.verbose = verbose
        self.typing = typing
        self.entry_max_scan_size = entry_max_scan_size
        self.scan_depth = scan_depth
        self.recursive = recursive
        self.rules_manager = RulesManager()
        self.output = OutputFormatter(
            json_output=json,
            output_dir=output_dir,
            rules_manager=self.rules_manager,
            include_types=include_types
        )


class Scanner(object):

    def __init__(self, rules: yara.Rules, options: Options):
        self.rules = rules
        self.options = options

    def scan(self, path: str) -> None:
        if os.path.isfile(path):
            results = self.scan_file(path)
            if len(results) > 0:
                self.options.output.write(results)
        elif os.path.isdir(path):
            self.scan_directory(path)

    def scan_directory(self, dir_path: str) -> None:
        for file_path in self._yield_file_paths(dir_path):
            self.scan(file_path)

    def scan_file(self, file_path: str) -> Dict[str, List[yara.Match]]:
        results = []
        with open(file_path, 'rb') as f:
            try:
                results: Dict[str, List[yara.Match]] = self.scan_file_obj(f, file_path)
            except Exception as e:
                stack = traceback.format_exc()
                print(f"Exception scanning {file_path}: {stack}")
        return results

    def scan_file_obj(self, file: IO, file_path: str = '$FILE$'):
        if file_path == '$FILE$':
            file_name = file_path
        else:
            file_name = os.path.basename(file_path)

        results: Dict[str, List[yara.Match]] = {}
        if not self._should_scan(file, file_name):
            return results

        matches: List[yara.Matches] = self.rules.match(data=file.read(), timeout=self.options.timeout)
        if len(matches) > 0:
            results[file_path] = matches
        if self._is_zipfile(file, file_name):
            with zipfile.ZipFile(file) as zf:
                zip_results = self._scan_zip(zf)
            for entry_name, entry_matches in zip_results.items():
                results[f'{file_path}!{entry_name}'] = entry_matches
        return results

    def _scan_zip(self, zf: zipfile.ZipFile, depth=0) -> Dict[str, List[yara.Match]]:
        results: Dict[str, List[yara.Match]] = {}
        for info in zf.infolist():
            if info.is_dir():
                continue
            try:
                self._scan_zip_entry(zf, info, results, depth)
            except Exception as e:
                stack = traceback.format_exc()
                print(f"Exception scanning {info.filename} in {zf.filename}, depth={depth}: {stack}")
        return results

    def _scan_zip_entry(self, zf, info, results, depth) -> None:
        with zf.open(info) as entry:
            # Python 3.6 zip entries are not seek'able :(
            entry_buffer: IO = io.BytesIO(entry.read(4))
            entry_buffer.seek(0)
            if not self._should_scan(entry_buffer, info.filename):
                return
            entry_buffer.seek(4)
            entry_buffer.write(entry.read())

        entry_buffer.seek(0)
        matches = self.rules.match(data=entry_buffer.read(), timeout=self.options.timeout)

        if len(matches) > 0:
            results[info.filename] = matches

        if depth < self.options.scan_depth and self._is_zipfile(entry_buffer, info.filename):
            with zipfile.ZipFile(entry_buffer) as zip_entry:
                nested_results = self._scan_zip(zip_entry, depth=depth + 1)
                for nested_name, nested_matches in nested_results.items():
                    results[f'{info.filename}!{nested_name}'] = nested_matches

    @staticmethod
    def _type_file(file: IO) -> Union[None, str]:
        magic = file.read(4)
        file.seek(0)
        for file_type, magics in SCANNABLE_FILE_MAGICS.items():
            if magic in magics:
                return file_type
        return None

    def _is_zipfile(self, file: IO, name: str) -> bool:
        if self.options.typing == 'filename':
            name = name.lower()
            return name.endswith('.apk') or name.endswith('.zip') or name.endswith('.jar')
        else:
            # Look at file magic since zipfile.is_zipfile isn't perfect
            # Some elfs may be considered zips and this causes apkid to barf errors
            file.seek(0)
            return Scanner._type_file(file) == 'zip' and zipfile.is_zipfile(file)

    def _should_scan(self, file: IO, name: str) -> bool:
        if self.options.typing == 'magic':
            file_type = Scanner._type_file(file)
            return file_type is not None
        elif self.options.typing == 'filename':
            name = name.lower()
            return name.startswith('classes') \
                   or name.startswith('AndroidManifest.xml') \
                   or name.startswith('lib/') \
                   or name.endswith('.so') \
                   or name.endswith('.dex') \
                   or name.endswith('.apk')
        return True

    def _yield_file_paths(self, dir_path: str):
        if self.options.recursive:
            for root, _, filenames in os.walk(dir_path):
                for path in filenames:
                    yield os.path.join(root, path)
        else:
            for path in os.listdir(dir_path):
                full_path = os.path.join(dir_path, path)
                if os.path.isdir(full_path):
                    continue
                yield full_path

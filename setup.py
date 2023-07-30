#!/usr/bin/env python
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

from codecs import open
from os import path, walk

from setuptools import setup, find_packages

import apkid

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()


def package_files(directory):
    paths = []
    for (filepath, directories, filenames) in walk(directory):
        for filename in filenames:
            paths.append(path.join(filepath, filename))
    return paths


install_requires = [
    'yara-python-dex>=1.0.1',
]

dev_requires = [
    'mypy',
    'pypandoc',
    'twine',
]

test_requires = [
    'delayed-assert',
    'factory_boy',
    'mock',
    'pytest',
    'pytest-cov',
    'pytest-factoryboy',
    'pytest-flask',
    'pytest-runner',
    'tox',
]

setup(
    name=apkid.__title__,
    version=apkid.__version__,
    description="Android Package Identifier",
    long_description=long_description,
    url='https://github.com/rednaga/APKiD',
    author=apkid.__author__,
    author_email='rednaga@protonmail.com',
    license=apkid.__license__,
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'License :: Other/Proprietary License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Security',
        'Topic :: Utilities',
    ],
    keywords='android analysis reversing malware apk dex dalvik',
    packages=find_packages(exclude=['docs', 'tests']),
    package_data={
        'rules': package_files('apkid/rules/'),
    },
    include_package_data=True,
    install_requires=install_requires,
    extras_require={
        'dev': dev_requires,
        'test': test_requires,
    },
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'apkid=apkid.main:main',
        ],
    },
)

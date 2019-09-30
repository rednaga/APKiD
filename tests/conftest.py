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

import yara

import pytest

from apkid.apkid import Scanner, Options
from apkid.rules import RulesManager


@pytest.fixture
def rules_manager():
    return RulesManager()


@pytest.fixture
def options():
    return Options()


@pytest.fixture
def rules():
    return yara.compile(source='rule dummy { condition: true }')


@pytest.fixture
def scanner(rules: yara.Rules, options):
    return Scanner(rules=rules, options=options)

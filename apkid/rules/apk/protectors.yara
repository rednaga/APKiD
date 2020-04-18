/*
 * Copyright (C) 2020  RedNaga. https://rednaga.io
 * All rights reserved. Contact: rednaga@protonmail.com
 *
 *
 * This file is part of APKiD
 *
 *
 * Commercial License Usage
 * ------------------------
 * Licensees holding valid commercial APKiD licenses may use this file
 * in accordance with the commercial license agreement provided with the
 * Software or, alternatively, in accordance with the terms contained in
 * a written agreement between you and RedNaga.
 *
 *
 * GNU General Public License Usage
 * --------------------------------
 * Alternatively, this file may be used under the terms of the GNU General
 * Public License version 3.0 as published by the Free Software Foundation
 * and appearing in the file LICENSE.GPL included in the packaging of this
 * file. Please visit http://www.gnu.org/copyleft/gpl.html and review the
 * information to ensure the GNU General Public License version 3.0
 * requirements will be met.
 *
 **/

include "common.yara"

rule virbox_apk : protector
{
  meta:
    description = "Virbox"
    url         = "https://shell.virbox.com"
    sample      = "b1a5d9d4c1916a0acc2d5c3b7c811a39ebeb2f6d42b305036473f7053bbf5fe7"
    author      = "Eduardo Novella"

  strings:
    $libs1 = "libsandhook.so"
    $libs2 = "libsandhook-native.so"
    $libv1 = "libv++_64.so"
    $libv2 = "libv++.so"

  condition:
    is_apk and
    1 of ($libs*) and
    1 of ($libv*)
}

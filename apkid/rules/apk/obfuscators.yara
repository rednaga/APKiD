/*
 * Copyright (C) 2019  RedNaga. https://rednaga.io
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

rule arxan_guardit : obfuscator
{
  meta:
    description = "Arxan GuardIT"
    url         = "https://www.arxan.com"
    sample      = "0da79f5202b4c29c4ef43f769d5703a3d4ebfa65e49ea967abb49965d4ac3ba4"
    author      = "Eduardo Novella"

  strings:
    // guardit4j.fin -- in root of apk; contains GuardIT version
    $cfg = { 00 67 75 61 72 64 69 74 34 6A 2E 66 69 6E }

  condition:
    is_apk and #cfg > 1
}

rule gemalto_protector : obfuscator
{
  meta:
    description = "Gemalto"
    url         = "https://www.gemalto.com"
    author      = "Eduardo Novella"
    sample      = "294f95298189080a25b20ef28295d60ecde27ee12361f93ad2f024fdcb5bdb0b"

  strings:
    $l1 = "lib/arm64-v8a/libmedl.so"
    $l2 = "lib/armeabi-v7a/libmedl.so"
    $l3 = "lib/armeabi/libmedl.so"
    $l4 = "lib/mips/libmedl.so"
    $l5 = "lib/mips64/libmedl.so"
    $l6 = "lib/x86/libmedl.so"
    $l7 = "lib/x86_64/libmedl.so"

  condition:
    any of them and is_apk
}

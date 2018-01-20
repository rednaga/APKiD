/*
 * Copyright (C) 2017  RedNaga. http://rednaga.io
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

import "dex"
include "common.yara"

rule dexguard : obfuscator
{
  meta:
    description = "DexGuard"

  strings:
    $opcodes = {
      00 06 00 01 00 03 00 00 00 00 00 00 00
      [20-65]
      0c 01
      12 12
      23 22 ?? ??
      1c 03 ?? ??
      12 04
      4d 03 02 04
      6e 3? ?? ?? 10 02
      0c 00
      62 01 ?? ??
      12 12
      23 22 ?? ??
      12 03
      4d 05 02 03
      6e 3? ?? ?? 10 02
      0c 00
      1f 00 ?? ??
      11 00
    }
    $a = "getClass"
    $b = "getDeclaredMethod"
    $c = "invoke"

  condition:
    is_dex and
    $opcodes and
    all of ($a, $b, $c) and
    uint32(dex.header.data_offset + dex.header.data_size - 4) == 0
}

rule dexprotector : obfuscator
{
  meta:
    description = "DexProtector"

  strings:
    $method = {
      07 00 02 00 00 00 02 00 00 00 00 00 3E 00 00 00
      12 01 13 00 0E 00 48 00 05 00 E0 00 00 10 01 12
      39 02 2A 00 12 32 D5 63 FF 00 48 03 05 03 D5 33
      FF 00 E1 04 06 08 D5 44 FF 00 48 04 05 04 D5 44
      FF 00 E0 04 04 08 B6 43 E1 04 06 10 D5 44 FF 00
      48 04 05 04 D5 44 FF 00 E0 04 04 10 B6 43 E1 04
      06 18 D5 44 FF 00 48 00 05 04 E0 00 00 18 B6 30
      0F 00 0D 02 39 01 FE FF 12 21 DD 02 06 7F 48 00
      05 02 E1 00 00 08 28 F5 0D 03 28 CB 0D 00 00 00
      20 00 ?? 00 37 00 00 00 02 00 ?? 00 02 01
    }
    $a = "getClass"
    $b = "getDeclaredMethod"
    $c = "invoke"

  condition:
    is_dex and
    $method and
    all of ($a, $b, $c)
}

rule bitwise_antiskid : obfuscator
{
  meta:
    description = "Bitwise AntiSkid"

  strings:
    $credits = "AntiSkid courtesy of Bitwise\x00"
    $array = "AntiSkid_Encrypted_Strings_Courtesy_of_Bitwise"
    $truth1 = "Don't be a script kiddy, go actually learn something. Stealing credit is pathetic, you didn't make this or even contribute to it and you know it."
    $truth2 = "Only skids can't get plaintext. Credits to Bitwise.\x00"

  condition:
    is_dex and
    any of them
}


rule arxan : obfuscator
{
  meta:
    description = "Arxan"
    url         = "https://www.arxan.com/products/application-protection-mobile/"
    example     = "7bd1139b5f860d48e0c35a3f117f980564f45c177a6ef480588b5b5c8165f47e"

  strings:
    // Obfuscated Lpackage/class/: "L([a-z]\1{5}\/[a-z]{6}\/".
    // AFAIK, Yara does not support backreferences at the moment, thus this is the combo:
    $pkg = /L(a{6}|b{6}|c{6}|d{6}|e{6}|f{6}|g{6}|h{6}|i{6}|j{6}|k{6}|l{6}|m{6}|n{6}|o{6}|p{6}|q{6}|r{6}|s{6}|t{6}|u{6}|v{6}|w{6}|x{6}|y{6}|z{6})\/[a-z]{6}/

    // Obfuscated methods are found to follow a pattern like:
    // 1 byte size + 1 byte ASCII + [7-26] non-ASCII bytes + 00 (null terminator)
    $m1 = { 10 62 (6? | 75) [14] 00 }
    $m2 = { (0b | 0d) 62 d0 [15] 00 }
    $m3 = { (0e | 10) 62 30 34 3? [15] 00 }
    $m4 = { (0b | 0d) 62 30 34 3? [13] 00 }
    $m5 = { (08 | 0b | 0d | 0e ) 62 [7-13] 00 }
    $m6 = { 0a 62 (30 34 3? | d? ?? ??) [11] 00 }
    $m7 = { (0d | 0b | 11) (62 d1 8? | 6? ?? ??) [14] 00 }

  condition:
    is_dex and
    $pkg and
    6 of ($m*)
}


rule arxan_multidex : obfuscator
{
  meta:
    description = "Arxan (multidex)"
    url         = "https://www.arxan.com/products/application-protection-mobile/"
    example     = "9b2a978a937293d6cb93439e0f819b4e044a3fad80dde92dec9b67e419278b5d"

  strings:
    // Obfuscated Lpackage/class/: "L([a-z]\1{5}\/[a-z]{6}\/".
    // AFAIK, Yara does not support backreferences at the moment, thus this is the combo:
    $pkg = /L(a{6}|b{6}|c{6}|d{6}|e{6}|f{6}|g{6}|h{6}|i{6}|j{6}|k{6}|l{6}|m{6}|n{6}|o{6}|p{6}|q{6}|r{6}|s{6}|t{6}|u{6}|v{6}|w{6}|x{6}|y{6}|z{6})\/[a-z]{6}/

    // Obfuscated methods are found to follow a pattern like:
    // 1 byte size + 1 byte ASCII + [7-26] non-ASCII bytes + 00 (null terminator)
    $m1 = { 10 62 (6? | 75) [14] 00 }
    $m2 = { (0b | 0d) 62 d0 [15] 00 }
    $m3 = { (0e | 10) 62 30 34 3? [15] 00 }
    $m4 = { (0b | 0d) 62 30 34 3? [13] 00 }
    $m5 = { (08 | 0b | 0d | 0e ) 62 [7-13] 00 }
    $m6 = { 0a 62 (30 34 3? | d? ?? ??) [11] 00 }
    $m7 = { (0d | 0b | 11) (62 d1 8? | 6? ?? ??) [14] 00 }

  condition:
    is_dex and
    $pkg and
    2 of ($m*) and
    not arxan
}



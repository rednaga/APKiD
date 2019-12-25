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

import "dex"
include "common.yara"

private rule short_unicode_field_names : internal
{
  meta:
    description = "one or two character unicode field names"

  condition:
    is_dex and
    for 3 i in (0..dex.header.field_ids_size) : (dex.field[i].name matches /[^\x00-\x7F]{1,4}/)
}

private rule short_unicode_method_names : internal
{
  meta:
    description = "one or two character unicode method names"

  condition:
    is_dex and
    for 3 i in (0..dex.header.method_ids_size) : (dex.method[i].name matches /[^\x00-\x7F]{1,4}/)
}

rule dexguard_a : obfuscator
{
  meta:
    description = "DexGuard"
    url         = "https://www.guardsquare.com/en/products/dexguard"
    sample      = "74eb7cf3b81ff14add71ca884ef0cc9c7477b4193a74ca71b92f81212ff56101"

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

rule dexguard_b : obfuscator
{
  meta:
    description = "DexGuard"
    url         = "https://www.guardsquare.com/en/products/dexguard"
    sample      = "41a9b44af8931d63812b4a23395b29279d2e055f357222dabed7153d4aee6299"

  strings:
    // Other obfuscators use aux and con (protected Windows file names), but not from Lo/
    $a_aux_class     = { 00 07 4C 6F 2F (41|61) (55|75) (58|78) 3B 00 }  // Lo/[Aa][Uu][Xx];
    $a_con_class     = { 00 07 4C 6F 2F (43|63) (4F|6F) (4E|6E) 3B 00 }  // Lo/[Cc][Oo][Nn];
    $a_if_class      = { 00 ?? 4C 6F 2F [1-4] 24 (49|69) (46|66) 3B 00 } // Lo/???$[iI][fF];
    // A single unicode code point may take 1 or more bytes depending on encoding.
    // Normally only see one code point worth, but not sure how many bytes it might be in some variants.
    // Also note the trailing null byte in the regex so this  is less of a naked string.
    $a_inner_unicode = /Lo\/([\u0000-\u007F]{1,4}|[^\u0000-\u007F]{1,4})\$[^\u0000-\u007F]{1,4};\x00/
    $b_o_three_class = { 00 07 4C 6F 2F ?? ?? ?? 3B 00 }  // Lo/???;

  condition:
    2 of ($a_*)
    or (#a_if_class >= 3 and (short_unicode_field_names or short_unicode_method_names))
    or (#b_o_three_class >= 3 and (short_unicode_field_names or short_unicode_method_names))
}

rule dexguard_c : obfuscator
{
  meta:
    description = "DexGuard"
    url         = "https://www.guardsquare.com/en/products/dexguard"
    sample      = "de67161a8bd7ebcaa26c9661efd811375b59260924eb0dfd9436d3a47a1c31fe"

  strings:
    $dexguard_pkg = "guardsquare/dexguard/runtime"
    // Most of some kind of runtime decryption method, signature = a(IIZI[I[[I[I)V
    $decrypt_method = {
      12 01                 // const/4 v1, 0x0
      39 ?? ?? ??           // if-nez ??, :????
      71 ?? ?? ?? ?? ??     // invoke-static {??}, ??
      01 10                 // move v0, v1
      35 ?? ?? ??           // if-ge ?, ?, :????
      44 ?? ?? ??           // aget ??, ??, ??
      B7 ??                 // xor-int/2addr (xor is fairly rare in legit code)
      71 ?? ?? ?? ?? ??     // invoke-static
      0A ??                 // move-result ??
      97 ?? ?? ??           // xor-int ??, ??, ??
      D8 00 00 01           // add-int/lit8 v0, v0, 0x1
      01 ??                 // move ?, ?
      28 F2                 // goto
      21 80                 // array-length
      D8 00 00 FE           // add-int/lit8 v0, v0, -0x2
      44 ?? ?? ??           // aget ??
      B7 ??                 // xor-int/2addr
      21 ??                 // invoke-static
      D8 ?? ?? ??           // add-int
      44 ?? ?? ??           // aget
      B7 ??                 // xor-int/2addr
    }

  condition:
    any of them
}

rule dexguard_d : obfuscator
{
  meta:
    description = "DexGuard"
    url         = "https://www.guardsquare.com/en/products/dexguard"
    sample      = "423b09d2aec74b1624d5b5c63d24486efc873c9cce75ea9e2f2d699f40ca8f7c"

  strings:
    // Ldexguard/util/TamperDetection;
    $dexguard_class = {00 1F 4C 64 65 78 67 75 61 72 64 2F 75 74 69 6C 2F 54 61 6D 70 65 72 44 65 74 65 63 74 69 6F 6E 3B 00}
    $a_aux_class     = { 00 05 4C (41|61) (55|75) (58|78) 3B 00 }  // L[Aa][Uu][Xx];
    $a_con_class     = { 00 05 4C (43|63) (4F|6F) (4E|6E) 3B 00 }  // L[Cc][Oo][Nn];
    $a_if_class      = { 00 ?? 4C [1-4] 24 (49|69) (46|66) 3B 00 } // L???$[iI][fF];
    $a_inner_unicode = /L([\u0000-\u007F]{1,4}|[^\u0000-\u007F]{1,4})\$[^\u0000-\u007F]{1,4};\x00/

  condition:
    3 of them
    or $dexguard_class
    or (#a_if_class >= 3 and (short_unicode_field_names or short_unicode_method_names))
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
    sample      = "7bd1139b5f860d48e0c35a3f117f980564f45c177a6ef480588b5b5c8165f47e"
    author      = "Eduardo Novella"

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
    sample      = "9b2a978a937293d6cb93439e0f819b4e044a3fad80dde92dec9b67e419278b5d"
    author      = "Eduardo Novella"

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

rule arxan_b : obfuscator
{
  meta:
    description = "Arxan (b - unconfirmed)"
    url         = "https://github.com/rednaga/APKiD/issues/160"
    sample      = "86ade15e885cf7927e5840dd2bf2782905fcd6843be77f898b51b64c2277f3de"
    author      = "Tim 'diff' Strazzere"

  strings:
    // Targeting this seemingly static byte sequence used inside the injected obfuscation:
    // move-result v0 (moving result from own deobfuscation, v2 and v3 are always consts)
    $deobf = {
      0A 0?
      DF 01 03 FF
      // and-int/2addr v1, v0
      B5 01
      // xor-int/lit8 v0, v0, -0x1
      DF 00 00 FF
      // and-int/2addr v0, v3
      B5 30
      // or-int/2addr v1, v0
      B6 01
      // int-to-short v7, v1
      8F 1?
    }

  condition:
    is_dex and
    $deobf
}

rule allatori_demo : obfuscator
{
  meta:
    description = "Allatori demo"
    url         = "http://www.allatori.com/features.html"
    author      = "Eduardo Novella"
    sample      = "7f2f5aac9833f7bdccc0b9865f5cc2a9c94ee795a285ef2fa6ff83a34c91827f"
    sample2     = "8c9e6c7b8c516499dd2065cb435ef68089feb3d4053faf2cfcb2b759b051383c"

  strings:
    // null-prev-str + len + str + null
    $s = { 00 0D 41 4C 4C 41 54 4F 52 49 78 44 45 4D 4F 00 }  // ALLATORIxDEMO

  condition:
    $s and is_dex
}

rule aamo_str_enc : obfuscator
{
  meta:
    description = "AAMO"
    author      = "P0r0"
    url         = "https://github.com/necst/aamo"
    sample      = "c1ef860af0e168f924663630ed3b61920b474d0c8b10e2bde6bfd3769dbd31a8"
    sample2     = "eb0d4e1ba2e880749594eb8739e65aa21b6f7b43798f04b6681065b396c15a78"

  strings:
    $opcodes_nops = {
        22 ?? ?? ??                                 //new-instance v? Ljava/lang/String;
        ( 00 00 | 00 00 00 00 | 00 00 00 00 00 00 )
        12 ?2                                       //const/4 v2, 0x2 (the register and constant never change)
        ( 00 00 | 00 00 00 00 | 00 00 00 00 00 00 )
        1a ?? ?? ??                                 //const-string v?, _ref_to_string_
        ( 00 00 | 00 00 00 00 | 00 00 00 00 00 00 )
        71 ?? ?? ?? ?? ??                           //invoke-static {v?, v?}, Landroid/content/res/_RANDOM_CLASS_NAME.getStorageEncryption(ILjava/lang/String;)Ljavax/crypto/Cipher;
        0c 02                                       //move-result-object v2 (the register never changes)
        ( 00 00 | 00 00 00 00 | 00 00 00 00 00 00 )
        71 ?? ?? ?? ?? ??                           //invoke-static {v?, v?}, Landroid/content/res/_RANDOM_CLASS_NAME.decode(Ljava/lang/String;)[B
        0c 03                                       //move-result-object v3
        ( 00 00 | 00 00 00 00 | 00 00 00 00 00 00 )
        6e ?? ?? ?? ?? ??                           //invoke-virtual {v?, v?}, Ljavax/crypto/Cipher.doFinal([B)[B
        0c 02                                       //move-result-object v2
        ( 00 00 | 00 00 00 00 | 00 00 00 00 00 00 )
        1a ?? ?? ??                                 //const-string v?, _CONST_STR_
        ( 00 00 | 00 00 00 00 | 00 00 00 00 00 00 )
        70 ?? ?? ?? ?? ??                           //invoke-direct {v?, v?, v?}, Ljava/lang/String.<init>([BLjava/lang/String;)
        71 ?? ?? ?? ?? ??                           //invoke-static {v?, v?}, Landroid/content/res/_RANDOM_CLASS_NAME._RANDOM_METHOD_NAME_(Ljava/lang/String;)Ljava/lang/String;
        0c ??                                       //move-result-object v4
    }

    $opcodes = {
        22 ?? ?? ??         //new-instance v? Ljava/lang/String;
        12 ?2               //const/4 v2, 0x2 (the register and constant never change)
        1a ?? ?? ??         //const-string v?, _ref_to_string_
        71 ?? ?? ?? ?? ??   //invoke-static {v?, v?}, Landroid/content/res/_RANDOM_CLASS_NAME.getStorageEncryption(ILjava/lang/String;)Ljavax/crypto/Cipher;
        0c 02               //move-result-object v2 (the register never changes)
        71 ?? ?? ?? ?? ??   //invoke-static {v?, v?}, Landroid/content/res/_RANDOM_CLASS_NAME.decode(Ljava/lang/String;)[B
        0c 03               //move-result-object v3
        6e ?? ?? ?? ?? ??   //invoke-virtual {v?, v?}, Ljavax/crypto/Cipher.doFinal([B)[B
        0c 02               //move-result-object v2
        1a ?? ?? ??         //const-string v?, _CONST_STR_
        70 ?? ?? ?? ?? ??   //invoke-direct {v?, v?, v?}, Ljava/lang/String.<init>([BLjava/lang/String;)
        71 ?? ?? ?? ?? ??   //invoke-static {v?, v?}, Landroid/content/res/_RANDOM_CLASS_NAME._RANDOM_METHOD_NAME_(Ljava/lang/String;)Ljava/lang/String;
        0c ??               //move-result-object v4
    }

    $a = { 00 0f 63 6f 6e 76 65 72 74 54 6f 53 74 72 69 6e 67 00 } // convertToString
    $b = { 00 14 67 65 74 53 74 6f 72 61 67 65 45 6e 63 72 79 70 74 69 6f 6e 00 } //getStorageEncryption

  condition:
    1 of ($opcodes*) and all of ($a, $b)
}

rule appsuit_a : obfuscator
{
    meta:
        description = "AppSuit"
        url         = "http://www.stealien.com/appsuit.html"
        sample      = "b99bafbbd5288ac93647d22f1c5b1863c96f581ae7a19fdc0e84bff4c2141328"
        author      = "Eduardo Novella"

    strings:
        $a1 = { 00 0741707053756974 00 }                          // 00AppSuit00
        $a2 = { 00 0741505053554954 00 }                          // 00APPSUIT00
        $c1 = { 00 144c636f6d2f737465616c69656e2f636f6e73743b00 } // 00Lcom/stealien/const;00
        $c3 = { 00 084c615f6c6f636b3b00 }                         // 00La_lock;00
        $l1 = { 00 6c6962417070537569742e736f 00 }                // 00libAppSuit.so00
        $o  = { 000c 6368 6563 6b41 7070 5375 6974 00 }           // 00checkAppSuit00
        $p1 = { 00 08737465616c69656e 00 }                        // 00stealien00

    condition:
        is_dex and 2 of them
}

rule appsuit_b : obfuscator
{
    meta:
        description = "AppSuit"
        url         = "http://www.stealien.com/appsuit.html"
        sample      = "6055deceb83233cceefc89b2bce4e978fd417820c5f534b0df66415122f394ea"
        author      = "Eduardo Novella"

    strings:
        $c = { 00?? 4c636f6d2f737465616c69656e2f61707073756974 2f } // 00??Lcom/stealien/appsuit/

    condition:
        is_dex and all of them
}

rule gemalto_sdk : obfuscator
{
  meta:
    description = "Gemalto"
    url         = "https://www.gemalto.com/brochures-site/download-site/Documents/eba_ezio_on_mobile.pdf"
    author      = "Eduardo Novella"
    sample      = "294f95298189080a25b20ef28295d60ecde27ee12361f93ad2f024fdcb5bdb0b"

  strings:
    $p1 = "Lcom/gemalto/idp/mobile/"
    $p2 = "Lcom/gemalto/medl/"
    $p3 = "Lcom/gemalto/ezio/mobile/sdk/"

  condition:
    any of them and is_dex
}

rule kiwi_amazon : obfuscator
{
  meta:
    description = "Kiwi encrypter"
    sample      = "3e309548f90160e3a4dc6f67621c75d2b66cc3b580da7306ff3dc6d6c25bb8a1"
    author      = "Eduardo Novella"

  strings:
    $key   = { 00 19 4B6977695F5F56657273696F6E5F5F4F626675736361746F72 00 } // 00+len+"Kiwi__Version__Obfuscator"+00
    $class = { 00 19 4B69776956657273696F6E456E637279707465722E6A617661 00 } // 00+len+"KiwiVersionEncrypter.java"+00

  condition:
    all of them
}

rule unreadable_field_names : obfuscator
{
  meta:
    description = "unreadable field names"
    sample      = "afd6da00440ec83d54aefea742f26ba045505ac520f074512207a7bb50aaf9c4"

  condition:
    short_unicode_field_names
    and (not dexguard_a and not dexguard_b and not dexguard_c and not dexguard_d)
}

rule unreadable_method_names : obfuscator
{
  meta:
    description = "unreadable method names"
    sample      = "afd6da00440ec83d54aefea742f26ba045505ac520f074512207a7bb50aaf9c4"

  condition:
    short_unicode_method_names
    and (not dexguard_a and not dexguard_b and not dexguard_c and not dexguard_d)
}

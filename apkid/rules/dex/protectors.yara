/*
 * Copyright (C) 2022  RedNaga. https://rednaga.io
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

rule CNProtect_dex : protector
{
  // https://github.com/rednaga/APKiD/issues/52
  meta:
    description = "CNProtect (anti-disassemble)"
    sample = "5bf6887871ce5f00348b1ec6886f9dd10b5f3f5b85d3d628cf21116548a3b37d"

  strings:
    // code segment of the injected methods plus junk opcodes
    $code_segment = {
	  02 00 01 00 00 00 00 00 ?? ?? ?? ?? 11 00 00 00 00 (1? | 2? | 3? | 4? | 5? | 6? | 7? | 8? | 9? | a? | b? | c0 | c1 | c2 | c3 | c4 | c5 | c6 | c7)
    }

  condition:
    is_dex and
    $code_segment
}

rule whitecryption_dex : protector
{
  // https://github.com/rednaga/APKiD/issues/177
  meta:
    description = "WhiteCryption"
    sample      = "6821bce73b3d1146ef7ec9a2d91742a7f6fc2f8206ca9354d3d553e1b5d551a7"
    url         = "https://www.intertrust.com/products/application-shielding/"
    author      = "Tim 'diff' Strazzere"

  strings:
    // Loader class which doesnt appear to get obfuscated in these versions, plus
    // the surrounding null bytes and sizing used for the dex string table
    // Lcom/whitecryption/jcp/generated/scp;
    $loader = {
      00 25 4C 63 6F 6D 2F 77 68 69 74 65 63 72 79 70
      74 69 6F 6E 2F 6A 63 70 2F 67 65 6E 65 72 61 74
      65 64 2F 73 63 70 3B 00
    }
    // __scpClassInit with surrounding size and null bytes
    $init_stub = { 00 0E 5F 5F 73 63 70 43 6C 61 73 73 49 6E 69 74 00 }

  condition:
    is_dex and ($loader or $init_stub)
}

rule whitecryption_dex_a : protector
{
  meta:
    description = "WhiteCryption"
    url         = "https://www.intertrust.com/products/application-shielding/"
    sample      = "6ca8315fdb3fc2af989dd49806102bc3720b214f2053297b9f1041ab4f2f81b2"
    author      = "Eduardo Novella"

  strings:
    $s1 = "http://www.whitecryption.com"
    $s2 = /\(c\) 20\d{2} whiteCryption/
    $s3 = "http://www.cryptanium.com"
    $s4 = "CryptaniumHighSpeedAes"
    $s5 = "Lcom/cryptanium/skb/"
    $s6 = "SecureKeyBoxJava"

  condition:
    is_dex and 3 of ($s*)
}

rule appdome_dex : protector
{
  // https://github.com/rednaga/APKiD/issues/151
  meta:
    description = "Appdome (dex)"
    sample      = "1c6496f1cc8c5799539ee24170c371e8a57547e2eb73c9502c98ff78f44c74cf"
    url         = "https://www.appdome.com/"
    author      = "Tim 'diff' Strazzere"

  strings:
    // Loader class injected into everything, surrounding null bytes and size
    // Lruntime/loading/InjectedActivity;
    $loader = {
      00 22 4C 72 75 6E 74 69 6D 65 2F 6C 6F 61 64 69
      6E 67 2F 49 6E 6A 65 63 74 65 64 41 63 74 69 76
      69 74 79 3B 00
    }

  condition:
    is_dex and $loader
}

rule insidesecure : protector
{
  meta:
    description = "InsideSecure Verimatrix"
    url         = "https://www.verimatrix.com/products/app-shield/"
    sample      = "edb939d77adba5ef5c536c352a4bc25a3a5ff2fe15408c5af9f08b5af583224c" // dk.mitid.app.android v2.3.7
    author      = "Eduardo Novella"

  strings:
    // Loader class injected into everything, surrounding null bytes and size
    // 00 + size + Lcom/insidesecure/core/
    $class = {
      00 ?? 4c 636f 6d2f 696e 7369 6465 7365  6375 7265 2f 63 6f72 652f
    }

  condition:
    is_dex and all of them
}

rule free_rasp_dex : protector
{
  meta:
    description = "FreeRASP"
    sample      = "e10b8772fd9b6aaf8ba030c5bcb324fb9b91f34e893a62bdf238629df856e047"
    url         = "https://www.talsec.app/freerasp-in-app-protection-security-talsec"
    author      = "Fare9"

  strings:
    // Decryption method found in DEX files, since strings will change
    // and other offsets change, we add ?? to some instructions
    $decryption = {
      6e 10 ?? ?? 08 00           // invoke-virtual {v8}, Ljava/lang/String.length()I
      0a 00                       // move-result v0
      db 00 00 02                 // div-int/lit8 v0, v0, 0x2
      23 01 ?? ??                 // new-array v1, v0, [B
      12 02                       // const/4 v2, 0
      12 03                       // const/4 v3, 0
      12 04                       // const/4 v4, 0
      6e 10 ?? ?? 08 00           // invoke-virtual {v8}, Ljava/lang/String.length()I
      0a 05                       // move-result v5
      35 53 28 00                 // if-ge v3, v5, 0x0016c83a
      d8 05 03 01                 // add-int/lit8 v5, v3, 0x1
      6e 20 ?? ?? 38 00           // invoke-virtual {v8, v3}, Ljava/lang/String.charAt(I)C
      0a 03                       // move-result v3
      13 06 10 00                 // const/16 v6, 0x10
      71 20 ?? ?? 63 00           // invoke-static {v3, v6}, Ljava/lang/Character.digit(CI)I
      0a 03                       // move-result v3
      e0 03 03 04                 // shl-int/lit8 v3, v3, 0x4
      8d 33                       // int-to-byte v3, v3
      4f 03 01 04                 // aput-byte v3, v1, v4
      48 03 01 04                 // aget-byte v3, v1, v4
      d8 07 05 01                 // add-int/lit8 v7, v5, 0x1
      6e 20 ?? ?? 58 00           // invoke-virtual {v8, v5}, Ljava/lang/String.charAt(I)C
      0a 05                       // move-result v5
      71 20 ?? ?? 65 00           // invoke-static {v5, v6}, Ljava/lang/Character.digit(CI)I
      0a 05                       // move-result v5
      8d 55                       // int-to-byte v5, v5
      b0 53                       // add-int/2addr v3, v5
      8d 33                       // int-to-byte v3, v3
      4f 03 01 04                 // aput-byte v3, v1, v4
      d8 04 04 01                 // add-int/lit8 v4, v4, 0x1
      01 73                       // move v3, v7
      28 d5                       // goto 0x0016c7e2
      23 08 ?? ??                 // new-array v8, v0, [B
      35 02 12 00                 // if-ge v2, v0, 0x0016c862
      48 03 01 02                 // aget-byte v3, v1, v2
      62 04 ?? ??                 // sget-object v4, Lx0/o;->a [B
      21 45                       // array-length v5, v4
      94 05 02 05                 // rem-int v5, v2, v5
      48 04 04 05                 // aget-byte v4, v4, v5
      b7 43                       // xor-int/2addr v3, v4
      8d 33                       // int-to-byte v3, v3
      4f 03 08 02                 // aput-byte v3, v8, v2
      d8 02 02 01                 // add-int/lit8 v2, v2, 0x1
      28 ef                       // goto 0x0016c83e
      22 00 ?? ??                 // new-instance v0, Ljava/lang/String;
      70 20 ?? ?? 80 00           // invoke-direct {v0, v8}, Ljava/lang/String.<init>([B)V
      11 00                       // return-object v0
    }

  condition:
    is_dex and $decryption
}

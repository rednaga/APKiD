/*
 * Copyright (C) 2023  RedNaga. https://rednaga.io
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
    description = "Appdome"
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

rule appiron : protector
{
    meta:
        description = "Secucen AppIron"
        url         = "http://www.secucen.com/app/view/fintech/appIron"
        sample      = "d4f4a24ce6350bc4e23e2170da5b217dd65161aba5eca775d75514e9cdac4d59"
        author      = "dustty0 & Eduardo Novella"

    strings:
      $pkg1 = {
             0023 4c63 6f6d 2f62 6172 756e 2f61 //   .#Lcom/barun/a
        7070 6972 6f6e 2f61 6e64 726f 6964 2f41 // ppiron/android/A
        7070 4972 6f6e 3b00                     // ppIron;.
      }

      $pkg2 = {
                                  00 2d4c 636f  //            .-Lco
        6d2f 7365 6375 6365 6e2f 6170 7069 726f // m/secucen/appiro
        6e65 7870 7265 7373 2f41 7070 4972 6f6e // nexpress/AppIron
        4578 6365 7074 696f 6e3b 00             // Exception;.
      }

      $pkg3 = {
                                 002b 4c63 6f6d //            +Lcom
        2f73 6563 7563 656e 2f61 7070 6972 6f6e // /secucen/appiron
        6578 7072 6573 732f 4170 7049 726f 6e45 // express/AppIronE
        7870 7265 7373 3b00                     // xpress;.
      }

    condition:
      is_dex and any of them
}

rule ahope_appshield : protector
{
    meta:
        description = "Ahope AppShield"
        url         = "http://www.ahope.net/sub/app-shields"
        sample      = "42a4d907caf625ff73d5b6fbbf32b59ba14d6d5a72f28b81bdc76c47db516122"
        author      = "dustty0 & Eduardo Novella"

    strings:
      $pkg1 = {
                                00 234c 636f 6d2f //          .#Lcom/
          6168 6f70 652f 6170 705f 7368 6965 6c64 // ahope/app_shield
          732f 4275 696c 6443 6f6e 6669 673b 00   // s/BuildConfig;.H
      }

      $pkg2 = {
                                00 254c 636f 6d2f //          .%Lcom/
          6168 6f70 652f 6170 705f 7368 6965 6c64 // ahope/app_shield
          732f 5075 7265 4170 7043 6c69 656e 743b // s/PureAppClient;
          00
      }

    condition:
      is_dex and any of them
}

rule vguard : protector
{
  meta:
    description = "VGuard"
    url         = "https://www.vguard.co.kr"
    sample      = "7024bdadb53cbec86a39de845108b182ed2f7b3f0e7c0b876a948e1532ec5b9f"
    author      = "dustty0"

  strings:
    $pkg = {
      001b 4c6b 722f 636f 2f73 646b 2f76 6775 6172 6432 // ..Lkr/co/sdk/vguard2
      2f45 6465 784a 4e49 3b00                          // /EdexJNI;.
    }

  condition:
    is_dex and any of them
}

rule appdefence : protector
{
  meta:
    description = "ExTrus AppDefence"
    url         = "https://www.extrus.co.kr/eng/m/product_01_05.html"
    sample      = "e080380673479d2e182ad7eff5130bb72fe9a228c0a5de9852df23c4e98113b2"
    author      = "dustty0"

  strings:
    $pkg = {
           003e 4c6e 6574 2f65 7874 7275 732f 6578 6166 //   .>Lnet/extrus/exaf
      652f 6170 7064 6566 656e 6365 2f6d 6f64 756c 652f // e/appdefence/module/
      6170 7064 6566 656e 6365 2f44 6566 656e 6365 4170 // appdefence/DefenceAp
      6949 6d70 6c3b 00                                 // iImpl;.
    }

  condition:
    is_dex and all of them
}

rule xiaomi_xsof_sdk : protector
{
  meta:
    description = "Xiaomi Security Open Service Client SDK"
    url         = "https://dev.mi.com/distribute/doc/details?pId=1746"
    sample      = "3a01186dbb3cb550d4b6139c8d82e39e74f7b3cc74966a27232e91c164817fe1"
    author      = "aviraxp"

  strings:
    // .?com.xiaomi.security.xsof.?
    $s = {
      00 ?? 636f 6d2e 7869 616f 6d69 2e73 6563 7572 6974 792e 7873 6f66 2e [1-128] 00
    }

  condition:
    is_dex and #s > 1
}

rule dpt_shell : protector
{
  meta:
    description = "DPT Shell"
    url         = "https://github.com/luoyesiqiu/dpt-shell"
    sample      = "0c4341700f4e685cafc9c86c9112098b75057580ba1f7163bc971347af3712ad"
    author      = "Abhi"

  strings:
    $s1 = { 00 ?? 4C 63 6F 6D 2F 6C 75 6F 79 65 2F 64 70 74 } // .??Lcom/luoye/dpt
    $s2 = { 00 ?? 4C 63 6F 6D 2F 6C 75 6F 79 65 73 69 71 69 75 2F 73 68 65 6C 6C } // .??Lcom/luoyesiqiu/shell
    $s3 = { 00 08 64 70 74 2D 6C 69 62 73 00 } // dpt-libs
    $s4 = { 00 0D 64 70 74 5F 4A 6E 69 42 72 69 64 67 65 00 } // dpt_JniBridge
    $s5 = { 00 09 6C 69 62 64 70 74 2E 73 6F 00 } // libdpt.so

  condition:
    is_dex and any of them
}

rule ahnlab_v3_engine : anti_root
{
  meta:
    description = "Ahnlab V3 Engine"
    url         = "https://www.ahnlab.com/en"
    sample      = "638bad9c6336049f43ac88d7db65c743d9703d732f86f2dc094999b195d63aa2"
    author      = "whoa-mi"

  strings:
    $class = "Lcom/ahnlab/enginesdk/"
  condition:
    is_dex and #class > 10
}

rule nhn_appguard_dex : protector
{
  meta:
    description = "NHN AppGuard"
    url         = "https://www.nhncloud.com/kr/service/security/nhn-appguard"
    sample      = "bafa2a9acf4af696b92e0a1ddcf7f470d49a7f3bc27b5c1b1e3ecbdf17049285" // jp.pjfb
    author      = "Abhi"

  strings:
    $package = { 00 ?? 4C 63 6F 6D 2F 6E 68 6E (63 6C 6F 75 64 | 65 6E 74) 2F 61 70 70 67 75 61 72 64 2F } // .??Lcom/nhn(cloud|ent)/appguard/

  condition:
    is_dex and all of them
}

rule protectt_dex : protector
{
  meta:
    description = "Protectt"
    sample      = "c246d85560599f91e9c3ed7e59df2dd4e21aaf667f3f2965c28c43d9842f5e75" // com.rblbank.mobank
    url         = "https://www.protectt.ai"
    author      = "Abhi"

  strings:
    $class = { 00 1C 4C 61 69 2F 70 72 6F 74 65 63 74 74 2F 61 70 70 2F 73 65 63 75 72 69 74 79 2F 52 3B 00 } // ..Lai/protectt/app/security/R;.

  condition:
    is_dex and all of them
}

rule flutter_security_checker : protector
{
  meta:
    description = "Flutter Security Checker"
    url         = "https://pub.dev/packages/flutter_security_checker"
    sample      = "045d548cfd282d1aa8993efd22846ff49b0c48d99590cc36e3cf6c633dd85bcc" // com.swisssign.swissid.mobile
    author      = "Abhi"

  strings:
    $class = { 00 43 4C 63 6F 6D 2F 70 72 61 76 65 72 61 2F 66 6C 75 74 74 65 72 5F
               73 65 63 75 72 69 74 79 5F 63 68 65 63 6B 65 72 2F 46 6C 75 74 74 65
               72 53 65 63 75 72 69 74 79 43 68 65 63 6B 65 72 50 6C 75 67 69 6E 3B 00 } // Lcom/pravera/flutter_security_checker/FlutterSecurityCheckerPlugin;

  condition:
    is_dex and all of them
}

rule flutterjailbreakdetection : anti_root
{
  meta:
    description = "Flutter Jailbreak Detection (RootBeer)"
    url         = "https://pub.dev/packages/flutter_jailbreak_detection"
    sample      = "045d548cfd282d1aa8993efd22846ff49b0c48d99590cc36e3cf6c633dd85bcc" // com.swisssign.swissid.mobile
    author      = "Abhi"

  strings:
    $class = { 00 46 4C 61 70 70 6D 69 72 65 2F 62 65 2F 66 6C 75 74 74 65 72 6A 61 69
               6C 62 72 65 61 6B 64 65 74 65 63 74 69 6F 6E 2F 46 6C 75 74 74 65 72 4A
               61 69 6C 62 72 65 61 6B 44 65 74 65 63 74 69 6F 6E 50 6C 75 67 69 6E 3B 00 } // Lappmire/be/flutterjailbreakdetection/FlutterJailbreakDetectionPlugin;

  condition:
    is_dex and all of them
}

rule rootbeer : anti_root
{
  meta:
    description = "RootBeer"
    url         = "https://github.com/scottyab/rootbeer.git"
    sample      = "607ec962ba93cc9817129cb693ff0f335f500a297b5a297e71fbb998d0f6849c" // com.scottyab.rootbeer.sample
    author      = "Abhi"

  strings:
    $class = { 00 20 4C 63 6F 6D 2F 73 63 6F 74 74 79 61 62 2F 72
               6F 6F 74 62 65 65 72 2F 52 6F 6F 74 42 65 65 72 3B 00 } // Lcom/scottyab/rootbeer/RootBeer;

  condition:
    is_dex and all of them
}

rule build38 : protector
{
  meta:
    description = "Build38"
    url         = "https://build38.com"
    sample      = "cfbbfca598a9877a381583a7ae2f9e8cde92e7314b21152658bcba5a4e3a0fff" // com.esignus.hashwalletmanager
    author      = "Abhi, ApkUnpacker"

  strings:
    $class        = { 00 15 4C 63 6F 6D 2F 62 75 69 6C 64 33 38 2F 74 61 6B 2F 54 41 4B 3B 00 } // Lcom/build38/tak/TAK;
    $package_name = { 00 0F 63 6F 6D 2E 62 75 69 6C 64 33 38 2E 74 61 6B 00 } // com.build38.tak
    $module_class = { 00 0D 42 75 69 6C 64 33 38 4D 6F 64 75 6C 65 00 } // Build38Module
    $license_name = { 00 0B 6C 69 63 65 6E 73 65 2E 74 61 6B 00 } // license.tak

  condition:
    is_dex and any of them
}

rule shield_sdk : protector
{
  meta:
    description = "Shield SDK"
    url         = "https://shield.com/"
    sample      = "fb4b7f033658b3898e0448955491b448a2c78e1a2325c65fece6ad64f6f6b6d0" // com.mpl.androidapp
    author      = "Abhi"

  strings:
    $class  = { 00 1B 4C 63 6F 6D 2F 73 68 69 65 6C 64 2F 61 6E 64
                72 6F 69 64 2F 53 68 69 65 6C 64 3B 00 } // Lcom/shield/android/Shield;
    $class2 = { 00 29 4C 63 6F 6D 2F 73 68 69 65 6C 64 2F 61 6E 64
                72 6F 69 64 2F 69 6E 74 65 72 6E 61 6C 2F 4E 61 74
                69 76 65 55 74 69 6C 73 3B 00 } // Lcom/shield/android/internal/NativeUtils;
    $class3 = { 00 27 4C 63 6F 6D 2F 73 68 69 65 6C 64 2F 61 6E 64
                72 6F 69 64 2F 63 6F 6D 6D 6F 6E 2F 42 75 69 6C 64
                43 6F 6E 66 69 67 3B 00 } // Lcom/shield/android/common/BuildConfig;
    $class4 = { 00 28 4C 63 6F 6D 2F 73 68 69 65 6C 64 2F 61 6E 64
                72 6F 69 64 2F 63 6F 6D 6D 6F 6E 2F 53 68 69 65 6C
                64 4D 6F 64 75 6C 65 3B 00 } // Lcom/shield/android/common/ShieldModule;

  condition:
    is_dex and any of them
}

rule bugsmirror : protector
{
  meta:
    description = "BugsMirror"
    url         = "https://www.bugsmirror.com/"
    sample      = "c9bbf66ac86bf02663b7bc28a735881d4aeaa8d90e9b8b752e9cf337a26f0bdd"
    author      = "Abhi"

  strings:
    $tag      = { 00 12 42 75 67 73 6D 69 72 72 6F 72 44 65 66 65 6E
                  64 65 72 00 } // BugsMirrorDefender
    $pkg_name = { 00 16 63 6F 6D 2E 62 75 67 73 6D 69 72 72 6F 72 64
                  65 66 65 6E 64 65 72 00 } // com.bugsmirrordefender
    $service  = { 00 35 42 75 67 73 6D 69 72 72 6F 72 44 65 66 65 6E
                  64 65 72 53 65 72 76 69 63 65 73 2E 42 75 67 73 6D
                  69 72 72 6F 72 44 65 66 65 6E 64 65 72 53 65 72 76
                  69 63 65 73 00 } // BugsmirrorDefenderServices.BugsmirrorDefenderServices
    $filter   = { 00 19 63 6F 6D 2E 62 75 67 73 6D 69 72 72 6F 72 2E
                  6D 69 74 69 67 61 74 69 6F 6E 00 } // com.bugsmirror.mitigation
    $class    = { 00 22 4C 63 6F 6D 2F 62 75 67 73 6D 69 72 72 6F 72
                  2F 64 65 66 65 6E 64 65 72 2F 44 65 66 65 6E 64 65
                  72 3B 00 } // Lcom/bugsmirror/defender/Defender;
    $class2   = { 3B 00 1B 4C 63 6F 6D 2F 62 75 67 73 6D 69 72 72 6F
                  72 2F 64 65 66 65 6E 64 65 72 2F 52 3B 00 } // com/bugsmirror/defender/R;
    $class3   = { 00 24 4C 63 6F 6D 2F 62 75 67 73 6D 69 72 72 6F 72
                  64 65 66 65 6E 64 65 72 2F 42 75 69 6C 64 43 6F 6E
                  66 69 67 3B 00 } // Lcom/bugsmirrordefender/BuildConfig;
    $class4   = { 00 45 4C 63 6F 6D 2F 62 75 67 73 6D 69 72 72 6F 72
                  2F 64 65 66 65 6E 64 65 72 61 70 69 2F 67 65 6E 65
                  72 61 74 65 64 2F 42 75 67 73 6D 69 72 72 6F 72 44
                  65 66 65 6E 64 65 72 53 65 72 76 69 63 65 73 47 72
                  70 63 3B 00 } // Lcom/bugsmirror/defenderapi/generated/BugsmirrorDefenderServicesGrpc;

  condition:
   is_dex and any of them
}

rule bshield : protector
{
  meta:
    description = "BShield"
    url         = "https://bshield.io/"
    sample      = "f54fa5cfcd9a5d14a947bbd93bc7bb59e8c2b1b23cc5bcc84c66ad0143e55201"
    author      = "Abhi"

  strings:
    $dat = { 00 0B 42 53 48 49 45 4C 44 5F 44 41 54 00 } // BSHIELD_DAT

  condition:
    is_dex and all of them
}

rule alibaba_sec : protector
{
  meta:
    description = "Alibaba Security SDK"
    url         = "https://www.alibabacloud.com/zh/product/mpaas"
    sample      = "4590673ad6320d9a091d33e5b3b9b652479ddced573bde9c3ded8acba0451d53"
    author      = "Abhi"

  strings:
    $class = { 00 1D 4C 63 6F 6D 2F 61 6C 69 2F 6D 6F 62 69 73 65
               63 65 6E 68 61 6E 63 65 2F 49 6E 69 74 3B 00 } // Lcom/ali/mobisecenhance/Init;

  condition:
    is_dex and all of them
}

rule bureau : protector
{
  meta:
    description = "Bureau"
    url         = "https://bureau.id"
    sample      = "484d8d0f4eb2c2ed66770edfa0ab89bf76f9b84227faea3889ce74b2af8cbbc4"
    author      = "Abhi, ApkUnpacker"

  strings:
    $string = /api\.(stg\.)?bureau\.id/
    $class  = { 00 28 4C 63 6F 6D 2F 62 75 72 65 61 75 2F 64 65 76 69
                63 65 66 69 6E 67 65 72 70 72 69 6E 74 2F 42 75 72
                65 61 75 41 50 49 3B 00 } // Lcom/bureau/devicefingerprint/BureauAPI;
    $class2 = { 00 25 4C 63 6F 6D 2F 62 75 72 65 61 75 2F 62 61 73
                65 2F 6D 6F 64 65 6C 73 2F 42 75 72 65 61 75 43 6F
                6E 66 69 67 3B 00 } // Lcom/bureau/base/models/BureauConfig;
    $class3 = { 00 21 4C 63 6F 6D 2F 62 75 72 65 61 75 2F 63 68 65 63
                6B 52 6F 6F 74 2F 56 65 72 69 66 79 52 6F 6F 74 3B 00 } // Lcom/bureau/checkRoot/VerifyRoot;

  condition:
    is_dex and any of them
}

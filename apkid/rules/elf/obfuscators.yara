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


import "elf"
include "common.yara"

rule ollvm_v3_4 : obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 3.4"
    url         = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    sample      = "cd16ad33bf203dbaa9add803a7a0740e3727e8e60c316d33206230ae5b985f25"
    author      = "Eduardo Novella"

  strings:
    // "Obfuscator-clang version 3.4 (tags/RELEASE_34/final) (based on LLVM 3.4svn)"
    $clang_version = "Obfuscator-clang version 3.4 "
    $based_on      = "(based on LLVM 3.4"

  condition:
    is_elf and all of them
}

rule ollvm_v3_5 : obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 3.5"
    url         = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    sample      = "664214969f1b94494a8fc0491407f4440032fc5c922eb0664293d0440c52dbe7"
    author      = "Eduardo Novella"

  strings:
    // "Obfuscator- clang version 3.5.0 (tags/RELEASE_350/final) (based on LLVM 3.5.0svn)"
    $clang_version = "Obfuscator- clang version 3.5.0 "
    $based_on      = "(based on LLVM 3.5"

  condition:
    is_elf and all of them
}

rule ollvm_v3_6_1 : obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 3.6.1"
    url         = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    sample      = "d84b45856b5c95f7a6e96ab0461648f22ad29d1c34a8e85588dad3d89f829208"
    author      = "Eduardo Novella"

  strings:
    // "Obfuscator-LLVM clang version 3.6.1 (tags/RELEASE_361/final) (based on Obfuscator-LLVM 3.6.1)"
    $clang_version = "Obfuscator-LLVM clang version 3.6.1 "
    $based_on      = "(based on Obfuscator-LLVM 3.6.1)"

  condition:
    is_elf and all of them
}

rule ollvm_v4_0 : obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 4.0"
    url         = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    sample      = "aaba570388d0fe25df45480ecf894625be7affefaba24695d8c1528b974c00df"
    author      = "Eduardo Novella"

  strings:
    // "Obfuscator-LLVM clang version 4.0.1  (based on Obfuscator-LLVM 4.0.1)"
    $clang_version = "Obfuscator-LLVM clang version 4.0.1 "
    $based_on      = "(based on Obfuscator-LLVM 4.0.1)"

  condition:
    is_elf and all of them
}

rule ollvm_v6_0_strenc : obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 6.0 (string encryption)"
    url         = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    sample      = "f3a2e6c57def9a8b4730965dd66ca0f243689153139758c44718b8c5ef9c1d17"
    author      = "Eduardo Novella"

  strings:
    // "Obfuscator-LLVM clang version 6.0.0 (trunk) (based on Obfuscator-LLVM 6.0.0)"
    // "Obfuscator-LLVM clang version 6.0.0 (trunk) (based on Obfuscator-LLVM 6.0.0git-b9ea5776)"
    $clang_version = "Obfuscator-LLVM clang version 6.0."
    $based_on      = "(based on Obfuscator-LLVM 6.0."

  condition:
    is_elf and
    all of them and
    for any i in (0..elf.symtab_entries): (elf.symtab[i].name matches /\.datadiv_decode[\d]{18,20}/)
}

rule ollvm_v6_0 : obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 6.0"
    url         = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    author      = "Eduardo Novella"

  strings:
    // "Obfuscator-LLVM clang version 6.0.0 (trunk) (based on Obfuscator-LLVM 6.0.0)"
    // "Obfuscator-LLVM clang version 6.0.0 (trunk) (based on Obfuscator-LLVM 6.0.0git-b9ea5776)"
    $clang_version = "Obfuscator-LLVM clang version 6.0."
    $based_on      = "(based on Obfuscator-LLVM 6.0."

  condition:
    is_elf and
    all of them and
    not ollvm_v6_0_strenc
}

rule ollvm_v9_strenc : obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 9.x (string encryption)"
    sample      = "2314ec0053d829d424a82f702188fcb525cefce4feeef096f0855339b897a5d1"
    author      = "Eduardo Novella"

  strings:
    $clang_version = /clang version \d\.\d\.\d /
    $strenc        = /\.datadiv_decode[\d]{18,20}/
    $ollvm         = "(based on Obfuscator-LLVM 9."

  condition:
    is_elf and all of them
}

rule ollvm_tll : obfuscator
{
  meta:
    description = "Obfuscator-LLVM TLL (string encryption)"
    url         = "https://github.com/yazhiwang/ollvm-tll"
    sample      = "1f010330e9ac90f00d11aa37fdca25c437ad6f4b1302f6d7aa48b91ef22cc107"
    author      = "Eduardo Novella"

  strings:
    /**
      .datadiv_decode7760209850571766755
      Android clang version 5.0.300080  (based on LLVM 5.0.300080)
      clang version 6.0.0 (tags/RELEASE_600/final) (https://github.com/yazhiwang/ollvm-tll.git a38559e4c13359073102793c0a734bb1add3d5ff)
    */
    $clang_version = /clang version \d\.\d\.\d \(tags\/RELEASE\_\d+\/final\)/
    $strenc        = /\.datadiv_decode[\d]{18,20}/
    $url           = "https://github.com/yazhiwang/ollvm-tll"

  condition:
    is_elf and all of them
}

rule ollvm_tll_a : obfuscator
{
  meta:
    description = "Obfuscator-LLVM TLL (string encryption)"
    url         = "https://github.com/yazhiwang/ollvm-tll"
    sample      = "0e5992066f177e2495a2a424201e146c29b78b63a9eb94bce6765691a47e6fd7"
    author      = "Eduardo Novella"

  strings:
    /**
      clang version 6.0.0 (tags/RELEASE_600/final) (git@github.com:enovella/ollvm-tll.git a38559e4c13359073102793c0a734bb1add3d5ff)
    */
    $version = /clang version \d+\.\d+\.\d+ \(.*\) \(.*\/ollvm\-tll\.git [0-9a-f]{40}\)/

  condition:
    is_elf and all of them and not ollvm_tll
}

rule ollvm_armariris : obfuscator
{
  meta:
    description = "Armariris Obfuscator-LLVM (string encryption)"
    url         = "https://github.com/GoSSIP-SJTU/Armariris"
    sample      = "d22c2f53bab6fa2ab7bdb4f7acabb419e3ee3163bb758c4f7a013d07a8b09e12" // aka malware Joker
    author      = "Eduardo Novella"

  strings:
    // clang version 3.9.1 (tags/RELEASE_391/final)
    // clang version 5.0.1 (tags/RELEASE_501/final)
    // .datadiv_decode14660921177804423408
    $clang_version = /clang version \d\.\d\.\d \(tags\/RELEASE\_\d+\/final\)/

  condition:
    is_elf and $clang_version and
    not ollvm_tll and
    for any i in (0..elf.symtab_entries): (elf.symtab[i].name matches /\.datadiv_decode[\d]{18,20}/)
}

rule ollvm_strenc : obfuscator
{
  meta:
    description = "Obfuscator-LLVM version unknown (string encryption)"
    sample      = "73f34f7dd5f5c2eff33fc48371c850a2a3ff0355a2bfa014467478ccb30309e3"
    author      = "Eduardo Novella"

  strings:
    $strenc = /\.datadiv_decode[\d]{18,20}/

  condition:
    is_elf and $strenc and
    not ollvm_tll and
    not ollvm_armariris and
    not ollvm_v6_0_strenc and
    not ollvm_v9_strenc
}

rule ollvm : obfuscator
{
  meta:
    description = "Obfuscator-LLVM version unknown"
    url         = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    author      = "Eduardo Novella"

  strings:
    $ollvm1 = "Obfuscator-LLVM "
    $ollvm2 = "Obfuscator-clang "
    $ollvm3 = "Obfuscator- clang "

  condition:
    is_elf and
    ($ollvm1 or $ollvm2 or $ollvm3) and
    not ollvm_v3_4 and
    not ollvm_v3_5 and
    not ollvm_v3_6_1 and
    not ollvm_v4_0 and
    not ollvm_v6_0 and
    not ollvm_v6_0_strenc and
    not ollvm_strenc and
    not ollvm_v9_strenc
}

rule alipay : obfuscator
{
  meta:
    description = "Alipay"
    url         = "https://www.jianshu.com/p/477af178d7d8"
    sample      = "cbfec478f4860cb503ecb28711fe4767a68b7819d9a0c17cf51aaa77e11eb19a"
    author      = "Eduardo Novella"

  strings:
    /**
        __obfuscator_version
        Alipay  Obfuscator (based on LLVM 4.0.1)
        Alipay clang version 4.0.1  (based on LLVM 4.0.1.Alipay.Obfuscator.Trial)
    */
    $a = "Alipay clang version "
    $b = "Alipay  Obfuscator (based on LLVM "
    $c = "Alipay.Obfuscator."

  condition:
    any of them and is_elf
}

rule byteguard_0_9_3 : obfuscator
{
  meta:
    description = "ByteGuard 0.9.3"
    sample      = "eed4f7b907fe2173935d307dfb0d6aa7098f69db8dfb65e49affd7b7a6c0a5e4"
    samples     = "https://koodous.com/rulesets/5862/apks"
    author      = "Eduardo Novella"

  strings:
    // clang version 6.0.0 (Byteguard 0.6) (git@sysrepo.byted.org:dingbaozeng/native_obfuscator.git 448f20ff6eb06dd336dd81846d6a7dc8ba8c961b)
    // Apple LLVM version 6.0.0 (ByteGuard 0.9.3-af515063)
    $version = /(Apple LLVM|clang) version \d+\.\d+\.\d+ \(Byte(G|g)uard(-| )0\.9\.3/

  condition:
    is_elf and all of them
}

rule byteguard_0_9_2 : obfuscator
{
  meta:
    description = "ByteGuard 0.9.2"
    sample      = "178b1ef3c4ac563604c8a262f0e3651f56995768c8aa13ccc845f33bd6eb0ac2"
    samples     = "https://koodous.com/rulesets/5862/apks"
    author      = "Eduardo Novella"

  strings:
    // clang version 5.0.2 (Byteguard-0.9.2-255c7b5e)
    $version = /(Apple LLVM|clang) version \d+\.\d+\.\d+ \(Byte(G|g)uard(-| )0\.9\.2/

  condition:
    is_elf and all of them
}

rule byteguard_unknown : obfuscator
{
  meta:
    description = "ByteGuard unknown version"
    author      = "Eduardo Novella"

  strings:
    $clang_version = /(Apple LLVM|clang) version \d+\.\d+\.\d+ \(Byte(G|g)uard/

  condition:
    is_elf and $clang_version and
    not byteguard_0_9_2 and
    not byteguard_0_9_3
}

rule firehash : obfuscator
{
  meta:
    description = "Firehash"
    url         = "https://firehash.grayhash.com/"
    author      = "Eduardo Novella"

    // original   : https://firehash.grayhash.com/static/sample/dodocrackme_original.apk
    // firehashed : https://firehash.grayhash.com/static/sample/dodocrackme_obfuscated.apk
    sample   = "38e2170a5f272ecae97dddb0dac0c1f39f7f71a4639477764a9154557106dd94"

    // original : 6352f6d0cdc85a42de3ccfd9226dfec28280aa835227acc507043a4403b7e700
    sample2   = "c98af9a777d9633559b7903e21b61b845f7e1766afa74ef85e3380f41265e6b5"

    // original : 727be6789e8f4f6eab66288f957b58800e47a4bacebacc0dd700e8f9a374f116
    sample3   = "423dc9866d1c5f32cabfeb254030d83e11db4d807394a8ff09be47d8bfc38f18"

  strings:
    // Library below heuristic is found inside of is normally named "libaurorabridge.so"
    $segment = ".firehash"
    $opcodes_arm = {
        04 00 2D E5  //  STR     R0, [SP,#var_4]!
        00 00 0F E1  //  MRS     R0, CPSR
        01 00 51 E1  //  CMP     R1, R1
        02 00 00 ?A  //  BNE     loc_F0854
        00 F0 29 E1  //  MSR     CPSR_cf, R0
        04 00 9D E4  //  LDR     R0, [SP+4+var_4],#4
        ?? ?? ?? EA  //  B       loc_F0828
    }

  condition:
    elf.machine == elf.EM_ARM and all of them
}

rule advobfuscator : obfuscator
{
  meta:
    description = "ADVobfuscator"
    url         = "https://github.com/andrivet/ADVobfuscator"
    author      = "Eduardo Novella"
    sample      = "357f0c2ad6bf5cf60c671b090eab134251db63993f52aef512bde5bfa4a1b598"

  strings:
    $s_01 = "_ZNK17ObfuscatedAddressIPFiiiPciS0_S0_EE8originalEv"
    $s_02 = "_ZNK17ObfuscatedAddressIPFiPcEE8originalEv"
    $s_03 = "_ZNK17ObfuscatedAddressIPFvPciEE8originalEv"
    $s_04 = "_ZNK17ObfuscatedAddressIPFvPcS0_EE8originalEv"
    $s_05 = "_ZNK17ObfuscatedAddressIPFvvEE8originalEv"
    $s_06 = "_Z14ObfuscatedCallI17ObfuscatedAddressIPFvvEEJEEvT_DpOT0_"
    $s_07 = "_ZNK17ObfuscatedAddressIPFiPviEE8originalEv"
    $s_08 = "_ZNK17ObfuscatedAddressIPFvPcEE8originalEv"
    $s_09 = "_ZNK17ObfuscatedAddressIPFvP7_JNIEnvEE8originalEv"
    $s_10 = "_ZNK17ObfuscatedAddressIPFvPcS0_iiEE8originalEv"
    $s_11 = "_ZNK17ObfuscatedAddressIPFvcEE8originalEv"
    $s_12 = "_ZNK17ObfuscatedAddressIPFvPviiEE8originalEv"

  condition:
    any of them and is_elf
}

rule arxan_arm32 : obfuscator
{
  meta:
    description = "Arxan"
    url         = "https://www.arxan.com/resources/technology/app-code-obfuscation"
    sample      = "5bbb241d41c4150798b5800e62afcb6f49e05755d2fd89c7a9f7e356609c9012"
    author      = "Eduardo Novella"

  strings:
    // Prolog breakage 1 ARM32
    $a = {
      00 10 90 E5    // LDR R1, [R0]
      00 00 81 E0    // ADD R0, R1, R0
      03 10 00 E0    // AND R1, R0, R3
      02 20 A0 E3    // MOV R2, #2
      92 01 01 E0    // MUL R1, R2, R1
      03 00 20 E0    // EOR R0, R0, R3
      01 00 80 E0    // ADD R0, R0, R1
      00 F0 A0 E1    // MOV PC, R0
    }

    // Prolog breakage 2 Thumb2
    $b = {
      4F F0 01 00    // MOV.W   R0, #1
      02 A1          // ADR     R1, loc_191658
      01 FB 00 F0    // MUL.W   R0, R1, R0
      87 46          // MOV     PC, R0
    }

    // Prolog breakage 3 ARM32
    $c = {
      ?? ?? ?? E?
      91 00 00 E0    // MUL     R0, R1, R0
      00 F0 A0 E1    // MOV     PC, R0
    }

  condition:
    (#a > 5 or #b > 5 or #c > 10) and elf.machine == elf.EM_ARM
}

rule arxan_arm64 : obfuscator
{
  meta:
    description = "Arxan"
    url         = "https://www.arxan.com/resources/technology/app-code-obfuscation"
    sample      = "444ae35cea294ca0268adbddf1c39e8a45fcbb4c967c55f23449cf0d1ae6fce6"
    author      = "Eduardo Novella"

  strings:
    /*
     * Prolog breakage 1 ARM64
     * This is how Arxan breaks the functions in basic blocks' sets making the static reverse engineering task very hard to follow.
     * This is a updated version of the previous Arxan 32bits rule.
     */
    $a = {
      09 01 0? 8A   // AND  X9, X8, X11/X12
      4A 00 80 D2   // MOV  X10, #2
      29 7D 0A 9B   // MUL  X9, X9, X10
      08 01 0? CA   // EOR  X8, X8, X11/X12
      08 01 09 8B   // ADD  X8, X8, X9
      00 01 1F D6   // BR   X8
    }

    $b = {
      28 00 80 D2   // MOV  X8, #1
      69 00 00 10   // ADR  X9, loc_XXX
      28 7D 08 9B   // MUL  X8, X9, X8
      00 01 1F D6   // BR   X8
    }

  condition:
    (#a > 3 or #b > 3) and elf.machine == elf.EM_AARCH64
}

rule alipay : obfuscator
{
  meta:
    description = "Alipay"
    url         = "https://www.jianshu.com/p/477af178d7d8"
    sample      = "cbfec478f4860cb503ecb28711fe4767a68b7819d9a0c17cf51aaa77e11eb19a"
    author      = "Eduardo Novella"

  strings:
    /**
        __obfuscator_version
        Alipay  Obfuscator (based on LLVM 4.0.1)
        Alipay clang version 4.0.1  (based on LLVM 4.0.1.Alipay.Obfuscator.Trial)
    */
    $a = "Alipay clang version "
    $b = "Alipay  Obfuscator (based on LLVM "
    $c = "Alipay.Obfuscator."

  condition:
    any of them and is_elf
}

rule dexguard_native : obfuscator
{
  meta:
    description = "DexGuard"
    url         = "https://www.guardsquare.com/en/products/dexguard"
    sample      = "ad25035a9ff2ccf44535fd0e5c9d3390f9ba2c4cd68ddf2aa69608494c48ea9e"

    strings:
      // "Java_com_guardsquare_dexguard_runtime_detection_HookDetector"
      $hook_detector = {
        00 4A 61 76 61 5F 63 6F 6D 5F 67 75 61 72 64 73 71 75 61 72 65 5F
        64 65 78 67 75 61 72 64 5F 72 75 6E 74 69 6D 65 5F 64 65 74 65 63
        74 69 6F 6E 5F 48 6F 6F 6B 44 65 74 65 63 74 6F 72
      }

    condition:
      is_elf
      and any of them
}

rule dexguard_native_a : obfuscator
{
  meta:
    description = "DexGuard 9.x"
    url         = "https://www.guardsquare.com/en/products/dexguard"
    sample      = "71b11059820c358fb14a0917430e07cf254e15d5b3337471ad172ad5ceccfa2a"
    author      = "Eduardo Novella"

    strings:
      // Library name is libdgrt (probably DexGuard RunTime)
      $libdgrt     = { 006c 6962 6467 7274 2e73 6f00 } // libdgrt.so
      $s_java_o_   = { 00 4a61 7661 5f6f 5f } // Java_o_
      $s_jnionload = { 004a 4e49 5f4f 6e4c 6f61 6400 } // JNI_OnLoad
      $s_basename  = { 00 6261 7365 6e61 6d65 00 }
      $s_mprotect  = { 006d 7072 6f74 6563 7400 }
      $s_dirname   = { 00 6469 726e 616d 6500 }

    condition:
      is_elf
      and $libdgrt
      and 4 of ($s_*)
      and not dexguard_native
}

rule dexguard_native_arm64 : obfuscator
{
  meta:
    description = "DexGuard 9.x"
    url         = "https://www.guardsquare.com/en/products/dexguard"
    sample      = "fc3fae3de64eceab969b7d91e3a5fbc45c7407bb8d1a5d5018caa86947604713"
    author      = "FrenchYeti"

  strings:
    // that is how dexguard detects frida into /proc/%d/maps
    $hook = {
      0b 1d 00 12  //  and        w11,bf,#0xff
      48 15 40 38  //  ldrb       bf,[x10], #0x1
      29 25 1b 53  //  ubfiz      w9,w9,#0x5,#0xa
      29 01 0b 4a  //  eor        w9,w9,w11
      88 ff ff 35  //  cbnz       bf,LAB_00106e44
      e8 c1 86 52  //  mov        bf,#0x360f
      3f 01 08 6b  //  cmp        w9,bf
    }
    // recurring patterns used into several string decryption
    $str = {
      6c 69 69 38  //  ldrb       w12,[x11, x9, LSL ]
      8c ?? ?? 11  //  add        w12,w12,??
      6c 69 29 38  //  strb       w12,[x11, x9, LSL ]
      29 05 00 91  //  add        x9,x9,#0x1
      3f ?? ?? f1  //  cmp        x9,??
      ec 17 9f 1a  //  cset       w12,??
    }
    $str2 = {
      30 ?? cc 9b 10 fe ?? d3 10 a6 0d 9b 6f 69 69 38 d0 69 70 38
      0f 02 0f 4a 6f 69 29 38 29 05 00 91 3f ?? ?? f1 ef 17 9f 1a
    }
    // binaries have always 8 svc instructions
    $svc = {
      ?8 ?? ?? d2  //  mov        x8,??
      01 00 00 d4  //  svc        0x0
      1f 04 40 b1  //  cmn        x0, #0x1, LSL#12
      00 94 80 da  //  cneg       x0, x0, hi
      ?8 ?? ?? 54  //  b.hi       ??
      c0 03 5f d6  //  ret
    }

  condition:
    elf.machine == elf.EM_AARCH64
    and $hook and ($str or $str2) and #svc >= 6
    and not dexguard_native and not dexguard_native_a
}

rule snapprotect : obfuscator
{
  meta:
    description = "SnapProtect"
    url         = "https://www.snapchat.com/"
    sample      = "6dcd634e41304e41b91b49a3c77872a3c7ce28777bab016bd37f79bc7bb08274"
    author      = "Eduardo Novella"

  strings:
    // "clang version 7.0.0 (snap.protect version 2.4.0 - df15518f469ca4749b08/93d2c161df4b9b202bce)"
    $a = /clang version \d\.\d\.\d \(snap.protect version \d\.\d\.\d/
    $b = " (snap.protect version "

  condition:
    is_elf and 1 of ($a,$b)
}

rule safeengine : obfuscator
{
  meta:
    description = "Safeengine LLVM"
    url         = "https://bbs.pediy.com/thread-195327.htm"
    sample      = "93ec9a03b76fa359a7706aed0682003b76bca971e96462540fddad297817049b"
    author      = "horsicq"

  strings:
    // "Safengine clang version 3.8.0 (trunk 608) (based on LLVM 3.8.0svn)"
    //$clang_version = \0"Safengine clang version "
    $clang_version = { 00 53 61 66 65 6e 67 69 6e 65 20 63 6c 61 6e 67 20 76 65 72 73 69 6f 6e 20 }
    $based_on      = "(based on LLVM "

  condition:
    all of them and is_elf
}

rule hikari : obfuscator
{
  meta:
    description = "Hikari"
    sample      = "f6b936ab06ade3de189a0cf11964f77ea3a6ad081cfd8cc4580cc87bcd7dec70"
    url         = "https://github.com/HikariObfuscator/Hikari"
    author      = "Eduardo Novella"

  strings:
    // clang version 8.0.0 (tags/RELEASE_800/final) (https://gitee.com/chenzimo/Hikari.git ecdf30fa1a4635a76c3b528a41eb48d791f4be95)
    $version = /clang version \d+\.\d+\.\d+ \(.*\) \(.*\/Hikari\.git [0-9a-f]{40}\)/

  condition:
    is_elf and all of them
}

rule dexprotector : obfuscator
{
  meta:
    description = "DexProtector"
    url         = "https://dexprotector.com/"
    sample      = "d506e22003798f8b3a3d3c4a1b08af1cbd64667da6f9ed8cf73bc99ded73da44"
    author      = "Eduardo Novella"

  strings:
    // - offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
    // 0x00000000  7f45 4c46 0201 0100 4450 4c46 00e0 0100  .ELF....DPLF....
    // Possibly DPLF stands for "DexProtector Linkable Format"
    $dp_elf_header = { 7f45 4c46 0201 0100 4450 4c46 }

  condition:
    $dp_elf_header at 0
}

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
    all of them
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
    all of them
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
    all of them
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
    all of them
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
    $strenc        = /datadiv_decode[0-9]{18,20}/

  condition:
    all of them
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
    all of them and not ollvm_v6_0_strenc
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
    ($ollvm1 or $ollvm2 or $ollvm3) and
    not ollvm_v3_4 and
    not ollvm_v3_5 and
    not ollvm_v3_6_1 and
    not ollvm_v4_0 and
    not ollvm_v6_0 and
    not ollvm_v6_0_strenc
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

rule avdobfuscator : obfuscator
{
  meta:
    description = "ADVobfuscator"
    url         = "https://github.com/andrivet/ADVobfuscator"
    author      = "Eduardo Novella"
    sample     = "357f0c2ad6bf5cf60c671b090eab134251db63993f52aef512bde5bfa4a1b598"

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

rule arxan_native_arm : obfuscator
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

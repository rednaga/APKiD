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


import "elf"


rule ollvm_v3_4 : obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 3.4"
    url         = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    example     = "cd16ad33bf203dbaa9add803a7a0740e3727e8e60c316d33206230ae5b985f25"

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
    example     = "664214969f1b94494a8fc0491407f4440032fc5c922eb0664293d0440c52dbe7"

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
    example     = "d84b45856b5c95f7a6e96ab0461648f22ad29d1c34a8e85588dad3d89f829208"

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
    example     = "aaba570388d0fe25df45480ecf894625be7affefaba24695d8c1528b974c00df"

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
    example     = "f3a2e6c57def9a8b4730965dd66ca0f243689153139758c44718b8c5ef9c1d17"

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

    // original   : https://firehash.grayhash.com/static/sample/dodocrackme_original.apk
    // firehashed : https://firehash.grayhash.com/static/sample/dodocrackme_obfuscated.apk
    example1   = "38e2170a5f272ecae97dddb0dac0c1f39f7f71a4639477764a9154557106dd94"

    // original : 6352f6d0cdc85a42de3ccfd9226dfec28280aa835227acc507043a4403b7e700
    example2   = "c98af9a777d9633559b7903e21b61b845f7e1766afa74ef85e3380f41265e6b5"

    // original : 727be6789e8f4f6eab66288f957b58800e47a4bacebacc0dd700e8f9a374f116
    example3   = "423dc9866d1c5f32cabfeb254030d83e11db4d807394a8ff09be47d8bfc38f18"

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

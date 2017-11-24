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



rule ollvm_v3_4 : obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 3.4"
    info        = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    example     = "cd16ad33bf203dbaa9add803a7a0740e3727e8e60c316d33206230ae5b985f25"
    // "Obfuscator-clang version 3.4 (tags/RELEASE_34/final) (based on LLVM 3.4svn)"

  strings:
    $clang_version = "Obfuscator-clang version 3.4"
    $based_on      = "(based on LLVM 3.4"

  condition:
    all of them
}


rule ollvm_v3_6_1 : obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 3.6.1"
    info        = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    example     = "d84b45856b5c95f7a6e96ab0461648f22ad29d1c34a8e85588dad3d89f829208"
    // "Obfuscator-LLVM clang version 3.6.1 (tags/RELEASE_361/final) (based on Obfuscator-LLVM 3.6.1)"

  strings:
    $clang_version = "Obfuscator-LLVM clang version 3.6.1"
    $based_on      = "(based on Obfuscator-LLVM 3.6.1)"

  condition:
    all of them
}


rule ollvm_v4_0 : obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 4.x"
    info        = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    example     = "aaba570388d0fe25df45480ecf894625be7affefaba24695d8c1528b974c00df"
    // "Obfuscator-LLVM clang version 4.0.1  (based on Obfuscator-LLVM 4.0.1)"

  strings:
    $clang_version = "Obfuscator-LLVM clang version 4"
    $based_on      = "(based on Obfuscator-LLVM"

  condition:
    all of them
}


rule ollvm_v6_0 : obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 6.x"
    info        = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    example     = ""
    // "Obfuscator-LLVM clang version 6.0.0 (trunk) (based on Obfuscator-LLVM 6.0.0git-b9ea5776)"

  strings:
    $clang_version = "Obfuscator-LLVM clang version 6"
    $based_on      = "(based on Obfuscator-LLVM 6"
    $strenc        = /.datadiv_decode[0-9]{18,20}/

  condition:
    ($clang_version and $based_on) and not $strenc
}

rule ollvm_v6_0_strenc : obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 6.x (string encryption)"
    info        = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    example     = "f3a2e6c57def9a8b4730965dd66ca0f243689153139758c44718b8c5ef9c1d17"
    // "Obfuscator-LLVM clang version 6.0.0 (trunk) (based on Obfuscator-LLVM 6.0.0git-b9ea5776)"

  strings:
    $clang_version = "Obfuscator-LLVM clang version 6"
    $based_on      = "(based on Obfuscator-LLVM 6"
    $strenc        = /.datadiv_decode[0-9]{18,20}/

  condition:
    all of them
}


rule ollvm : obfuscator
{
  meta:
    description = "Obfuscator-LLVM version unknown"
    info        = "https://github.com/obfuscator-llvm/obfuscator/wiki"

  strings:
    $ollvm1 = "Obfuscator-LLVM "
    $ollvm2 = "Obfuscator-clang "

  condition:
    ($ollvm1 or $ollvm2) and
    not ollvm_v3_4 and
    not ollvm_v3_6_1 and
    not ollvm_v4_0 and
    not ollvm_v6_0 and
    not ollvm_v6_0_strenc
}



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
    description = "Obfuscator-LLVM version 3.4 svn"
    info = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    // "Obfuscator-clang version 3.4 (tags/RELEASE_34/final) (based on LLVM 3.4svn)"

  strings:
    $clang_version = "Obfuscator-clang version 3.4"
    $based_on = "(based on LLVM 3.4svn)"

  condition:
    all of them
}

rule ollvm_v3_6_1 : obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 3.6.1"
    info = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    // "Obfuscator-LLVM clang version 3.6.1 (tags/RELEASE_361/final) (based on Obfuscator-LLVM 3.6.1)"

  strings:
    $clang_version = "Obfuscator-LLVM clang version 3.6.1"
    $based_on = "(based on Obfuscator-LLVM 3.6.1)"

  condition:
    all of them
}


rule ollvm_v4_0 : obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 4"
    info = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    // "Obfuscator-LLVM clang version 4.0.1  (based on Obfuscator-LLVM 4.0.1)"

  strings:
    $clang_version = "Obfuscator-LLVM clang version 4"
    $based_on = "(based on Obfuscator-LLVM"

  condition:
    all of them
}


rule ollvm : obfuscator
{
  meta:
    description = "Obfuscator-LLVM"
    info = "https://github.com/obfuscator-llvm/obfuscator/wiki"

  strings:
    $ollvm = "Obfuscator-LLVM"

  condition:
    $ollvm and
    not ollvm_v3_4 and
    not ollvm_v3_6_1 and
    not ollvm_v4_0
}


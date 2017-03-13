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

include "common.yara"

rule pangxie_dex : packer
{
  // sample: ea70a5b3f7996e9bfea2d5d99693195fdb9ce86385b7116fd08be84032d43d2c
  meta:
    description = "PangXie"

  strings:
    // Lcom/merry/wapper/WapperApplication;
    $wrapper = {
      00 24 4C 63 6F 6D 2F 6D 65 72 72 79 2F 77 61 70
      70 65 72 2F 57 61 70 70 65 72 41 70 70 6C 69 63
      61 74 69 6F 6E 3B 00
    }

  condition:
    is_dex and
    $wrapper
}

rule medusah_dex : packer
{
  meta:
    description = "Medusah"

  strings:
    $wrapper = "Lcom/seworks/medusah"

  condition:
    is_dex and $wrapper
}

rule medusah_appsolid_dex : packer
{
  meta:
    description = "Medusah (AppSolid)"

  strings:
    $loader = "Lweb/apache/sax/app;"
    $main_activity = "Lweb/apache/sax/MainActivity;"

  condition:
    is_dex and $loader and $main_activity
}

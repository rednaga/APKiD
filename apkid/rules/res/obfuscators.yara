/*
 * Copyright (C) 2024  RedNaga. https://rednaga.io
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

rule mtprotector_res : protector
{
  meta:
    description = "MT Protector"
    url         = "https://mt2.cn/download/"
    sample      = "462475fb14ef7b979d1102a61d334cffcdcfc24183be37af868d1dc681bc7126"
    author      = "Eduardo Novella"

  strings:
    $sign = {
      0000 0c0c                         // extra bytes
      4d54 5f50 726f 7465 6374 6f72 00  // ..MT_Protector.
    }

  condition:
    is_res and $sign
}

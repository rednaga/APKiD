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

rule whitecryption_elf : protector
{
  // https://github.com/rednaga/APKiD/issues/177
  meta:
    description = "WhiteCryption (elf)"
    sample      = "6821bce73b3d1146ef7ec9a2d91742a7f6fc2f8206ca9354d3d553e1b5d551a7"
    url         = "https://www.intertrust.com/products/application-shielding/"
    author      = "Tim 'diff' Strazzere"

  strings:
    // Currently, it injects the init stub into all classes, so this is a reasonable thing
    // to search for
    $init_stub = "scpClassInit"
    $empty_func = "SCP_EmptyFunction"
    $init_proc_stub = {
        // PUSH {R0-R2,R4,R11,LR}
        17 48 2D E9 
        // BL sub_B500
        58 00 00 EB
        // BX R0
        10 FF 2F E1
    }

  condition:
    is_elf and (($init_stub or $empty_func) or $init_proc_stub)
}
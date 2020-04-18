/*
 * Copyright (C) 2020  RedNaga. https://rednaga.io
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

rule appdome_elf : protector
{
  // https://github.com/rednaga/APKiD/issues/151
  meta:
    description = "Appdome (elf)"
    sample      = "1c6496f1cc8c5799539ee24170c371e8a57547e2eb73c9502c98ff78f44c74cf"
    url         = "https://www.appdome.com/"
    author      = "Tim 'diff' Strazzere"

  strings:
    // Currently these are exported symbols and work across all abi's
    $ad_start = "__start_adinit"
    $ad_stop = "__stop_adinit"
    $hook_start = "__start_hook"
    $hook_stop = "__stop_hook"
    $ipcent_start = "__start_ipcent"
    $ipcent_stop = "__stop_ipcent"


  condition:
    is_elf and (
      ($ad_start and $ad_stop) or
      ($hook_start and $hook_stop) or
      ($ipcent_start and $ipcent_stop)
    )
}

rule virbox_elf : protector
{
  meta:
    description = "Virbox"
    url         = "https://shell.virbox.com"
    sample      = "dcbe15f9f9e44690e200c04a2aefd15107e5beeafb2eab6d07be85b9f0a42435"
    author      = "Eduardo Novella"

  strings:
    $brand = {  5669 7262 6f78 2050 726f 7465 6374 6f72 0000 } // Virbox Protector

  condition:
    is_elf and $brand
}

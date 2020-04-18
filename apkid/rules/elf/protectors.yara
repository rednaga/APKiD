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

rule vkey_elf : protector
{
  meta:
    description = "Vkey (V-OS App Protection)"
    url         = "https://www.v-key.com/products/v-os-app-protection/"
    author      = "Eduardo Novella"
    sample      = "00b745b7c8314c395afa3b01aa24db6e7453c15f19175b7f987988c8b27faa15"

  strings:
    $libname    = "libvosWrapperEx.so"
    $detection1 = "***** FRIDA DETECTED *****"
    $detection2 = "Error creating frida tcp file scan thread"
    $detection3 = "GDB detected!"
    $detection4 = "run_frida_port_scan: reseting map"
    $detection5 = "Error creating emulator detection thread"
    $detection6 = "start_debugger_check"
    $detection7 = "startEmulatorCheck"
    $detection8 = "app_integrity_check_jni: "
    $vos1       = "V-OS.debug"
    $vos2       = "********** V-Key %s: V-OS Firmware Version %d.%d.%d.%d *********"
    $vos3       = "********** V-Key %s: V-OS Firmware (%s) Version %d.%d.%d.%d ****"
    $vos4       = "********** V-Key Release SDK: V-OS Processor"
    $jni1       = "Java_vkey_android_vos_VosWrapper_"
    $jni2       = "Java_vkey_android_vos_VosWrapper_initVOSJNI"
    $jni3       = "Java_vkey_android_vos_VosWrapper_getVADefaultPath"
    $jni4       = "Java_vkey_android_vos_VosWrapper_registerCallback"
    $jni5       = "Java_vkey_android_vos_VosWrapper_setVADefaultPath"

  condition:
    is_elf and $libname and 1 of ($vos*) and 1 of ($detection*) and 1 of ($jni*)
}

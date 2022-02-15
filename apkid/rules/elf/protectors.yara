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

rule whitecryption_elf : protector
{
  // https://github.com/rednaga/APKiD/issues/177
  meta:
    description = "WhiteCryption"
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

rule whitecryption_elf_a : protector
{
  meta:
    description = "WhiteCryption"
    sample      = "a9926158f16d57072940c001a5ef06e4bf600f98d9ca9daeec202f71caa3d7b2"
    url         = "https://www.intertrust.com/products/application-shielding/"
    author      = "Eduardo Novella"

  strings:
    $wcskbox = "whiteCryptionSecureKeyBox"
    $jni     = "Java_com_whitecryption_skb_"
    $libname = "libSecureKeyBoxJava.so"

  condition:
    is_elf and 1 of them
}

rule appdome_elf : protector
{
  // https://github.com/rednaga/APKiD/issues/151
  meta:
    description = "Appdome"
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

rule metafortress : protector
{
  meta:
    description = "InsideSecure MetaFortress"
    url         = "https://www.insidesecure.com/Products/Application-Protection/Software-Protection/Code-Protection"
    sample      = "326632f52eba45609f825ab6746037f2f2b47bfe66fd1aeebd835c8031f4fdb0"
    author      = "Eduardo Novella"

  strings:
    $a = { 00 4d65 7461 466f 7274 7265 7373 3a20 2573 0025 733a 2025 730a 00 } // MetaFortress %s.%s: %s
    $b = { 00 4d65 7461 466f 7274 7265 7373 00 } // MetaFortress
    $c = { 00 4d45 5441 464f 5249 4300 0000 0000 0000 } // "METAFORIC"
    $d = { 00 4a61 7661 5f63 6f6d 5f69 6e73 6964 6573 6563 7572 655f 6863 655f } // Java_com_insidesecure_hce_internal_MatrixHCENativeBridge_

  condition:
    is_elf and (($a and $b) or $c or $d)
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

rule verimatrix_arm64 : protector
{
  meta:
    description = "InsideSecure Verymatrix"
    url         = "https://www.verimatrix.com/products/app-shield/"
    sample      = "105a2646e8acf45afcd606f4d47af68a8218e0ae7d8c9646d0048cbf32df7a73"
    author      = "FrenchYeti"
    
  strings:
    // byte sequence from .data, used into JNI_OnLoad
    $seq = {
      ?? ?? ?? ?? 88 98 a8 b8
      ?? ?? ?? ?? 94 a4 b4 c4
      ?? ?? ?? ?? 88 98 a8 b8
      ?? ?? ?? ?? 94 a4 b4 c4
    }
    
    $comm1 =  "Android (7019983 based on r365631c3) clang version 9.0.9 (https://android.googlesource.com/toolchain/llvm-project a2a1e703c0edb03ba29944e529ccbf457742737b) (based on LLVM 9.0.9svn)"
    $comm2 = "GCC: (GNU) 4.9.x 20150123 (prerelease)"
    
    // common pattern
    $instr = {
      ?3 ?? ?? 54 //  b.cc    ??
      29 0d ?0 12 //  and     w9, w9, #0xf
      49 21 c9 1a //  lsl     w9, w10, w9
      ea 03 09 cb //  neg     x10, x9
      ?a 0? ?? 8a //  and     x10, ??, ??
      5f 01 ?? eb //  cmp     x10, ??
      9f 3b 03 d5 //  dsb     ISH
      ?2 ?? ?? 54 //  b.cs    ??
      2a 75 0b d5 //  ic      x10
      4a 01 09 8b //  add     x10, x10, x9
      5f 01 ?? eb //  cmp     x10, ??
      ?3 ?? ?? 54 //  b.cc    ??
      [0-4]
      df 3f 03 d5 //  isb
    }
  
  condition:
    ELF is Aarch64 and all of them
}

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
    description = "InsideSecure Verimatrix"
    url         = "https://www.verimatrix.com/products/app-shield/"
    sample      = "88cb73fbc7371a7ef0ef0efc99c0fcaf129d5fc21bfca8bb5c318dff8f227fcc" // Package: com.bcp.bank.bcp v3.0.4
    author      = "Eduardo Novella"

  strings:
    // Potential crash via division by zero
    // Sample contains ~500 break instructions  (other sample ~80)
    $brk_0_3e8 = {
      00 7D 20 D4   // BRK  #0x3E8
    }

    // Inlined syscall with obfuscated _NR_SYSCALL
    // Payment HCE app sample contains 2.6k inlined syscalls (other sample ~150)
    $svc_0 = {
      01 00 00 D4   // SVC  0
    }

  condition:
    elf.machine == elf.EM_AARCH64
    and #svc_0 >= 50
    and #brk_0_3e8 >= 50
    and for any i in (0..elf.number_of_segments): (elf.segments[i].type == elf.PT_LOAD)
}

rule verimatrix_arm64_a : protector
{
  meta:
    description = "InsideSecure Verimatrix"
    url         = "https://www.verimatrix.com/products/app-shield/"
    sample      = "edb939d77adba5ef5c536c352a4bc25a3a5ff2fe15408c5af9f08b5af583224c" // dk.mitid.app.android v2.3.7
    author      = "Eduardo Novella"

  strings:
    /**
      .mfrt:0000000000AFCC98             ; Segment type: Pure data
      .mfrt:0000000000AFCC98                             AREA .mfrt, DATA
      .mfrt:0000000000AFCC98                             ; ORG 0xAFCC98
      .mfrt:0000000000AFCC98 04 EC 82 5F+                DCQ 0x4BDB66335F82EC04
      .mfrt:0000000000AFCCA0 FA 45 E6 0C                 DCD 0xCE645FA
      .mfrt:0000000000AFCCA0             ; .mfrt         ends
    */

    // Sample contains 25 inlined syscalls
    $svc_0 = {
      01 00 00 D4   // SVC  0
    }

    /**
      do
        {
          __asm { SYS             #3, c7, c11, #1, X12 }
          i += c;
        }
        while ( i < len );
      }
      v30 = (unsigned int)(4 << (StatusReg & 0xF));
      v31 = v3 & -v30;
      __dsb(0xBu);
      for ( ; v31 < len; v31 += v30 )
        __asm { SYS             #3, c7, c5, #1, X10 }
      __isb(0xFu);
      ret = ((__int64 (__fastcall *)(_QWORD *))v3)(v33);
      linux_eabi_syscall(__NR_munmap, (void *)v3, 0x4000u);
    */
    $asm_sys_dsb_isb = {
      2C 7B 0B D5   // SYS #3, c7, c11, #1, X12
      [12-64]
      9F 3B 03 D5   // DSB ISH
      [0-4]
      2A 75 0B D5   // SYS #3, c7, c5, #1, X10
      [12-64]
      DF 3F 03 D5   // ISB
    }

    // "libsdfgebg.so"
    $libname = /lib[a-z]{6,14}\.so/

  condition:
    elf.machine == elf.EM_AARCH64
    and $asm_sys_dsb_isb
    and $libname
    and #svc_0 >= 15
    and for any i in (0..elf.number_of_segments): (elf.segments[i].type == elf.PT_LOAD)
    and for any i in (0..elf.number_of_sections): (elf.sections[i].name matches /\.mfrt/)
}

rule verimatrix_arm64_b : protector
{
  meta:
    description = "InsideSecure Verimatrix"
    url         = "https://www.verimatrix.com/products/app-shield/"
    sample      = "41aab8bad66ab3ee47d8133488084e87abd271e2865d5715fb36269d967a2571"
    author      = "FrenchYeti"

  strings:
    // byte sequence from .rodata, used into JNI_OnLoad
    /**
      void sub_AD1468()
        {
          _QWORD v0[2]; // [xsp+40h] [xbp-A1480h] BYREF
          int v1; // [xsp+50h] [xbp-A1470h]
          int v2; // [xsp+54h] [xbp-A146Ch]
          _QWORD v3[2]; // [xsp+60h] [xbp-A1460h] BYREF
          __int64 v4; // [xsp+70h] [xbp-A1450h]
          _QWORD v5[2]; // [xsp+80h] [xbp-A1440h] BYREF
          int v6; // [xsp+90h] [xbp-A1430h]
          int v7; // [xsp+94h] [xbp-A142Ch]
          char v8[660496]; // [xsp+A8h] [xbp-A1418h] BYREF
          __int64 v9; // [xsp+A14B8h] [xbp-8h]

          v9 = *(_QWORD *)(_ReadStatusReg(ARM64_SYSREG(3, 3, 13, 0, 2)) + 40);
          v5[1] = v5;
          v7 = 0xB8A89888;
          v5[0] = v5;
          v4 = 0xB8A89888BCAC9C8BLL;
          v3[0] = v3;
          v3[1] = v3;
          v0[0] = v3;
          v0[1] = v0;
          v2 = 0xB8A89888;
          v6 = 1;
          v1 = 0;
          sub_ADCB58(v8, 0LL, 0xA1410LL);
          LODWORD(v4) = 1;
          JUMPOUT(0xAD1524LL);
        }
    */
    $rodata_pattern = {
      ?? ?? ?? ?? 88 98 a8 b8
      ?? ?? ?? ?? 94 a4 b4 c4
      ?? ?? ?? ?? 88 98 a8 b8
      ?? ?? ?? ?? 94 a4 b4 c4
    }

    // common pattern
    $opcodes = {
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
    elf.machine == elf.EM_AARCH64
    and all of them
    and not verimatrix_arm64_a
}

rule protectt : protector
{
  meta:
    description = "Protectt"
    sample      = "c246d85560599f91e9c3ed7e59df2dd4e21aaf667f3f2965c28c43d9842f5e75" // com.rblbank.mobank
    url         = "https://www.protectt.ai"
    author      = "Eduardo Novella"

  strings:
    $lib1 = "libprotectt-native-lib.so"
    $lib2 = "libprotecttai.so"
    $lib3 = "libapp-protectt-native-lib.so"

  condition:
    is_elf and 1 of them
}

rule googleIntegrityProtection : protector
{
  meta:
    description = "Google Play Integrity"
    url         = "https://developer.android.com/games/playgames/integrity"
    sample      = "607e256868c012dda10aaff07fdd24928d86122c715078406fb21aae7a2b8a44"
    author      = "Eduardo Novella"

    strings:
      $export_jnionload      = { 004a 4e49 5f4f 6e4c 6f61 6400 } // JNI_OnLoad
      $export_jnionunload    = { 004a 4e49 5f4f 6e55 6e6c 6f61 6400 } // JNI_OnUnLoad
      $export_ExecuteProgram = { 00  4578 6563 7574 6550 726f 6772 616d 00  } // ExecuteProgram
      $lib_name              = { 00 6c69 6270 6169 7269 7063 6f72  652e 736f 00} // libpairipcore.so

    condition:
      is_elf and all of them
}


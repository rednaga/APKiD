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
include "../apk/packers.yara"

private rule upx_elf32_arm_stub : packer
{
  meta:
    description = "Contains a UPX ARM stub"

  strings:
    $UPX_STUB = { 1E 20 A0 E3 14 10 8F E2 02 00 A0 E3 04 70 A0 E3 00 00 00 EF 7F 00 A0 E3 01 70 A0 E3 00 00 00 EF }

  condition:
    elf.machine == elf.EM_ARM and $UPX_STUB
}

private rule upx_stub : packer
{
  meta:
    description = "Contains a UPX stub"

  condition:
    upx_elf32_arm_stub
}

private rule upx_unmodified : packer
{
  meta:
    description = "Contains an unmodified UPX stub"

  strings:
    $upx = "UPX!"

  condition:
    $upx in (0..200) and $upx in (filesize - 50 .. filesize) and upx_elf32_arm_stub
}

rule upx_sharedlib_unmodifed : packer
{
  meta:
    description = "sharelib UPX"

  strings:
    $upx = "UPX!"

  condition:
    elf.type == elf.ET_DYN
    and $upx in (filesize - 50 .. filesize) and upx_stub
}

rule upx_elf_3_94 : packer
{
  meta:
    description = "UPX 3.94 (unmodified)"

  strings:
    $copyright = "UPX 3.94 Copyright"

  condition:
    upx_unmodified and $copyright
}

rule upx_elf_3_93 : packer
{
  meta:
    description = "UPX 3.93 (unmodified)"

  strings:
    $copyright = "UPX 3.93 Copyright"

  condition:
    upx_unmodified and $copyright
}

// Fixes included for Android shared libs
rule upx_elf_3_92 : packer
{
  meta:
    description = "UPX 3.92 (unmodified)"

  strings:
    $copyright = "UPX 3.92 Copyright"

  condition:
    upx_unmodified and $copyright
}

rule upx_elf_3_91 : packer
{
  meta:
    description = "UPX 3.91 (unmodified)"

  strings:
    $copyright = "UPX 3.91 Copyright"

  condition:
    upx_unmodified and $copyright
}

rule upx_elf_3_09 : packer
{
  meta:
    description = "UPX 3.09 (unmodified)"

    strings:
	  $copyright = "UPX 3.09 Copyright"

    condition:
      upx_unmodified and $copyright
}

rule upx_elf_3_08 : packer
{
  meta:
    description = "UPX 3.08 (unmodified)"

  strings:
    $copyright = "UPX 3.08 Copyright"

  condition:
    upx_unmodified and $copyright
}

rule upx_elf_3_07 : packer
{
  meta:
    description = "UPX 3.07 (unmodified)"

  strings:
    $copyright = "UPX 3.07 Copyright"

  condition:
    upx_unmodified and $copyright
}

rule upx_elf_3_04 : packer
{
  meta:
    description = "UPX 3.04 (unmodified)"

  strings:
    $copyright = "UPX 3.04 Copyright"

  condition:
    upx_unmodified and $copyright
}

rule upx_elf_3_03 : packer
{
  meta:
    description = "UPX 3.03 (unmodified)"

  strings:
    $copyright = "UPX 3.03 Copyright"

  condition:
	upx_unmodified and $copyright
}

rule upx_elf_3_02 : packer
{
  meta:
    description = "UPX 3.02 (unmodified)"

  strings:
    $copyright = "UPX 3.02 Copyright"

  condition:
    upx_unmodified and $copyright
}

rule upx_elf_3_01 : packer
{
  meta:
    description = "UPX 3.01 (unmodified)"

  strings:
    $copyright = "UPX 3.01 Copyright"

  condition:
    upx_unmodified and $copyright
}

rule upx_elf_bangcle_secneo : packer
{
  meta:
    description = "Bangcle/SecNeo (UPX)"

  strings:
    // They replace UPX! with SEC!
    $sec = "SEC!"

  condition:
    $sec in (0..200) and $sec in (filesize - 50 .. filesize) and upx_stub
}

rule upx_elf_bangcle_secneo_newer : packer
{
  meta:
    description = "newer-style Bangcle/SecNeo (UPX)"

  strings:
    // They replace UPX! with \x03\x02\x01\x00
    $TTO = { 03 02 01 00 }

  condition:
    $TTO in (filesize - 50 .. filesize) and upx_stub
}

rule upx_elf_ijiami : packer
{
  meta:
    description = "Ijiami (UPX)"

  strings:
    // They replace UPX! with AJM!
    $ajm = "AJM!"

  condition:
    $ajm in (filesize - 50 .. filesize) and upx_stub
}

private rule upx_unknown_version : packer
{
  meta:
    description = "UPX (unknown)"

  condition:
    upx_stub
    // We could extend this for more comprehensive rules, however lower versions than this should not be
    // appears on arm/android devices
    and not (upx_elf_3_01 or upx_elf_3_02 or upx_elf_3_03 or upx_elf_3_04 or upx_elf_3_07 or upx_elf_3_08 or upx_elf_3_09 or upx_elf_3_91 or upx_elf_3_92 or upx_elf_3_93 or upx_elf_3_94)
    and not (upx_elf_ijiami or upx_elf_bangcle_secneo or upx_elf_bangcle_secneo_newer)
}

rule upx_embedded_inside_elf : packer dropper
{
  meta:
    description = "UPX packed ELF embedded in ELF"

  strings:
    $elf_magic = { 7F 45 4C 46 }

  condition:
    $elf_magic at 0 and $elf_magic in (256..filesize)
    and upx_unknown_version
    and not upx_unmodified
    and not upx_sharedlib_unmodifed
}

rule upx_unknown_version_modified : packer
{
  meta:
    description = "UPX (unknown, modified)"

  condition:
    upx_unknown_version
    and not is_apk
    and not upx_unmodified
    and not bangcle
    and not upx_elf_bangcle_secneo
    and not upx_elf_bangcle_secneo_newer
    and not upx_elf_ijiami
    and not ijiami
    and not upx_sharedlib_unmodifed
    and not upx_embedded_inside_elf
}

rule upx_compressed_apk : packer embedded
{
  meta:
    description = "UPX packed ELF embedded in APK"

  condition:
    upx_unknown_version and
    is_apk and
    not (upx_unmodified or ijiami or bangcle or jiagu)
}

rule upx_unknown_version_unmodified : packer
{
  meta:
    description = "UPX (unknown, unmodified)"

  condition:
    upx_unknown_version and
    upx_unmodified and
    not upx_compressed_apk
}

rule promon : packer
{
  meta:
    description = "Promon Shield"
    url         = "https://promon.co/"
    sample      = "6a3352f54d9f5199e4bf39687224e58df642d1d91f1d32b069acd4394a0c4fe0"

  strings:
    $a = "libshield.so"
    $b = "deflate"
    $c = "inflateInit2"
    $d = "crc32"

    $s1 = /.ncc/  // Code segment
    $s2 = /.ncd/  // Data segment
    $s3 = /.ncu/  // Another segment

  condition:
    ($a and $b and $c and $d) and
    2 of ($s*)
}

rule appsealing_core_2_10_10 : packer
{
  meta:
    description = "AppSealing CORE VERSION 2.10.10"
    url         = "https://www.appsealing.com/"
    sample      = "61a983b032aee2e56159e682ad1588ad30fa8c3957bf849d1afe6f10e1d9645d"
    author      = "zeroload"

  strings:
    $core_ver = "APPSEALING-CORE-VERSION_2.10.10"

  condition:
    $core_ver
}

rule tencent_elf : packer
{
  meta:
    description = "Mobile Tencent Protect"
    url         = "https://intl.cloud.tencent.com/product/mtp"
    sample      = "7c6024abc61b184ddcc9fa49f9fac1a7e5568d1eab09ee748f8c4987844a3f81"

  strings:
    // getenv liblog.so libz.so libdl.so libc.so libshell.so
    $libs = {
      00 67 65 74 65 6E 76 00 6C 69 62 6C 6F 67 2E 73 6F 00 6C 69 62 7A 2E
      73 6F 00 6C 69 62 64 6C 2E 73 6F 00 6C 69 62 63 2E 73 6F 00 6C 69 62
      73 68 65 6C 6C 2E 73 6F 00
    }

  condition:
    is_elf
    and any of them
}

rule crackproof : packer
{
  meta:
    description = "CrackProof"
    url         = "https://www.hypertech.co.jp/eng/"
    sample      = "312243d9133ced054a850fa933d1f62adb717a232b79469ab2f58be77c9377a4"
    samples     = "https://koodous.com/rulesets/5244/apks"
    author      = "Eduardo Novella"

  strings:
    /**
      int __fastcall j_do_asm_syscall(int svc_nr, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7)
      {
        int r; // r0

        r = do_asm_syscall(a2, a3, a4, a5, a6, a7, 0, svc_nr);
        return sub_4D78C(svc_nr, r);
      }
    */
    $j_do_asm_syscall = {
      00 48 2D E9 //   PUSH {R11,LR}
      04 B0 8D E2 //   ADD  R11, SP, #4
      28 D0 4D E2 //   SUB  SP, SP, #0x28
      10 00 0B E5 //   STR  R0, [R11,#var_10]
      14 10 0B E5 //   STR  R1, [R11,#a1]
      18 20 0B E5 //   STR  R2, [R11,#a2]
      1C 30 0B E5 //   STR  R3, [R11,#a3]
      00 30 A0 E3 //   MOV  R3, #0
      08 30 0B E5 //   STR  R3, [R11,#r]
      08 30 9B E5 //   LDR  R3, [R11,#a6]
      00 30 8D E5 //   STR  R3, [SP,#0x2C+var_2C] ; a5
      0C 30 9B E5 //   LDR  R3, [R11,#a7]
      04 30 8D E5 //   STR  R3, [SP,#0x2C+var_28] ; a6
      00 30 A0 E3 //   MOV  R3, #0
      08 30 8D E5 //   STR  R3, [SP,#0x2C+var_24] ; a7
      10 30 1B E5 //   LDR  R3, [R11,#var_10]
      0C 30 8D E5 //   STR  R3, [SP,#0x2C+svc_nr] ; svc_nr
      14 00 1B E5 //   LDR  R0, [R11,#a1] ; a1
      18 10 1B E5 //   LDR  R1, [R11,#a2] ; a2
      1C 20 1B E5 //   LDR  R2, [R11,#a3] ; a3
      04 30 9B E5 //   LDR  R3, [R11,#a5] ; a4
      ?? ?? ?? EB //   BL   do_asm_syscall
      00 30 A0 E1 //   MOV  R3, R0
      08 30 0B E5 //   STR  R3, [R11,#r]
      08 30 1B E5 //   LDR  R3, [R11,#r]
      10 00 1B E5 //   LDR  R0, [R11,#var_10] ; svc_nr
      03 10 A0 E1 //   MOV  R1, R3  ; r
      ?? ?? ?? EB //   BL   sub_4D78C
      00 30 A0 E1 //   MOV  R3, R0
      08 30 0B E5 //   STR  R3, [R11,#r]
      08 30 1B E5 //   LDR  R3, [R11,#r]
      03 00 A0 E1 //   MOV  R0, R3
      04 D0 4B E2 //   SUB  SP, R11, #4
      00 88 BD E8 //   POP  {R11,PC}
    }

    /**
      int __fastcall do_asm_syscall(void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, int svc_nr)
      {
        return linux_eabi_syscall(svc_nr, a1, a2, a3, a4, a5, a6, a7);
      }
    */
    $do_asm_syscall = {
      FE 4F 2D E9  //  PUSH  {R1-R11,LR}
      2C B0 8D E2  //  ADD   R11, SP, #0x2C
      04 40 9B E5  //  LDR   R4, [R11,#a5]
      08 50 9B E5  //  LDR   R5, [R11,#a6]
      0C 60 9B E5  //  LDR   R6, [R11,#a7]
      10 70 9B E5  //  LDR   R7, [R11,#svc_nr]
      00 00 00 EF  //  SVC   0
      FE 8F BD E8  //  POP   {R1-R11,PC}
    }

  condition:
    is_elf and all of them
}

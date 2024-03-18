/*
 * Copyright (C) 2023  RedNaga. https://rednaga.io
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

rule upx_elf_joker : packer
{
  meta:
    description = "Joker (UPX)"
    sample = "2de03bc5fc110a3bb2e6f4d6d6e558052b5cae3cb117a1a8c2be08576be0ed58"

  strings:
    // They replace UPX! with ZHSH or TIW°
    $rename1 = "ZHSH"
    // TIW°
    $rename2 = { 54 49 57 B0 }

  condition:
    ($rename1 in (filesize - 50 .. filesize)) or
    ($rename2 in (filesize - 50 .. filesize))
     and upx_stub
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
    and not (upx_elf_ijiami or upx_elf_joker or upx_elf_bangcle_secneo or upx_elf_bangcle_secneo_newer)
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
    and not upx_elf_joker
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
    sample2     = "0ef06e0b1511872e711cf3e8e53fee097d13755c9572cfea6d153d708906f45d"
    author      = "Eduardo Novella"

  strings:
    // Library names
    $libshield   = "libshield.so"
    $rnd_libname = /lib[a-z]{10,12}\.so/ // libchhjkikihfch.so || libgiompappkhnb.so

    /**
     Odd ELF segments found:
      .ncc -> Code segment
      .ncd -> Data segment
      .ncu -> Another segment
    */

  condition:
    is_elf and ($libshield or $rnd_libname) and
    (   // Match at least two section names from .ncu, .ncc, .ncd
        (for any i in (0..elf.number_of_sections): (elf.sections[i].name matches /\.ncu/)
            and for any i in (0..elf.number_of_sections): (elf.sections[i].name matches /\.ncc/))  or
        (for any i in (0..elf.number_of_sections): (elf.sections[i].name matches /\.ncu/)
            and for any i in (0..elf.number_of_sections): (elf.sections[i].name matches /\.ncd/))  or
        (for any i in (0..elf.number_of_sections): (elf.sections[i].name matches /\.ncc/)
            and for any i in (0..elf.number_of_sections): (elf.sections[i].name matches /\.ncd/))
    )
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

rule appsuit_packer_a : packer
{
  meta:
    description = "AppSuit"
    url         = "http://www.stealien.com/appsuit.html"
    sample      = "3bcb66444b43d1a225ac2dd59387b8aa2ce921b0595708d65753eef6b0ef2165"
    author      = "Eduardo Novella"

  strings:
    $native_lib1 = { 00 6c6962417070537569742e736f   00 } // \0libAppSuit.so\0
    $native_lib2 = { 00 6c6962556e7061636b65722e736f 00 } // \0libUnpacker.so\0

  condition:
    is_elf and all of them
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

rule crackproof_a : packer
{
  meta:
    description = "CrackProof"
    url         = "https://www.hypertech.co.jp/eng/"
    sample      = "a296f4c1d48b830bb26c6ca7f2889e47756fb4adf0dd86d193a8b60d3bc4ae7d"
    author      = "Eduardo Novella"

  strings:
    /**
      __int64 __usercall init_proc@<X0>(a1@<X1>,  a2@<X2>,  a3@<X3>,  a4@<X4>,  a5@<X5>,  a6@<X6>,  a7@<X7>,  a8@<X8>)
      {
        __int64 v9[30]; // [xsp+0h] [xbp-F0h] BYREF

        v9[28] = a1;
        v9[29] = a2;
        v9[26] = a3;
        v9[27] = a4;
        v9[24] = a5;
        v9[25] = a6;
        v9[22] = a7;
        v9[23] = a8;
        return sub_7F4(v9);
      }
    */
    $init_proc = {
      E1 0B BF A9  //  STP  X1, X2, [SP,#var_10]!
      E3 13 BF A9  //  STP  X3, X4, [SP,#0x10+var_20]!
      E5 1B BF A9  //  STP  X5, X6, [SP,#0x20+var_30]!
      E7 23 BF A9  //  STP  X7, X8, [SP,#0x30+var_40]!
      E9 2B BF A9  //  STP  X9, X10, [SP,#0x40+var_50]!
      EB 33 BF A9  //  STP  X11, X12, [SP,#0x50+var_60]!
      ED 3B BF A9  //  STP  X13, X14, [SP,#0x60+var_70]!
      EF 43 BF A9  //  STP  X15, X16, [SP,#0x70+var_80]!
      F1 4B BF A9  //  STP  X17, X18, [SP,#0x80+var_90]!
      F3 53 BF A9  //  STP  X19, X20, [SP,#0x90+var_A0]!
      F5 5B BF A9  //  STP  X21, X22, [SP,#0xA0+var_B0]!
      F7 63 BF A9  //  STP  X23, X24, [SP,#0xB0+var_C0]!
      F9 6B BF A9  //  STP  X25, X26, [SP,#0xC0+var_D0]!
      FB 73 BF A9  //  STP  X27, X28, [SP,#0xD0+var_E0]!
      FD 7B BF A9  //  STP  X29, X30, [SP,#0xE0+var_F0]!
      E0 03 00 91  //  MOV  X0, SP
      ?? ?? ?? 97  //  BL   sub_7F4
      FD 7B C1 A8  //  LDP  X29, X30, [SP+0xF0+var_F0],#0x10
      FB 73 C1 A8  //  LDP  X27, X28, [SP+0xE0+var_E0],#0x10
      F9 6B C1 A8  //  LDP  X25, X26, [SP+0xD0+var_D0],#0x10
      F7 63 C1 A8  //  LDP  X23, X24, [SP+0xC0+var_C0],#0x10
      F5 5B C1 A8  //  LDP  X21, X22, [SP+0xB0+var_B0],#0x10
      F3 53 C1 A8  //  LDP  X19, X20, [SP+0xA0+var_A0],#0x10
      F1 4B C1 A8  //  LDP  X17, X18, [SP+0x90+var_90],#0x10
      EF 43 C1 A8  //  LDP  X15, X16, [SP+0x80+var_80],#0x10
      ED 3B C1 A8  //  LDP  X13, X14, [SP+0x70+var_70],#0x10
      EB 33 C1 A8  //  LDP  X11, X12, [SP+0x60+var_60],#0x10
      E9 2B C1 A8  //  LDP  X9, X10, [SP+0x50+var_50],#0x10
      E7 23 C1 A8  //  LDP  X7, X8, [SP+0x40+var_40],#0x10
      E5 1B C1 A8  //  LDP  X5, X6, [SP+0x30+var_30],#0x10
      E3 13 C1 A8  //  LDP  X3, X4, [SP+0x20+var_20],#0x10
      E1 0B C1 A8  //  LDP  X1, X2, [SP+0x10+var_10],#0x10
      C0 03 5F D6  //  RET
    }

    /**
      signed __int64 __fastcall do_asm_syscall(void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, signed __int64 svc_nr)
      {
        return linux_eabi_syscall(svc_nr, a1, a2, a3, a4, a5, a6, a7);
      }
    */
    $do_asm_syscall = {
      E1 0B BF A9  //  STP  X1, X2, [SP,#var_10]!
      E3 13 BF A9  //  STP  X3, X4, [SP,#0x10+var_20]!
      E5 1B BF A9  //  STP  X5, X6, [SP,#0x20+var_30]!
      E7 23 BF A9  //  STP  X7, X8, [SP,#0x30+var_40]!
      E9 7B BF A9  //  STP  X9, X30, [SP,#0x40+var_50]!
      E8 03 07 AA  //  MOV  X8, X7
      01 00 00 D4  //  SVC  0
      E9 7B C1 A8  //  LDP  X9, X30, [SP+0x50+var_50],#0x10
      E7 23 C1 A8  //  LDP  X7, X8, [SP+0x40+var_40],#0x10
      E5 1B C1 A8  //  LDP  X5, X6, [SP+0x30+var_30],#0x10
      E3 13 C1 A8  //  LDP  X3, X4, [SP+0x20+var_20],#0x10
      E1 0B C1 A8  //  LDP  X1, X2, [SP+0x10+var_10],#0x10
      C0 03 5F D6  //  RET
    }

    /**
      v25 = j_asm_syscall(SYS_mprotect, v32, v29[6], 7LL, 0LL, 0LL, 0LL);
      if ( v34 != 1 )
      {
          v10 = sub_4309D80();
          v11 = -v25;
          v12 = sub_430D114(v17);
          v34 = sub_430E87C(0LL, 0LL, v10, 1LL, 181, 1LL, 5LL, v11, v17, v12);
      }
    */
    $func1 = {
      E2 03 00 2A  //  MOV             W2, W0
      E3 7F 94 B9  //  LDRSW           X3, [SP,#0x14C0+var_44]
      40 1C 80 D2  //  MOV             X0, #0xE2
      04 00 80 D2  //  MOV             X4, #0
      05 00 80 D2  //  MOV             X5, #0
      06 00 80 D2  //  MOV             X6, #0
      ?? ?? ?? 94  //  BL              j_asm_syscall
    }
    $func2 = {
      00 00 80 D2  //  MOV  X0, #0
      01 00 80 D2  //  MOV  X1, #0
      E2 03 14 2A  //  MOV  W2, W20
      23 00 80 52  //  MOV  W3, #1
      A4 16 80 52  //  MOV  W4, #0xB5
      25 00 80 52  //  MOV  W5, #1
      A6 00 80 52  //  MOV  W6, #5
      E7 03 13 2A  //  MOV  W7, W19
      ?? ?? ?? 94  //  BL   sub_430E87C
    }

    /**
      sub_430E87C(0LL, 0LL, v13, 1u, 198u, 1u, 6u, 0, 0LL, 0);
    */
    $func3 = {
      00 00 80 D2  //   MOV             X0, #0
      01 00 80 D2  //   MOV             X1, #0
      23 00 80 52  //   MOV             W3, #1
      C4 18 80 52  //   MOV             W4, #0xC6
      25 00 80 52  //   MOV             W5, #1
      C6 00 80 52  //   MOV             W6, #6
      07 00 80 52  //   MOV             W7, #0
      ?? ?? ?? 94  //   BL              sub_430E87C
    }

    /**
      sub_430E87C(0LL, 0LL, v14, 1LL, 199LL, 1LL, 7LL, 0LL, 0LL, 0);
    */
    $func4 = {
      00 00 80 D2   //   MOV  X0, #0
      01 00 80 D2   //   MOV  X1, #0
      23 00 80 52   //   MOV  W3, #1
      E4 18 80 52   //   MOV  W4, #0xC7
      25 00 80 52   //   MOV  W5, #1
      E6 00 80 52   //   MOV  W6, #7
      07 00 80 52   //   MOV  W7, #0
      ?? ?? ?? 94   //   BL   sub_430E87C
    }

  condition:
    is_elf and $init_proc and $do_asm_syscall and 1 of ($func*)
}

rule jiagu_native : packer
{
  meta:
    description = "Jiagu"
    sample      = "3e83c34f496bd33457ca0a100c90ed229e2c1a9e39fdcaf5670d32455c5d051e"
    url         = "http://jiagu.360.cn/"
    author      = "Govind Sharma"

  strings:
    $a = "libz.so"
    $b = "uncompress"
    $c = "libjiagu"
    $d = "JIAGU_APP_NAME"
    $e = "JIAGU_SO_BASE_NAME"
    $f = "JIAGU_ENCRYPTED_DEX_NAME"
    $g = "JIAGU_HASH_FILE_NAME"

  condition:
    is_elf and ($a and $b and $c) and any of ($d, $e, $f, $g)
}

rule blackmod : packer
{
  meta:
    description = "BlackMod"
    url         = "https://blackmod.net/"
    sample      = "77b1ff2db51896a2c5a0b1a932283d757f5d2285a8c035d212af09d8d373441a"
    author      = "Eduardo Novella"

  strings:
    $libname    = {00 6c6962626d742e736f 00}       // libbmt.so
    $jni_onload = {00 4a4e 495f 4f6e 4c6f 6164 00} // JNI_OnLoad

    $svc_arm32 = {
      // read_0   ; CODE XREF: j__xd
      ?? 7? A0 E3  //   MOV             R7, #3 (read), #4 (write) & #0x142 (openat)
      00 00 00 EF  //   SVC             0
    }

    $svc_arm64 = {
      ?8 0? 80 D2  //  MOV             X8, #63 (read), #64 (write), & #56 (openat)
      01 00 00 D4  //  SVC             0
    }

  condition:
    is_elf and 3 of them
}

rule _5play_ru : packer
{
  meta:
    description = "5play.ru"
    url         = "https://5play.ru"
    sample      = "b0db6d3a98a2e0e255380e5e04c9b461cc1aac06e9be29150318cf4cfbe06887"
    author      = "Eduardo Novella"

  strings:
    $libname    = {00 6c69 6252 4d53 2e73 6f 00}   // libRMS.so
    $jni_onload = {00 4a4e 495f 4f6e 4c6f 6164 00} // JNI_OnLoad

    $svc_arm32 = {
      FF 5F 2D E9   // PUSH  {R0-R12,LR}
      42 71 00 E3   // MOVW  R7, #0x142
      01 20 A0 E1   // MOV   R2, R1
      00 10 A0 E1   // MOV   R1, R0
      63 00 E0 E3   // MOV   R0, #0xFFFFFF9C
      00 00 00 EF   // SVC   0
    }

    $svc_arm64 = {
      08 07 80 D2   // MOV   X8, #56
      E2 03 01 AA   // MOV   X2, X1
      E1 03 00 AA   // MOV   X1, X0
      60 0C 80 12   // MOV   W0, #0xFFFFFF9C
      01 00 00 D4   // SVC   0
    }

  condition:
    is_elf and 3 of them
}

rule liapp_elf : packer
{
  meta:
    description = "LIAPP"
    url         = "https://liapp.lockincomp.com"
    sample      = "29b8c466148bcbe2ee4d1e9f1cc03ceb7e320cd19e7923e0c5a0b8a062758f0f" // com.teamblind.blind
    author      = "Eduardo Novella"

  strings:
    $libname = {  006c 6962 6c69 6170 702e 736f 00 } // libliapp.so

  condition:
    is_elf and all of them
}

rule eversafe_elf : packer
{
    meta:
        description = "Eversafe"
        url         = "https://everspin.global/products/solutions/eversafe-mobile"
        sample      = "00dbb346f3ae0540620eb120ccf00a65af81a07baed5adfdcd2fc620a33ed298"
        author      = "dustty0 & Eduardo Novella"

    strings:
      $lib = {
          006c 6962 6576 6572 7361 6665 2e73 6f00 // .libeversafe.so.
      }

    condition:
      is_elf and any of them
}

rule aegis_elf : packer
{
    meta:
        description = "Aegis"
        url         = "https://androidrepublic.org"
        sample      = "4ca8c5f8ecfa1c36678b1745a2b58872e3f3f5fd14df6dd5fd65d6b8f2677f53"
        author      = "Yehh22 & Eduardo Novella"

    strings:
        $lib1 = { 00 6c69 6261 6567 6973 5f65 2e73 6f00                } // .libaegis_e.so
        $lib2 = { 00 6c69 6261 6567 6973 5f65 5f61 726d 3634 2e73 6f00 } // .libaegis_e_arm64.so.
        $lib3 = { 00 6c69 6261 6567 6973 5f65 5f78 3836 2e73 6f00      } // .libaegis_e_x86.so.
        $url = "https://www.androidrepublic.org"

    condition:
      is_elf and 2 of them
}

rule appguard_elf : packer
{
  meta:
    description = "AppGuard"
    url         = "http://appguard.nprotect.com/en/index.html"
    sample      = "a6e9c876be2b8b936ab9bfe2699811524b8ad3c11305099b34194bb8aad79f1e"
    sample2     = "23cd2af10d46459065ea65b2d40fb706fd4847a1f8ef195cbebf1c6d8d54a48a"
    author      = "Eduardo Novella"

  strings:
    $a = { 00 6C 69 62 41 70 70 47 75 61 72 64 2E 73 6F 00 }  // .libAppGuard.so.
    $b = { 00 23 4C 63 6F 6D 2F 69 6E 63 61 2F 73 65 63 75
           72 69 74 79 2F 41 70 70 47 75 61 72 64 2F 78 43
           6C 61 73 73 3B 00 } //.#Lcom/inca/security/AppGuard/xClass;.

  condition:
    is_elf and any of them
}

rule dxshield_elf : packer
{
  meta:
    description = "DxShield"
    url         = "https://www.nshc.net/home/mobile-security/gxshield/"
    sample      = "64351853f9f1bcaa32598b6d2ecf97097a00989213defa31fb9b3abbba52a445" // com.wemade.nightcrowsglobal v1.0.28
    author      = "Eduardo Novella"

  strings:
    $lib = { 00 6C 69 62 64 78 62 61 73 65 2E 73 6F 00 4C 49 42 43 00 }  // libdxbase.so

  condition:
    is_elf and all of them
}


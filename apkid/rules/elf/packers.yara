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

import "elf"
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

rule upx_elf_3_94 : packer {
  meta:
    description = "UPX 3.94 (unmodified)"

  strings:
    $copyright = "UPX 3.94 Copyright"

  condition:
    upx_unmodified and $copyright
}

rule upx_elf_3_93 : packer {
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
    info        = "https://promon.co/"
    example     = "6a3352f54d9f5199e4bf39687224e58df642d1d91f1d32b069acd4394a0c4fe0"

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



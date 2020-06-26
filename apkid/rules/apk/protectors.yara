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

include "common.yara"

rule verymatrix : protector
{
  meta:
    description = "InsideSecure Verymatrix"
    url         = "https://www.verimatrix.com/solutions/code-protection"
    sample      = "fdd6b324a267cb5287550b1ab2c7e527ad49b5ed4f4542abbc4fb5e8e2c00d3f"
    author      = "Eduardo Novella"

  strings:
    $libname = /lib\/(x86\_64|armeabi\-v7a|arm64\-v8a|x86)\/libmfjava\.so/

  condition:
    is_apk and $libname
}

rule virbox_apk : protector
{
  meta:
    description = "Virbox"
    url         = "https://shell.virbox.com"
    sample      = "b1a5d9d4c1916a0acc2d5c3b7c811a39ebeb2f6d42b305036473f7053bbf5fe7"
    author      = "Eduardo Novella"

  strings:
    $libs1 = "libsandhook.so"
    $libs2 = "libsandhook-native.so"
    $libv1 = "libv++_64.so"
    $libv2 = "libv++.so"

  condition:
    is_apk and
    1 of ($libs*) and
    1 of ($libv*)
}

rule vkey_apk : protector
{
  meta:
    description = "Vkey (V-OS App Protection)"
    url         = "https://www.v-key.com/products/v-os-app-protection/"
    author      = "Eduardo Novella"
    sample      = "eb7f7fd8b23ea2b55504b2d22dd6ee7a1214d822a79e848badcf720359ee78d1"

  strings:
    $lib1    = /lib\/(x86\_64|armeabi\-v7a|arm64\-v8a|x86)\/libvosWrapperEx\.so/
    $lib2    = /lib\/(x86\_64|armeabi\-v7a|arm64\-v8a|x86)\/libvtap\.so/
    $lib3    = /lib\/(x86\_64|armeabi\-v7a|arm64\-v8a|x86)\/libloadTA\.so/
    $lib4    = /lib\/(x86\_64|armeabi\-v7a|arm64\-v8a|x86)\/libchecks\.so/
    $asseta1 = "assets/firmware"
    $asseta2 = "assets/kernel.bin"
    $asseta3 = "assets/signature"
    $assetb1 = "assets/vkeylicensepack"
    $assetb2 = "assets/vkwbc_ta.bin"
    $assetb3 = "assets/voscodesign.vky"

  condition:
    is_apk and
    2 of ($lib*) and
    1 of ($asseta*) and
    1 of ($assetb*)
}

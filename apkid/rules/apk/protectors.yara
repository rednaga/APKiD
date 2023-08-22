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

include "common.yara"

rule verimatrix : protector
{
  meta:
    description = "InsideSecure Verimatrix"
    url         = "https://www.verimatrix.com/solutions/code-protection"
    sample      = "fdd6b324a267cb5287550b1ab2c7e527ad49b5ed4f4542abbc4fb5e8e2c00d3f"
    author      = "Eduardo Novella"

  strings:
    $libname = /lib\/(arm.*|x86.*)\/libmfjava\.so/

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

rule free_rasp_old : protector
{
  meta:
    description = "FreeRASP"
    url         = "https://www.talsec.app/freerasp-in-app-protection-security-talsec"
    sample      = "e10b8772fd9b6aaf8ba030c5bcb324fb9b91f34e893a62bdf238629df856e047"
    author      = "Fare9"

  strings:
    $lib1   = /lib\/(arm.*|x86.*)\/libsecurity\.so/
    $lib2   = /lib\/(arm.*|x86.*)\/libpolarssl\.so/

  condition:
    is_apk and all of them
}

rule free_rasp_new : protector
{
  meta:
    description = "FreeRASP"
    url         = "https://www.talsec.app/freerasp-in-app-protection-security-talsec"
    sample      = "2b8faa038bf34474075a56e2fda7887a7df9c3c57db8a9f25547dc9374137ec9"
    author      = "Fare9"

  strings:
    $lib1   = /lib\/(arm.*|x86.*)\/libsecurity\.so/
    $lib2   = /lib\/(arm.*|x86.*)\/libpolarssl\.so/
    $asset  = "assets/talsec"

  condition:
    is_apk and all of them
}

rule ahope_appshield : protector
{
    meta:
        description = "Ahope AppShield"
        url         = "http://www.ahope.net/sub/app-shields"
        sample      = "42a4d907caf625ff73d5b6fbbf32b59ba14d6d5a72f28b81bdc76c47db516122"
        author      = "dustty0 & Eduardo Novella"

    strings:
      $lib = /lib\/(arm.*|x86.*)\/libahope(.*)\.so/

    condition:
      is_apk and any of them
}

rule vguard : protector
{
  meta:
    description = "VGuard"
    url         = "https://www.vguard.co.kr"
    sample      = "7024bdadb53cbec86a39de845108b182ed2f7b3f0e7c0b876a948e1532ec5b9f"
    author      = "dustty0"

  strings:
    $lib    = /lib\/(arm.*|x86.*)\/libedex\.so/
    $asset1 = /assets\/dexsky\.(d|e)b(a|b|x|y)/
    $asset2 = /assets\/dexsky\.ini/
    $asset3 = /assets\/dex[a-z0-9]{3}\.zip/
    $asset4 = /assets\/vguard\.(key|enginehash)/

  condition:
    is_apk and 2 of them
}

rule appdefence : protector
{
  meta:
    description = "ExTrus AppDefence"
    url         = "https://www.extrus.co.kr/eng/m/product_01_05.html"
    sample      = "e080380673479d2e182ad7eff5130bb72fe9a228c0a5de9852df23c4e98113b2"
    author      = "dustty0"

  strings:
    $asset = "assets/appdefence_xml"

  condition:
    is_apk and all of them
}

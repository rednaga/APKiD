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

rule ahnlab_v3_engine : protector
{
  meta:
    description = "Ahnlab V3 engine"
    url         = "https://www.ahnlab.com/en"
    author      = "whoa-mi"
    sample      = "638bad9c6336049f43ac88d7db65c743d9703d732f86f2dc094999b195d63aa2"

  strings:
    $binary1 = /lib\/(arm|x86).*\/libEngineManager\.so/
    $binary2 = /assets\/ahnlab\/engine\/(arm|x86).*\/lib(rc|av)engine/
    $binary3 = "assets/ahnlab/engine/rootchecker2.rcd"

  condition:
    is_apk and 2 of ($binary*)
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

rule dpt_shell : protector
{
  meta:
    description = "DPT Shell"
    url         = "https://github.com/luoyesiqiu/dpt-shell"
    sample      = "0c4341700f4e685cafc9c86c9112098b75057580ba1f7163bc971347af3712ad"
    author      = "Abhi"

  strings:
    $app = "assets/app_name"
    $app_acf = "assets/app_acf"
    $assetlib = /assets\/(.*)\/(arm.*|x86.*)\/libdpt\.so/

  condition:
    is_apk and $assetlib and any of ($app*)
}

rule build38 : protector
{
  meta:
    description = "Build38"
    url         = "https://build38.com"
    sample      = "cfbbfca598a9877a381583a7ae2f9e8cde92e7314b21152658bcba5a4e3a0fff" // com.esignus.hashwalletmanager
    author      = "Abhi"

  strings:
    $lib      = /lib\/(arm.*|x86.*)\/libtak\.so/
    $license  = "__license.tak"
    $license2 = "license.tak"

  condition:
    is_apk and 2 of them
}

rule shield_sdk : protector
{
  meta:
    description = "Shield SDK"
    url         = "https://shield.com/"
    sample      = "fb4b7f033658b3898e0448955491b448a2c78e1a2325c65fece6ad64f6f6b6d0" // com.mpl.androidapp
    author      = "Abhi"

  strings:
    $lib = /lib\/(arm.*|x86.*)\/libcashshieldabc-native-lib\.so/

  condition:
    is_apk and all of them
}

rule bugsmirror : protector
{
  meta:
    description = "BugsMirror"
    url         = "https://www.bugsmirror.com/"
    sample      = "c9bbf66ac86bf02663b7bc28a735881d4aeaa8d90e9b8b752e9cf337a26f0bdd"
    author      = "Abhi"
  
  strings:
    $lib  = /lib\/(arm.*|x86.*)\/libdefender\.so/
    $xml  = /res\/xml\/(com_bugsmirror_)?(defender|bugsmirror)_authenticator\.xml/
    $lib2 = /lib\/(arm.*|x86.*)\/libsettings\.so/
  
  condition:
    is_apk and 2 of them
}

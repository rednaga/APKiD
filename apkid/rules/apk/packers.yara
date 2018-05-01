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

include "common.yara"

rule appguard : packer
{
  meta:
    description = "AppGuard"
    url = "http://appguard.nprotect.com/en/index.html"

  strings:
    $stub = "assets/appguard/"
    $encrypted_dex = "assets/classes.sox"

  condition:
    is_apk and ($stub and $encrypted_dex)
}

rule appguard_new : packer
{
    meta:
        description = "AppGuard"
        sample      = "c5195daa5d17ba6e1755f8cb7270ae3a971eb688ee7d650d10c284d7c93b777d"
        url         = "http://appguard.nprotect.com/en/index.html"
        author      = "Eduardo Novella"

    strings:
        $a = "assets/AppGuard0.jar"
        $b = "assets/AppGuard.dgc"
        $c = "libAppGuard.so"
        $d = "libAppGuard-x86.so"

    condition:
        is_apk and 3 of them
}

rule dxshield : packer
{
  meta:
    description = "DxShield"
    url = "http://www.nshc.net/wp/portfolio-item/dxshield_eng/"

  strings:
    $decryptlib = "libdxbase.so"
    $res = "assets/DXINFO.XML"

  condition:
    is_apk and ($decryptlib and $res)
}

rule secneo : packer
{
  meta:
    description = "SecNeo"
    url = "http://www.secneo.com"

  strings:
    $encryptlib1 = "libDexHelper.so"
    $encryptlib2 = "libDexHelper-x86.so"
    $encrypted_dex = "assets/classes0.jar"

  condition:
    is_apk and any of ($encrypted_dex, $encryptlib2, $encryptlib1)
}

rule dexprotector : packer
{
 /**
 * DexProtector v6.x.x :- Demo,Standard,Business Edition (https://dexprotector.com)
 **/
  meta:
    author = "Jasi2169"
    description = "DexProtector"

  strings:
    $encrptlib = "assets/dp.arm.so.dat"
    $encrptlib1 = "assets/dp.arm-v7.so.dat"
    $encrptlib2 = "assets/dp.arm-v8.so.dat"
    $encrptlib3 = "assets/dp.x86.so.dat"
    $encrptcustom = "assets/dp.mp3"

  condition:
    is_apk and any of ($encrptlib, $encrptlib1, $encrptlib2, $encrptlib3) and $encrptcustom
}

rule apkprotect : packer
{
  meta:
    description = "APKProtect"

  strings:
    $key = "apkprotect.com/key.dat"
    $dir = "apkprotect.com/"
    $lib = "libAPKProtect.so"

  condition:
    is_apk and ($key or $dir or $lib)
}

rule bangcle : packer
{
  meta:
    description = "Bangcle"

  strings:
    $main_lib = "libsecexe.so"
    $second_lib = "libsecmain.so"
    $container = "assets/bangcleplugin/container.dex"
    $encrypted_jar = "bangcleclasses.jar"
    $encrypted_jar2 = "bangcle_classes.jar"

  condition:
    is_apk and any of ($main_lib, $second_lib, $container, $encrypted_jar, $encrypted_jar2)
}

rule bangcle_secshell : packer
{
    meta:
        description = "Bangcle (SecShell)"
        sample      = "d710a24971a0cd56c5cbe62b4b926e0122704fba52821e9c888e651a2d26a05c"
        url         = "https://blog.fortinet.com/2017/01/26/deep-analysis-of-android-rootnik-malware-using-advanced-anti-debug-and-anti-hook-part-i-debugging-in-the-scope-of-native-layer"
        author      = "Eduardo Novella"


    strings:
        $a = "assets/secData0.jar"
        $b = "libSecShell.so"
        $c = "libSecShell-x86.so"

    condition:
        is_apk and 2 of them
}

rule kiro : packer
{
  meta:
    description = "Kiro"

  strings:
    $kiro_lib = "libkiroro.so"
    $sbox = "assets/sbox"

  condition:
    is_apk and $kiro_lib and $sbox
}

rule qihoo360 : packer
{
  meta:
    description = "Qihoo 360"

  strings:
    $a = "libprotectClass.so"

  condition:
    is_apk and
    $a and
    not kiro
}

rule jiagu : packer
{
  meta:
    //developed by Qihoo 360
    description = "Jiagu"
    url = "http://jiagu.360.cn/"

  strings:
    // These contain a trick function "youAreFooled"
    $main_lib = "libjiagu.so"
    $art_lib = "libjiagu_art.so"

  condition:
    is_apk and ($main_lib or $art_lib)
}

rule qdbh_packer : packer
{
  meta:
    description = "Unknown. Asset 'qdbh'"
    example     = "faf1e85f878ea52a3b3fbb67126132b527f509586706f242f39b8c1fdb4a2065"

  strings:
    $qdbh = "assets/qdbh"

  condition:
    is_apk and $qdbh
}

rule unknown_packer_lib : packer
{
  meta:
    description = "Unknown. Random library name."
    example     = "faf1e85f878ea52a3b3fbb67126132b527f509586706f242f39b8c1fdb4a2065"

  strings:
    $pre_jar  = { 00 6F 6E 43 72 65 61 74 65 00 28 29 56 00 63 6F 6D 2F 76 } // .onCreate.()V.com/v
    $jar_data = { 2E 6A 61 72 00 2F 64 61 74 61 2F 64 61 74 61 2F 00 2F } // .jar./data/data
    $post_jar = { 2E 6A 61 72 00 77 00 6A 61 76 61 2F 75 74 69 6C 2F 4D 61 70 00 67 65 74 49 6E 74 00 } // .jar.w.java/util/Map.getInt.

  condition:
    //is_apk and
    ($pre_jar and $jar_data and $post_jar)
}

rule unicom_loader : packer
{
  meta:
    description = "Unicom SDK Loader"

  strings:
    $decrypt_lib = "libdecrypt.jar"
    $unicom_lib = "libunicomsdk.jar"
    $classes_jar = "classes.jar"

  condition:
    is_apk and ($unicom_lib and ($decrypt_lib or $classes_jar))
}

rule liapp : packer
{
  meta:
    description = "LIAPP"

  strings:
    $dir = "/LIAPPEgg"
    $lib = "LIAPPClient.sc"

  condition:
    is_apk and any of ($dir, $lib)
}

rule app_fortify : packer
{
  meta:
    description = "App Fortify"

  strings:
    $lib = "libNSaferOnly.so"

  condition:
    is_apk and $lib
}

rule nqshield : packer
{
  meta:
    description = "NQ Shield"

  strings:
    $lib = "libnqshield.so"
    $lib_sec1 = "nqshield"
    $lib_sec2 = "nqshell"

  condition:
    is_apk and any of ($lib, $lib_sec1, $lib_sec2)
}

rule tencent : packer
{
  meta:
    description = "Tencent"

  strings:
    $decryptor_lib = "lib/armeabi/libshell.so"
    $zip_lib = "lib/armeabi/libmobisecy.so"
    $classpath = "com/tencent/StubShell"
    $mix_dex = "/mix.dex"

  condition:
    is_apk and ($classpath or $decryptor_lib or $zip_lib or $mix_dex)
}

rule ijiami : packer
{
  meta:
    description = "Ijiami"

  strings:
    $old_dat = "assets/ijiami.dat"
    $new_ajm = "ijiami.ajm"
    $ijm_lib = "assets/ijm_lib/"

  condition:
    is_apk and ($old_dat or $new_ajm or $ijm_lib)
}

rule naga : packer
{
  meta:
    description = "Naga"

  strings:
    $lib = "libddog.so"

  condition:
    is_apk and $lib
}

rule alibaba : packer
{
  meta:
    description = "Alibaba"

  strings:
    $lib = "libmobisec.so"

  condition:
    is_apk and $lib
}

rule medusah : packer
{
  meta:
    description = "Medusah"
    url = "https://medusah.com/"

  strings:
    $lib = "libmd.so"

  condition:
    is_apk and $lib
}

rule medusah_appsolid : packer
{
  meta:
    // Samples and discussion: https://github.com/rednaga/APKiD/issues/19
    description = "Medusah (AppSolid)"
    url = "https://appsolid.co/"

  strings:
    $encrypted_dex = "assets/high_resolution.png"

  condition:
    is_apk and $encrypted_dex and not medusah
}

rule baidu : packer
{
  meta:
    description = "Baidu"

  strings:
    $lib = "libbaiduprotect.so"
    $encrypted = "baiduprotect1.jar"

  condition:
    is_apk and ($lib or $encrypted)
}

rule pangxie : packer
{
  meta:
    description = "PangXie"
    example = "ea70a5b3f7996e9bfea2d5d99693195fdb9ce86385b7116fd08be84032d43d2c"

  strings:
    $lib = "libnsecure.so"

  condition:
    is_apk and $lib
}

rule kony : packer
{
  meta:
    description = "Kony"
	  url = "http://www.kony.com/"

  strings:
    $lib = "libkonyjsvm.so"
    $decrypt_keys = "assets/application.properties"
    $encrypted_js = "assets/js/startup.js"

  condition:
    is_apk and $lib and $decrypt_keys and $encrypted_js
}

rule approov : packer
{
  meta:
    description = "Aproov"
	  url = "https://www.approov.io/"

  strings:
    $lib = "libapproov.so"
    $sdk_config = "assets/cbconfig.JSON"

  condition:
    is_apk and $lib and $sdk_config
}

rule yidun : packer
{
  meta:
    description = "yidun"
	  url = "https://dun.163.com/product/app-protect"

  strings:
    $anti_trick = "Lcom/_" // Class path of anti-trick
    $entry_point = "Lcom/netease/nis/wrapper/Entry"
    $jni_func = "Lcom/netease/nis/wrapper/MyJni"
    $lib = "libnesec.so"

  condition:
    is_apk and (#lib > 1) or ($anti_trick and $entry_point and $jni_func)
}

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

rule appguard_a : packer
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

rule appguard_b : packer
{
  meta:
    description = "AppGuard (TOAST-NHNent)"
    url         = "https://docs.toast.com/en/Security/AppGuard/en/Overview/"
    url2        = "https://www.toast.com/service/security/appguard"
    sample      = "80ac3e9d3b36613fa82085cf0f5d03b58ce20b72ba29e07f7c744df476aa9a92"
    samples     = "https://koodous.com/rulesets/5249/apks"
    author      = "Eduardo Novella"

  strings:
    // package com.nhnent.appguard;
    $a1 = "assets/classes.jet"
    $a2 = "assets/classes.zip"
    $a3 = "assets/classes2.jet"
    $a4 = "assets/classes2.zip"
    $a5 = "assets/classes3.jet"
    $a6 = "assets/classes3.zip"
    $b1 = "lib/armeabi-v7a/libloader.so"
    $b2 = "lib/x86/libloader.so"
    $b3 = "lib/armeabi-v7a/libdiresu.so"
    $b4 = "lib/x86/libdiresu.so"
    $c1 = "assets/m7a"
    $c2 = "assets/m8a"
    $c3 = "assets/agconfig"    //appguard cfg?
    $c4 = "assets/agmetainfo"

  condition:
    is_apk and (2 of ($a*) and 1 of ($b*) and 1 of ($c*))
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

private rule secneo_base
{
  strings:
    $encryptlib1 = "libDexHelper.so"
    $encryptlib2 = "libDexHelper-x86.so"
    $encrypted_dex = "assets/classes0.jar"

  condition:
    is_apk and any of ($encrypted_dex, $encryptlib2, $encryptlib1)
}

rule secneo_b : packer
{
  meta:
    description = "SecNeo.B"
    url = "http://www.secneo.com"
    sample = "f5d7985e2add50fce74c99511512084845558ac996ce66f45e633c9495d78400"

  strings:
    $lib1 = "libdexjni.so"
    $lib2 = "libdexjni%s.so"

  condition:
    secneo_base and any of ($lib1, $lib2)
}

rule secneo_a : packer
{
  meta:
    description = "SecNeo.A"
    url = "http://www.secneo.com"

  condition:
    secneo_base
    and not secneo_b
}

rule dexprotector : packer
{
  // DexProtector v6.x.x :- Demo, Standard, Business Edition

  meta:
    author      = "Jasi2169 and Eduardo Novella"
    description = "DexProtector"
    url         = "https://dexprotector.com/"

  strings:
    $encrptlib_1 = "assets/dp.arm.so.dat"
    $encrptlib_2 = "assets/dp.arm-v7.so.dat"
    $encrptlib_3 = "assets/dp.arm-v8.so.dat"
    $encrptlib_4 = "assets/dp.x86.so.dat"
    $encrptlib_5 = "assets/dp.x86_64.so.dat"
    $encrptlib_6 = "assets/classes.dex.dat"

    $encrptcustom = "assets/dp.mp3"

  condition:
    is_apk and 1 of ($encrptlib_*) and $encrptcustom
}

rule dexprotector_a : packer
{
  // Possible older version

  meta:
    author      = "Eduardo Novella"
    description = "DexProtector"
    url         = "https://dexprotector.com/"
    sample      = "242e0ee59de46c7648b7b38efeb8c088ae3dc8c5c8fe9fbd5e707b098ab8f404"

  strings:
    $encrptlib_1 = "assets/dp.arm-v7.art.kk.so"
    $encrptlib_2 = "assets/dp.arm-v7.art.l.so"
    $encrptlib_3 = "assets/dp.arm-v7.dvm.so"
    $encrptlib_4 = "assets/dp.arm.art.kk.so"
    $encrptlib_5 = "assets/dp.arm.art.l.so"
    $encrptlib_6 = "assets/dp.arm.dvm.so"
    $encrptlib_7 = "assets/dp.x86.art.kk.so"
    $encrptlib_8 = "assets/dp.x86.art.l.so"
    $encrptlib_9 = "assets/dp.x86.dvm.so"

    $encrptcustom = "assets/dp.mp3"

  condition:
    is_apk and 2 of ($encrptlib_*) and $encrptcustom
}

rule dexprotector_b : packer
{
  // Possible newer version

  meta:
    author      = "Eduardo Novella"
    description = "DexProtector"
    url         = "https://dexprotector.com/"
    sample      = "dca2a0bc0f2605072b9b48579e73711af816b0fa1108b825335d2d1f2418e2a7"

  strings:
    //              assets/com.package.name.arm.so.dat
    $encrptlib_1 = /assets\/[A-Za-z0-9.]{2,50}\.arm\-v7\.so\.dat/
    $encrptlib_2 = /assets\/[A-Za-z0-9.]{2,50}\.arm\-v8\.so\.dat/
    $encrptlib_3 = /assets\/[A-Za-z0-9.]{2,50}\.arm\.so\.dat/
    $encrptlib_4 = /assets\/[A-Za-z0-9.]{2,50}\.dex\.dat/
    $encrptlib_5 = /assets\/[A-Za-z0-9.]{2,50}\.x86\.so\.dat/
    $encrptlib_6 = /assets\/[A-Za-z0-9.]{2,50}\.x86\_64\.so\.dat/

    $encrptcustom = /assets\/[A-Za-z0-9.]{2,50}\.mp3/

  condition:
    is_apk and 2 of ($encrptlib_*) and $encrptcustom and
    not dexprotector_a and
    not dexprotector
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

rule apkprotect_a : packer
{
  meta:
    description = "APKProtect 6.x"
    url         = "https://play.google.com/store/apps/details?id=com.mcal.dexprotect"
    sample      = "1c3e09c6e336fef0261a19e546f3686fcf9a00ee23f7426608fef40465d91289"
    author      = "Eduardo Novella"

  strings:
    $a1 = /lib\/(x86\_64|armeabi\-v7a|arm64\-v8a|x86)\/libapkprotect\.so/
    $a2 = "assets/apkprotect.bin"
    $a3 = "assets/apkprotect/classes.dex.bin"
    $a4 = "apkprotect-build.properties"

  condition:
    is_apk and 2 of ($a*)
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

rule jiagu_a : packer
{
  meta:
    description = "Jiagu (ApkToolPlus)"
    sample      = "684baab16344dc663b7ae84dd1f8d6a39bfb480a977ad581a0a6032f6e437218"
    url         = "https://github.com/linchaolong/ApkToolPlus/tree/master/lib.JiaGu/src/com/linchaolong/apktoolplus/jiagu"
    author      = "Eduardo Novella"

  strings:
    $a = "assets/jiagu_data.bin"
    $b = "assets/sign.bin"
    $c = "libapktoolplus_jiagu.so"

  condition:
    is_apk and all of them
}

rule qdbh_packer : packer
{
  meta:
    description = "qdbh packer"
    sample      = "faf1e85f878ea52a3b3fbb67126132b527f509586706f242f39b8c1fdb4a2065"

  strings:
    $qdbh = "assets/qdbh"

  condition:
    is_apk and $qdbh
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
    sample = "b5be20d225edf55634621aa17988a6ed3368d4f7632c8a1eb4d3fc3b6a61c325"

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
    description = "Mobile Tencent Protect"
    url         = "https://intl.cloud.tencent.com/product/mtp"
    sample      = "7c6024abc61b184ddcc9fa49f9fac1a7e5568d1eab09ee748f8c4987844a3f81"

  strings:
    $decryptor_lib = "lib/armeabi/libshell.so"
    $zip_lib = "lib/armeabi/libmobisecy.so"
    $mix_dex = "/mix.dex"

  condition:
    is_apk and ($decryptor_lib or $zip_lib or $mix_dex)
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
    sample = "5c1f14c1674c6f3ff72d9a017b083023d6c59635bec83718afec2d23372f84f4"

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
    sample = "ea70a5b3f7996e9bfea2d5d99693195fdb9ce86385b7116fd08be84032d43d2c"

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

rule apkpacker : packer
{
  meta:
    description = "ApkPacker"
    sample      = "087af5aacab8fc8bc7b1dcb7a138c3552d175c74b496056893299bc437422f95"
    author      = "Eduardo Novella"

  strings:
    $a = "assets/ApkPacker/apkPackerConfiguration"
    $b = "assets/ApkPacker/classes.dex"
    // These may be related, but not enough samples to be sure
    //$c = "assets/config.txt"
    //$d = "assets/sht.txt"

  condition:
    is_apk and all of them
}

rule chornclickers : packer
{

  meta:
    // This has no name so we made one up from Ch-china,-orn-porn and -clickers
    description = "ChornClickers"
    url         = "https://github.com/rednaga/APKiD/issues/93"
    sample      = "0c4a26d6b27986775c9c58813407a737657294579b6fd37618b0396d90d3efc3"
    author      = "Eduardo Novella"

  strings:
    $a = "lib/armeabi/libhdus.so"
    $b = "lib/armeabi/libwjus.so"

  condition:
    is_apk and all of them
}

rule appsuit_packer : packer
{
    meta:
        description = "AppSuit"
        url         = "http://www.stealien.com/appsuit.html"
        sample      = "8dc42cc950617ff51d0409a05809d20ca4c375f05c3fa2324b249e1306758a94"
        author      = "Eduardo Novella"

    strings:
        $asset1      = "assets/appsuit/momo"
        $asset2      = "assets/appsuit/meme"
        $native_lib2 = "libAppSuit.so"

    condition:
        is_apk and 2 of them
}

rule appsealing : packer
{
  meta:
    // Commercial packer
    description = "AppSealing"
    url         = "https://www.appsealing.com/"
    sample      = "61a983b032aee2e56159e682ad1588ad30fa8c3957bf849d1afe6f10e1d9645d"
    author      = "zeroload"

  strings:
    $native_lib_1 = "libcovault.so"
    $native_lib_2 = "libcovault-appsec.so"
    $stub = "appsealing.dex"
    $dex = "sealed1.dex"

  condition:
    is_apk and all of them
}

rule secenh : packer
{
  meta:
    description = "Secenh"
    sample = "0709d38575e15643f03793445479d869116dca319bce2296cb8af798453a8752"
    author = "Nacho Sanmillan"

  strings:
    $a1 = "assets/libsecenh.so"
    $a2 = "assets/libsecenh_x86.so"
    $b1 = "assets/respatcher.jar"
    $b2 = "assets/res.zip"

  condition:
    is_apk
    and 1 of ($a*)
    and 1 of ($b*)
}

rule tencent_legu : packer
{
  meta:
    description = "Tencent's Legu"
    sample      = "9ff3a53f76c7a6d7e3de3b8567c9606f2cc08ec4aaaae596a27361018d839c58"
    author      = "Mert Arıkan"
    // Reference article : https://blog.quarkslab.com/a-glimpse-into-tencents-legu-packer.html

  strings:
    $a = "assets/toversion"
    $b = "assets/0OO00l111l1l"
    $c = "assets/0OO00oo01l1l"
    $d = "assets/o0oooOO0ooOo.dat"

  condition:
    is_apk
    and $b
    and ($a or $c or $d)
}


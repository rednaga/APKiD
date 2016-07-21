private rule apk {
  meta:
    description = "Resembles an simple APK that is likely not corrupt"

  strings:
    $zip_head = "PK"
    $manifest = "AndroidManifest.xml"

  condition:
    $zip_head at 0 and $manifest and #manifest >= 2
}

private rule signed_apk {
  meta:
    description = "Resembles an simple APK that is signed and likely not corrupt"

  strings:
    $meta_inf = "META-INF/"
    $rsa = ".RSA"
    $dsa = ".DSA"

  condition:
    apk and for all of ($meta_inf*) : ( $rsa or $dsa in (@ + 9..@ + 9 + 100))
}

private rule unsigned_apk {
  meta:
    description = "Resembles an simple APK that is unsigned and likely not corrupt"

  condition:
    apk and not signed_apk
}

rule apkprotect {
  meta:
    description = "Packed with APKProtect"

  strings:
    $key = "apkprotect.com/key.dat"
    $dir = "apkprotect.com/"
    $lib = "libAPKProtect.so"

  condition:
    apk and ($key or $dir or $lib)
}

rule bangcle {
  meta:
    description = "Packed with Bangcle"

  strings:
    $main_lib = "libsecexe.so"
    $second_lib = "libsecmain.so"
    $container = "assets/bangcleplugin/container.dex"
    $encrypted_jar = "bangcleclasses.jar"
    $encrypted_jar2 = "bangcle_classes.jar"


  condition:
    apk and any of ($main_lib, $second_lib, $container, $encrypted_jar, $encrypted_jar2)
}

rule kiro {

  strings:
    $kiro_lib = "libkiroro.so"
    $sbox = "assets/sbox"

  condition:
    apk and $kiro_lib and $sbox
}

rule qihoo360 {
  meta:
    description = "Packed with Qihoo 360"

  strings:
    $a = "libprotectClass.so"

  condition:
    apk and $a
    and not kiro
}

rule jiangu {
  meta:
    description = "Packed with Jiangu"

  strings:
    // These contain a trick function "youAreFooled"
    $main_lib = "libjiagu.so"
    $art_lib = "libjiagu_art.so"

  condition:
    apk and ($main_lib or $art_lib)
}

rule unknown_packer {
  meta:
    description = "Packed with an unknown packer"

  strings:
    $qdbh = "assets/qdbh"

  condition:
    apk and $qdbh
}

rule unknown_packer_lib {
  meta:
    description = "Packed with an unknown packer"

  strings:
    $pre_jar = { 00 6F 6E 43 72 65 61 74 65 00 28 29 56 00 63 6F 6D 2F 76 }
    $jar_data = { 2E 6A 61 72 00 2F 64 61 74 61 2F 64 61 74 61 2F 00 2F }
    $post_jar = { 2E 6A 61 72 00 77 00 6A 61 76 61 2F 75 74 69 6C 2F 4D 61 70 00 67 65 74 49 6E 74 00 }

  condition:
    //apk and
    ($pre_jar and $jar_data and $post_jar)
}

rule unicom_loader {
  meta:
    description = "Packed with Unicom SDK Loader"

  strings:
    $decrypt_lib = "libdecrypt.jar"
    $unicom_lib = "libunicomsdk.jar"
    $classes_jar = "classes.jar"

  condition:
    apk and ($unicom_lib and ($decrypt_lib or $classes_jar))
}

rule liapp {
  meta:
    description = "Packed with LIAPP"

  strings:
    $dir = "/LIAPPEgg"
    $lib = "LIAPPClient.sc"

  condition:
    apk and any of ($dir, $lib)
}

rule app_fortify {
  meta:
    description = "Packed with App Fortify"

  strings:
    $lib = "libNSaferOnly.so"

  condition:
    apk and $lib
}

rule nqshield {
  meta:
    description = "Packed with NQ Shield"

  strings:
    $lib = "libnqshield.so"
    $lib_sec1 = "nqshield"
    $lib_sec2 = "nqshell"

  condition:
    apk and any of ($lib, $lib_sec1, $lib_sec2)
}


rule tencent {
  meta:
    description = "Packed with Tencent"

  strings:
    $decryptor_lib = "lib/armeabi/libshell.so"
    $zip_lib = "lib/armeabi/libmobisecy.so"
    $classpath = "com/tencent/StubShell"
    $mix_dex = "/mix.dex"

  condition:
    apk and ($classpath or $decryptor_lib or $zip_lib or $mix_dex)
}

rule ijiami {
  meta:
    description = "Packed with Ijiami"

  strings:
    $old_dat = "assets/ijiami.dat"
    $new_ajm = "ijiami.ajm"
    $ijm_lib = "assets/ijm_lib/"

  condition:
    apk and ($old_dat or $new_ajm or $ijm_lib)
}

rule naga {
  meta:
    description = "Packed with Naga"

  strings:
    $lib = "libddog.so"

  condition:
    apk and $lib
}

rule alibaba {
  meta:
    description = "Packed with Alibaba"

  strings:
    $lib = "libmobisec.so"

  condition:
    apk and $lib
}

rule medusa {
  meta:
    description = "Packed with Medusa "

  strings:
    $lib = "libmd.so"

  condition:
    apk and $lib
}

rule baidu {
  meta:
    description = "Packed with Baidu"

  strings:
    $lib = "libbaiduprotect.so"
    $encrypted = "baiduprotect1.jar"

  condition:
    apk and ($lib or $encrypted)
}

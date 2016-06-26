rule apkprotect
{
  meta:
    description = "Packed with APKProtect"

  strings:
    $a = "apkprotect.com/"
    $b = "libAPKProtect.so"
    $c = "libbaiduprotect.so"

  condition:
    any of ($a, $b, $c)
}

rule bangcle
{
  meta:
    description = "Packed with Bangcle"

  strings:
    $a = "libsecexe.so"
    $b = "libapkprotect2.so"
    $c = "assets/bangcleplugin/container.dex"
    $d = "bangcleclasses.jar"
    $e = "libsecexe.so"
    $f = "bangcle_classes.jar"
    $g = "libsecmain"

  condition:
    any of ($a, $b, $c, $d, $e, $f, $g)
}

rule qihoo360
{
  meta:
    description = "Packed with Qihoo 360"

  strings:
    $a = "libprotectClass.so"

  condition:
    $a
}

rule liapp
{
  meta:
    description = "Packed with LIAPP"

  strings:
    $a = "/LIAPPEgg"
    $b = "LIAPPClient.sc"

  condition:
    any of ($a, $b)
}

rule app_fortify
{
  meta:
    description = "Packed with App Fortify"

  strings:
    $a = "libNSaferOnly.so"

  condition:
    $a
}

rule nqshield
{
  meta:
    description = "Packed with NQ Shield"

  strings:
    $a = "libnqshield.so"
    $b = "nqshield"
    $c = "nqshell"

  condition:
    any of ($a, $b, $c)
}


rule tencent
{
  meta:
    description = "Packed with Tencent"

  strings:
    $a = "libshell.so"

  condition:
    $a
}

rule ijiami
{
  meta:
    description = "Packed with Ijiami"

  strings:
    $a = "ijiami.dat"

  condition:
    $a
}

rule naga
{
  meta:
    description = "Packed with Naga"

  strings:
    $a = "libddog.so"

  condition:
    $a
}

rule alibaba
{
  meta:
    description = "Packed with Alibaba"

  strings:
    $a = "libmobisec.so"

  condition:
    $a
}

rule medusa
{
  meta:
    description = "Packed with Medusa "

  strings:
    $a = "libmd.so"

  condition:
    $a
}

rule baidu
{
  meta:
    description = "Packed with Baidu"

  strings:
    $a = "libbaiduprotect.so"
  condition:
    $a
}
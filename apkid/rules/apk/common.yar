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
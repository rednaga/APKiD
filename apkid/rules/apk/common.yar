/*
 * Copyright (C) 2016  RedNaga. http://rednaga.io
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

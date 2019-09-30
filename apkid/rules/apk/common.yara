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

rule is_apk : file_type
{
  meta:
    description = "APK"

  strings:
    $zip_head = "PK"
    $manifest = "AndroidManifest.xml"

  condition:
    $zip_head at 0 and $manifest and #manifest >= 2
}

private rule is_signed_apk : internal
{
  meta:
    description = "Resembles a signed APK that is likely not corrupt"

  strings:
    $meta_inf = "META-INF/"
    $ext_rsa = ".RSA"
    $ext_dsa = ".DSA"
    $ext_ec = ".EC"

  condition:
    is_apk and
    for all of ($meta_inf*) : ($ext_rsa or $ext_dsa or $ext_ec in (@ + 9..@ + 9 + 100))
}

private rule is_unsigned_apk : internal
{
  meta:
    description = "Resembles an unsigned APK that is likely not corrupt"

  condition:
    is_apk and not is_signed_apk
}

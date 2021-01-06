/*
 * Copyright (C) 2021  RedNaga. https://rednaga.io
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

import "dex"

rule is_dex : file_type
{
  meta:
    description = "DEX"

  strings:
    $dex = { 64 65 78 0A 30 33 ?? 00 }
    $odex = { 64 65 79 0A 30 33 ?? 00 }

  condition:
    $dex at 0 or
    $odex at 0
}

private rule yara_detected_dex : internal {
  meta:
    description = "magic bytes look like a dex but yara disagrees"

  condition:
    is_dex
    and dex.header.header_size > 0
}

rule yara_undetected_dex : yara_issue {
  meta:
    description = "yara issue - dex file recognized by apkid but not yara module"

  condition:
    is_dex
    and not yara_detected_dex
}

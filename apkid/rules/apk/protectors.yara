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

rule verymatrix : protector
{
  meta:
    description = "InsideSecure Verymatrix"
    url         = "https://www.verimatrix.com/solutions/code-protection"
    sample      = "fdd6b324a267cb5287550b1ab2c7e527ad49b5ed4f4542abbc4fb5e8e2c00d3f"
    author      = "Eduardo Novella"

  strings:
    $libname = /lib\/(x86\_64|armeabi\-v7a|arm64\-v8a|x86)\/libmfjava\.so/

  condition:
    is_apk and $libname
}

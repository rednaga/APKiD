/*
 * Copyright (C) 2024  RedNaga. https://rednaga.io
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

rule is_res : file_type
{
  meta:
    description = "RES"

  strings:
    // Common patterns in resources.arsc (package ID, resource type,..)
    $magic = { 02 00 0C 00 }
    $type1 = { 01 00 1C 00 }
    $type2 = { 03 00 00 00 }
    $type3 = { 00 02 00 00 }

  condition:
    $magic at 0 and 1 of ($type*)
}


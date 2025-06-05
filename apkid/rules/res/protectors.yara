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

include "common.yara"

rule bugsmirror : protector
{
    meta:
      description = "BugsMirror"
      url         = "https://www.bugsmirror.com/"
      sample      = "c9bbf66ac86bf02663b7bc28a735881d4aeaa8d90e9b8b752e9cf337a26f0bdd"
      author      = "Abhi"
    
    strings:
        $comment  = { 00 ?? ?? 53 65 63 75 72 65 64 20 62 79 20
                      42 75 67 73 6D 69 72 72 6F 72 00 } // Secured by Bugsmirror
        $comment2 = { ?? 73 65 63 75 72 65 64 5F 62 79 5F 62 75
                      67 73 6D 69 72 72 6F 72 00 } // secured_by_bugsmirror
    
    condition:
        is_res and any of them
}
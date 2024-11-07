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

rule beebyte : obfuscator
{
  meta:
    description = "Beebyte Obfuscator"
    url         = "https://www.beebyte.co.uk/"
    sample      = "53fa7054f7112197cfe3ab8adc1afe825c6e6b4a696404f75f75eb894ae77456"
    author      = "Abhi"
  
  strings:
    $name = "Beebyte.Obfuscator"

  condition:
    is_dll and all of them
}

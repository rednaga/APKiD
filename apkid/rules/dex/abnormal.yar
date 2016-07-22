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

import "dex"

rule abnormal_header_size
{
  meta:
    description = "Non-Standard Header Size"

  condition:
    /*
     * Header size is always 112 bytes but the format allows it to be bigger. This would make it
     * possible to do weird stuff like hide files after the normal header data.
     */
    dex.header.header_size != 0x70
}

/*

- data after header, file size is different from header.file_size?

- illegal class names:
  "CON", "PRN", "AUX", "CLOCK$", "NUL",
  "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3",
  "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"

- abnormal endian magic

- link section is not 0

- class name length is > 255 characters

*/

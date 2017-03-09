/*
 * Copyright (C) 2017  RedNaga. http://rednaga.io
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

/*
TODO:
    class name length is > 255 characters
*/

import "dex"
include "common.yara"

rule abnormal_header_size : abnormal
{
  meta:
    description = "non-standard header size"

  condition:
    /*
     * Header size is always 112 bytes but the format allows it to be bigger. This would make it
     * possible to do weird stuff like hide files after the normal header data.
     */
    is_dex and dex.header.header_size != 0x70
}

rule non_zero_link_size : anti_disassembly
{
  meta:
    description = "non-zero link size"

  condition:
    dex.header.link_size != 0x0
}

rule non_zero_link_offset : anti_disassembly
{
  meta:
    description = "non-zero link offset"

  condition:
    dex.header.link_offset != 0x0
}

rule non_little_endian : abnormal
{
  meta:
    description = "non little-endian format"

  condition:
    dex.header.endian_tag != 0x12345678
}

rule data_injected_after_map : dropper
{
  meta:
    description = "injected data after map section"

  condition:
    dex.header.file_size < dex.header.map_offset + (dex.map_list.size * 12) + 4
}

rule illegal_class_names : anti_disassembly
{
  meta:
    description = "illegal class name"

  strings:
    /*
     * Disassemblers use class names for file names, and these file names
     * are illegal on some file systems (looking at you, Windows)
     */
    $invalid = /\x00[^\x00]{1,4}L([^\x00\x2f]+\x2f)*(CON|PRN|AUX|CLOCK\$|NUL|COM[1-9]|LPT[1-9])(\x2f[^\x00\x2f]+\x2f+)*;\x00/is

  condition:
    any of them
}

rule invalid_dex : abnormal
{
  meta:
    description = "invalid dex (parsing error)"

  condition:
    is_dex and dex.invalid_dex == 1
}

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

rule dexlib1
{
  meta:
    description = "Compiled with Dexlib 1.x"

  condition:
    /*
     * DEX format requires string IDs to be sorted according to the data at their offsets but the actual
     * ordering of the string pool is undefined. Dexlib (smali/apktool) 1.x sorts strings by class and
     * proximity. DX sorts strings in the same order as the string table.
     */
    for any i in (0..dex.header.string_ids_size - 1) : (dex.string_ids[i].offset + dex.string_ids[i].item_size + 1 != dex.string_ids[i + 1].offset)
}

rule dexlib2
{
  meta:
    description = "Compiled with Dexlib 2.x"

  condition:
    /*
     * The map_list types are in different orders for DX, dexmerge, and dexlib (1 and 2 are the same)
     */
    dex.map_list.map_items[7].type == 0x2002 // TYPE_STRING_DATA_ITEM
}

rule dexlib2beta
{
  meta:
    description = "Compiled with Dexlib 2.x Beta"

  condition:
    /*
     * Dexlib2 adds a non-zero interfaces_off to every class_def_item, even if the class doesn't implement an
     * interface. It points to 4 null bytes right after string pool. DEX documentation says the value for
     * interfaces_off should be 0 if there is no interface, which is what DX does. It's enough to check
     * if a single class has an interface which points to null bytes since no one else does this.
     */
    dexlib2 and
    for any i in (0..dex.header.class_defs_size) : (dex.class_defs[i].interfaces_off > 0 and uint32(dex.class_defs[i].interfaces_off) == 0)
}

rule dx
{
  meta:
    description = "Compiled with dx"

  condition:
    /*
     * The map_list types are in different orders for DX, dexmerge, and dexlib (1 and 2 are the same)
     * DX order derrived from: http://osxr.org/android/source/dalvik/dx/src/com/android/dx/dex/file/DexFile.java#0111
     */
    not dexlib1 and
    (dex.map_list.map_items[7].type == 0x1002 or // TYPE_ANNOTATION_SET_REF_LIST
    dex.map_list.map_items[7].type == 0x1003 or  // TYPE_ANNOTATION_SET_ITEM
    dex.map_list.map_items[7].type == 0x2001)    // TYPE_CODE_ITEM
}

rule dexmerge
{
  meta:
    description = "Compiled with dxmerge"

  condition:
    /*
     * The map_list types are in different orders for DX, dexmerge, and dexlib (1 and 2 are the same)
     * DexMerge order derrived from: http://osxr.org/android/source/dalvik/dx/src/com/android/dx/merge/DexMerger.java#0111
     */
    dex.map_list.map_items[7].type == 0x1000 // TYPE_MAP_LIST
}

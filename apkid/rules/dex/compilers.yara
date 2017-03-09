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

import "dex"
include "common.yara"

private rule unsorted_string_table
{
  condition:
    /*
     * DEX format requires string IDs to be sorted according to the data at their offsets but the actual
     * ordering of the string pool is undefined. Dexlib (smali/apktool) 1.x sorts strings by class and
     * proximity. DX sorts strings in the same order as the string table.
     *
     * Note: It's probably only necessary to check the first several strings.
     */
    for any i in (0..dex.header.string_ids_size - 1) : (dex.string_ids[i].offset + dex.string_ids[i].item_size + 1 < dex.string_ids[i + 1].offset)
}

private rule dexlib2_map_type_order
{
  condition:
    /*
     * The map_list types are in different orders for DX, dexmerge, and dexlib (1 and 2 are the same)
     */
    dex.map_list.map_items[7].type == 0x2002 // TYPE_STRING_DATA_ITEM
}

private rule null_interfaces
{
  condition:
    /*
     * Dexlib2 adds a non-zero interfaces_offset to every class_def_item, even if the class doesn't implement an
     * interface. It points to 4 null bytes right after string pool. DEX documentation says the value for
     * interfaces_offset should be 0 if there is no interface, which is what DX does. It's enough to check
     * if a single class has an interface which points to null bytes since no one else does this.
     */
    for any i in (0..dex.header.class_defs_size) : (dex.class_defs[i].interfaces_offset > 0 and uint32(dex.class_defs[i].interfaces_offset) == 0)
}

private rule dx_map_type_order
{
  condition:
    /*
     * The map_list types are in different orders for DX, dexmerge, and dexlib (1 and 2 are the same)
     * DX order derrived from: http://osxr.org/android/source/dalvik/dx/src/com/android/dx/dex/file/DexFile.java#0111
     */
    (dex.map_list.map_items[7].type == 0x1002 or // TYPE_ANNOTATION_SET_REF_LIST
    dex.map_list.map_items[7].type == 0x1003 or  // TYPE_ANNOTATION_SET_ITEM
    dex.map_list.map_items[7].type == 0x2001)    // TYPE_CODE_ITEM
}

private rule dexmerge_map_type_order
{
  condition:
    /*
     * The map_list types are in different orders for DX, dexmerge, and dexlib (1 and 2 are the same)
     * DexMerge order derrived from: http://osxr.org/android/source/dalvik/dx/src/com/android/dx/merge/DexMerger.java#0111
     */
    dex.map_list.map_items[7].type == 0x1000 // TYPE_MAP_LIST
}

rule jack_4_12 : compiler
{
  meta:
    description = "Jack 4.12"

  strings:
    $jack_emitter = {00 12 65 6D 69 74 74 65 72 3A 20 6A 61 63 6B 2D 34 2E 31 32 00}

  condition:
    is_dex and $jack_emitter
}

rule jack_3x : compiler
{
  meta:
    description = "Jack 3.x"

  strings:
    //\0<len>emitter: jack-3.??\0
    $jack_emitter = {00 1? 65 6D 69 74 74 65 72 3A 20 6A 61 63 6B 2D 33 2E [1-3] 00}

  condition:
    is_dex and $jack_emitter
}

rule jack_4x : compiler
{
  meta:
    description = "Jack 4.x"

  strings:
    //\0<len>emitter: jack-4.??\0
    $jack_emitter = {00 1? 65 6D 69 74 74 65 72 3A 20 6A 61 63 6B 2D 34 2E [1-3] 00}

  condition:
    is_dex and not jack_4_12 and $jack_emitter
}

rule jack_5x : compiler
{
  meta:
    description = "Jack 5.x"

  strings:
    //\0<len>emitter: jack-5.??\0
    $jack_emitter = {00 1? 65 6D 69 74 74 65 72 3A 20 6A 61 63 6B 2D 35 2E [1-3] 00}

  condition:
    is_dex and $jack_emitter
}

private rule has_jack_anon_methods
{
  // https://calebfenton.github.io/2016/12/01/building-with-and-detecting-jack/
  strings:
    $anon_set = {00 05 2D 73 65 74 30 00} // -set0
    $anon_get = {00 05 2D 67 65 74 30 00} // -get0
    $anon_wrap = {00 06 2D 77 72 61 70 30 00} // -wrap0

  condition:
    2 of ($anon_*)
}

private rule jack_emitter
{
  strings:
    // "\0<len>emitter: jack-?.?\0"
    $jack_emitter = {00 1? 65 6D 69 74 74 65 72 3A 20 6A 61 63 6B 2D ?? 2E [1-3] 00}

  condition:
    $jack_emitter or has_jack_anon_methods
}

private rule has_javac_anon_methods
{
  // https://calebfenton.github.io/2016/12/01/building-with-and-detecting-jack/
  strings:
    $anon_set = {00 0A 61 63 63 65 73 73 24 30 30 32 00} // access$002
    $anon_get = {00 0A 61 63 63 65 73 73 24 30 30 30 00} // access$000
    $anon_wrap = {00 0A 61 63 63 65 73 73 24 31 30 30 00} // access$100

  condition:
    2 of ($anon_*)
}

rule jack_generic : compiler
{
  // http://tools.android.com/tech-docs/jackandjill
  meta:
    description = "Jack (unknown version)"

  condition:
    is_dex
    and not jack_3x and not jack_4x and not jack_5x
    and not jack_4_12
    and (jack_emitter or has_jack_anon_methods)
}

rule dexlib1 : compiler
{
  meta:
    description = "dexlib 1.x"

  condition:
    unsorted_string_table
}

rule dexlib2 : compiler
{
  meta:
    description = "dexlib 2.x"

  condition:
    not dexlib1 and dexlib2_map_type_order
}

rule dexlib2beta : compiler
{
  meta:
    description = "dexlib 2.x beta"

  condition:
    not dexlib1
    and not dexlib2
    and null_interfaces
}

rule dx : compiler
{
  meta:
    description = "dx"

  condition:
    dx_map_type_order
    and not dexlib1
    and not dexlib2
    and not dexlib2beta
}

rule dx_merged : compiler
{
  meta:
    description = "dx (possible dexmerge)"

  condition:
    dexmerge_map_type_order
    and not dexlib1
    and not dexlib2
    and not dexlib2beta
}

rule dexmerge : manipulator
{
  meta:
    description = "dexmerge"

  condition:
    dexmerge_map_type_order
}


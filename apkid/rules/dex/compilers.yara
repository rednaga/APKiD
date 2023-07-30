/*
 * Copyright (C) 2023  RedNaga. https://rednaga.io
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

private rule unsorted_string_pool : internal
{
  meta:
    description = "String pool in non-standard order"

  condition:
    /*
     * DEX format requires string IDs to be sorted according to the data at their offsets but the actual
     * ordering of the string pool is undefined. Dexlib (smali/apktool) 1.x sorts strings by class and
     * proximity. DX sorts the string pool in the same order as the string table.
     *
     * Note: It's probably only necessary to check the first several strings.
     */
    for any i in (0..dex.header.string_ids_size - 1) : (dex.string_ids[i + 1].offset < dex.string_ids[i].offset)
}

private rule dexlib2_map_type_order : internal
{
  meta:
    description = "dexlib2 map_list type order"

  condition:
    (dex.map_list.map_item[7].type == 0x2002 and dex.map_list.map_item[8].type == 0x1001)
    or (dex.map_list.map_item[6].type == 0x2002 and dex.map_list.map_item[7].type == 0x1001)
}

private rule null_interfaces : internal
{
  meta:
    description = "null interfaces offset"

  condition:
    /*
     * Dexlib2 adds a non-zero interfaces_offset to every class_def_item, even if the class doesn't implement an
     * interface. It points to 4 null bytes right after string pool. DEX documentation says the value for
     * interfaces_offset should be 0 if there is no interface, which is what DX does. It's enough to check
     * if a single class has an interface which points to null bytes since no one else does this.
     */
    for any i in (0..dex.header.class_defs_size) : (dex.class_defs[i].interfaces_offset > 0 and uint32(dex.class_defs[i].interfaces_offset) == 0)
}

private rule dx_map_type_order : internal
{
  meta:
    description = "dx map_list type order"

  condition:
    /*
     * Different compiler families tend to order the map_list types differently.
     * DX order derrived from: https://github.com/aosp-mirror/platform_dalvik/blob/2e9d6011fe4f4d2e8c065210d0118e7b9d9f305c/dx/src/com/android/dx/dex/file/DexFile.java#L144
     * The order starting at offset 7 is:
     *   0x1002 = TYPE_ANNOTATION_SET_REF_LIST (optional)
     *   0x1003 = TYPE_ANNOTATION_SET_ITEM (optional)
     *   0x2001 = TYPE_CODE_ITEM (optional, but very common)
     *   0x2006 = TYPE_ANNOTATIONS_DIRECTORY_ITEM (optional)
     *   0x1001 = TYPE_TYPE_LIST (optional, but common)
     *   0x2002 = TYPE_STRING_DATA_ITEM
     * Also, for reference:
     *   0x0000 = TYPE_HEADER_ITEM
     *   0x0001 = TYPE_STRING_ID_ITEM
     *   0x0002 = TYPE_TYPE_ID_ITEM
     *   0x0006 = TYPE_CLASS_DEF_ITEM
     *   0x1000 = TYPE_MAP_LIST
     */
    // missing all TYPE_ANNOTATION*, common case
    (dex.map_list.map_item[7].type == 0x2001 and dex.map_list.map_item[8].type == 0x1001)

    // missing all TYPE_ANNOTATION*, and TYPE_TYPE_LIST so probably very small DEX
    or (dex.map_list.map_item[7].type == 0x2001 and dex.map_list.map_item[8].type == 0x2002)

    // has all TYPE_ANNOTATION*
    or (dex.map_list.map_item[7].type == 0x1002 and dex.map_list.map_item[8].type == 0x1003 and dex.map_list.map_item[9].type == 0x2001 and dex.map_list.map_item[10].type == 0x2006 and dex.map_list.map_item[11].type == 0x1001)

    // missing TYPE_ANNOTATION_SET_REF_LIST
    or (dex.map_list.map_item[7].type == 0x1003 and dex.map_list.map_item[8].type == 0x2001 and dex.map_list.map_item[9].type == 0x2006 and dex.map_list.map_item[10].type == 0x1001)

    // missing TYPE_ANNOTATION_SET_REF_LIST and TYPE_ANNOTATION_SET_ITEM
    or (dex.map_list.map_item[7].type == 0x2001 and dex.map_list.map_item[8].type == 0x2006 and dex.map_list.map_item[9].type == 0x1001)

    // missing TYPE_ANNOTATION_SET_REF_LIST and TYPE_ANNOTATIONS_DIRECTORY_ITEM
    or (dex.map_list.map_item[7].type == 0x1003 and dex.map_list.map_item[8].type == 0x2001 and dex.map_list.map_item[9].type == 0x1001)

    // missing TYPE_ANNOTATION_SET_ITEM
    or (dex.map_list.map_item[7].type == 0x1002 and dex.map_list.map_item[8].type == 0x2001 and dex.map_list.map_item[9].type == 0x2006 and dex.map_list.map_item[10].type == 0x1001)

    // missing TYPE_ANNOTATION_SET_ITEM and TYPE_ANNOTATIONS_DIRECTORY_ITEM
    or (dex.map_list.map_item[7].type == 0x1002 and dex.map_list.map_item[8].type == 0x2001 and dex.map_list.map_item[9].type == 0x1001)

    // missing TYPE_ANNOTATIONS_DIRECTORY_ITEM
    or (dex.map_list.map_item[7].type == 0x1002 and dex.map_list.map_item[8].type == 0x1003 and dex.map_list.map_item[9].type == 0x2001 and dex.map_list.map_item[10].type == 0x1001)

    // missing almost everything, VERY tiny dex
    or (dex.map_list.map_item[1].type == 0x0001 and dex.map_list.map_item[2].type == 0x0002 and dex.map_list.map_item[3].type == 0x0006 and dex.map_list.map_item[4].type == 0x2002 and dex.map_list.map_item[5].type == 0x1000)

    // missing code and (fields | something else), likely small dex
    or (dex.map_list.map_item[6].type == 0x1003 and dex.map_list.map_item[7].type == 0x2006 and dex.map_list.map_item[8].type == 0x1001 and dex.map_list.map_item[9].type == 0x2002)
}

private rule ambiguous_tiny_dex_map_type_order : internal
{
  meta:
    description = "ambiguous tiny dex map type order"

  condition:
    // missing almost everything, dexlib2 and r8 are identical here, impossible to type alone
    (dex.map_list.map_item[1].type == 0x0001 and dex.map_list.map_item[2].type == 0x0002 and dex.map_list.map_item[3].type == 0x0006 and dex.map_list.map_item[4].type == 0x2002 and dex.map_list.map_item[5].type == 0x1003 and dex.map_list.map_item[6].type == 0x1000)
}

private rule r8_map_type_order : internal
{
  meta:
    description = "r8 map_list type order"

  condition:
    /*
     * R8 order derrived from: https://r8.googlesource.com/r8/+/refs/heads/master/src/main/java/com/android/tools/r8/dex/FileWriter.java#731
     * The order starting at offset 7 is:
     *   0x0007 = TYPE_CALL_SITE_ID_ITEM (optional)
     *   0x0008 = TYPE_METHOD_HANDLE_ITEM (optional)
     *   0x2001 = TYPE_CODE_ITEM
     *   0x2003 = TYPE_DEBUG_INFO_ITEM (optional)
     *   0x1001 = TYPE_TYPE_LIST
     */
    // missing TYPE_CALL_SITE_ID_ITEM and TYPE_METHOD_HANDLE_ITEM, common case
    (dex.map_list.map_item[7].type == 0x2001 and dex.map_list.map_item[8].type == 0x2003 and dex.map_list.map_item[9].type == 0x1001)

    // has everything
    or (dex.map_list.map_item[7].type == 0x0007 and dex.map_list.map_item[8].type == 0x0008 and dex.map_list.map_item[9].type == 0x2001 and dex.map_list.map_item[10].type == 0x2003 and dex.map_list.map_item[11].type == 0x1001)

    // missing TYPE_CALL_SITE_ID_ITEM
    or (dex.map_list.map_item[7].type == 0x0008 and dex.map_list.map_item[8].type == 0x2001 and dex.map_list.map_item[9].type == 0x2003 and dex.map_list.map_item[10].type == 0x1001)

    // missing TYPE_METHOD_HANDLE_ITEM
    or (dex.map_list.map_item[7].type == 0x0007 and dex.map_list.map_item[8].type == 0x2001 and dex.map_list.map_item[9].type == 0x2003 and dex.map_list.map_item[10].type == 0x1001)

    // ignore missing TYPE_CALL_SITE_ID_ITEM, TYPE_METHOD_HANDLE_ITEM, and TYPE_DEBUG_INFO_ITEM is possibly identical to dx map type order

    // missing code and (fields | something else), likely small dex
    or (dex.map_list.map_item[6].type == 0x1001 and dex.map_list.map_item[7].type == 0x2002 and dex.map_list.map_item[8].type == 0x2004 and dex.map_list.map_item[9].type == 0x2000 and dex.map_list.map_item[10].type == 0x1003)
}

private rule r8_marker : internal
{
  meta:
    description = "r8 hidden marker"

  strings:
    // Example: ~~D8{"compilation-mode":"
    $marker = { 00 [1-2] 7E 7E ( 44 | 52 | 4C ) 38 7B 22 63 6F 6D 70 69 6C 61 74 69 6F 6E 2D 6D 6F 64 65 22 3A 22 }

  condition:
    /*
     * Marker logic from: https://r8.googlesource.com/r8/+/refs/heads/master/src/main/java/com/android/tools/r8/dex/Marker.java#18
     */
    $marker
}

private rule dexmerge_map_type_order : internal
{
  meta:
    description = "dexmerge map_list type order"

  condition:
    /*
     * DexMerge order derrived from: https://github.com/aosp-mirror/platform_dalvik/blob/2e9d6011fe4f4d2e8c065210d0118e7b9d9f305c/dx/src/com/android/dx/merge/DexMerger.java#L110
     */
    dex.map_list.map_item[7].type == 0x1000 // TYPE_MAP_LIST
}

rule jack_4_12 : compiler
{
  meta:
    description = "Jack 4.12"
    sample      = "b6a92aec55ab93f2254f12a2ab42f6c53a1b4ba1fbae62623193262e7dc31f26"

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

private rule has_jack_anon_methods : internal
{
  meta:
    description = "has Jack compiler anonymous methods"
    url = "https://calebfenton.github.io/2016/12/01/building-with-and-detecting-jack/"

  strings:
    $anon_set = {00 05 2D 73 65 74 30 00} // -set0
    $anon_get = {00 05 2D 67 65 74 30 00} // -get0
    $anon_wrap = {00 06 2D 77 72 61 70 30 00} // -wrap0

  condition:
    2 of ($anon_*)
}

private rule jack_emitter : internal
{
  meta:
    description = "has Jack compiler emitter string"

  strings:
    // "\0<len>emitter: jack-?.?\0"
    $jack_emitter = {00 1? 65 6D 69 74 74 65 72 3A 20 6A 61 63 6B 2D ?? 2E [1-3] 00}

  condition:
    $jack_emitter or has_jack_anon_methods
}

private rule has_javac_anon_methods : internal
{
  meta:
    description = "has Javac compiler anonymous methods"
    url = "https://calebfenton.github.io/2016/12/01/building-with-and-detecting-jack/"

  strings:
    $anon_set = {00 0A 61 63 63 65 73 73 24 30 30 32 00} // access$002
    $anon_get = {00 0A 61 63 63 65 73 73 24 30 30 30 00} // access$000
    $anon_wrap = {00 0A 61 63 63 65 73 73 24 31 30 30 00} // access$100

  condition:
    2 of ($anon_*)
}

rule jack_generic : compiler
{
  // New Android compiler: http://tools.android.com/tech-docs/jackandjill
  meta:
    description = "Jack (unknown version)"
    sample      = "aaa4aed09a3a014c6e045566b86708f964088a0f9c712f02191cdcf61ff06fe8"

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
    sample      = "cf7b06bd339ee68224420dfcaba84a88e51ae6cd07d504fc8b4f2db6c6889971"

  condition:
    unsorted_string_pool
}

rule dexlib2beta : compiler
{
  meta:
    description = "dexlib 2.x beta"
    sample      = "8fd8c1e2337a4d2ac8f8f64c13a4fb304589ecf165e41de27ebc656a7475a008"

  condition:
    not dexlib1
    and null_interfaces
}

rule dexlib2 : compiler
{
  meta:
    description = "dexlib 2.x"
    sample      = "c7c566b1b185c99e338a77865eaf2eed6dc9b2b97793e262208c0b7f38bbf947"

  condition:
    not dexlib1
    and dexlib2_map_type_order
    and not dexlib2beta
}

rule dx : compiler
{
  meta:
    description = "dx"
    sample      = "6ef06bcc9712ec2ef3b71c5c8454af3abdafa628406b4f5629815995470da878"

  condition:
    dx_map_type_order
    and not dexlib1
    and not dexlib2
    and not dexlib2beta
    and not r8_marker
}

rule dx_merged : compiler
{
  meta:
    description = "dx (possible dexmerge)"
    sample      = "6c31ccd3b10ff2b0fa428e6efa954c37c0d2e641814f63c524c4f8fec9d11e22"

  condition:
    dexmerge_map_type_order
    and not dexlib1
    and not dexlib2
    and not dexlib2beta
    and not r8_marker
}

rule r8 : compiler
{
  meta:
    description = "r8"
    sample      = "e45ea01eedfc7bede77669412cce07b7d41b284bc6ffc9dfa27a519270bbe99a"
    sample2     = "bae4c7c1974fa317ecc8fbbcf7bafa3b1a0d5903fdd3040412c628277cf45258"

  condition:
    r8_marker
    and (r8_map_type_order or ambiguous_tiny_dex_map_type_order)
}

rule r8_merged : compiler
{
  meta:
    description = "r8 (possible dexmerge)"
    sample      = "ee1e901bb862835b227f7e9cfbaaa357402992ee9760b630a05f9b3423520526"

  condition:
    r8_marker
    and dexmerge_map_type_order
}

rule r8_no_marker : compiler
{
  meta:
    // Hiding the marker is easier than hiding the map type order.
    description = "r8 without marker (suspicious)"
    sample      = "f399d833ff54a798d609279bb8a51222c75be9b7fb7b3ab9cc8cb628f7d76257"
    sample2     = "d8a5545eb3c76d8078d778eb5962398d9f2fefab34f971b19beda35e0e76f6ef"

  condition:
    not r8_marker
    and r8_map_type_order
}

rule dexmerge : manipulator
{
  meta:
    description = "dexmerge"
    sample      = "6c31ccd3b10ff2b0fa428e6efa954c37c0d2e641814f63c524c4f8fec9d11e22"

  condition:
    dexmerge_map_type_order
}

rule unknown_compiler : compiler {
  meta:
    description = "unknown (please file detection issue!)"

  condition:
    is_dex
    and not (
      (dexlib1 or dexlib2 or dexlib2beta)
      or (dx or dx_merged)
      or (r8 or r8_merged or r8_no_marker)
      or (jack_generic or jack_3x or jack_4x or jack_4_12 or jack_5x)
      or (dexmerge)
    )
}

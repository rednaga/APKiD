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

include "common.yara"

rule pangxie_dex : packer
{
  meta:
    description = "PangXie"
    example = "ea70a5b3f7996e9bfea2d5d99693195fdb9ce86385b7116fd08be84032d43d2c"

  strings:
    // Lcom/merry/wapper/WapperApplication;
    $wrapper = {
      00 24 4C 63 6F 6D 2F 6D 65 72 72 79 2F 77 61 70
      70 65 72 2F 57 61 70 70 65 72 41 70 70 6C 69 63
      61 74 69 6F 6E 3B 00
    }

  condition:
    is_dex and
    $wrapper
}

rule medusah_dex : packer
{
  meta:
    description = "Medusah"

  strings:
    $wrapper = "Lcom/seworks/medusah"

  condition:
    is_dex and $wrapper
}

rule medusah_appsolid_dex : packer
{
  meta:
    description = "Medusah (AppSolid)"

  strings:
    $loader = "Lweb/apache/sax/app;"
    $main_activity = "Lweb/apache/sax/MainActivity;"

  condition:
    is_dex and $loader and $main_activity
}



rule apkguard_dex : packer
{
  meta:
    description = "APKGuard"
    url         = "http://apkguard.io/"
    example     = "d9c98fff427646883ecb457fc2e9d2a8914ba7a9ee194735e0a18f56baa26cca"

  strings:

    $attachBaseContextOpcodes = {
        120b            // const/4 v11, #int 0 // #0
        6f20 0100 fe00  // invoke-super {v14, v15}, Landroid/app/Application;.attachBaseContext:(Landroid/content/Context;)V // method@0001
        2206 ??00       // new-instance v6, Ljava/io/File; // type@0006
        6e10 ??00 0e00  // invoke-virtual {v14}, Lyxlhycuqv/weudayy;.getFilesDir:()Ljava/io/File; // method@0019
        0c09            // move-result-object v9
        1a0a (2f|30) 00 // const-string v10, "lllllllllllllllllllllllllllllllllllllllll.zip" // string@002f
        7030 ??00 960a  // invoke-direct {v6, v9, v10}, Ljava/io/File;.<init>:(Ljava/io/File;Ljava/lang/String;)V // method@000a
        1a09 1900       //  const-string v9, BASE64_ENCODED_ZIP_FILE
        7120 ??00 b900  // invoke-static {v9, v11}, Landroid/util/Base64;.decode:(Ljava/lang/String;I)[B // method@0003
        0c02            // move-result-object v2
        2205 ??00       // new-instance v5, Ljava/io/FileOutputStream; // type@0007
        7020 ??00 6500  // invoke-direct {v5, v6}, Ljava/io/FileOutputStream;.<init>:(Ljava/io/File;)V // method@000c
        2201 ??00       // new-instance v1, Ljava/io/BufferedOutputStream; // type@0005
        7020 ??00 5100  // invoke-direct {v1, v5}, Ljava/io/BufferedOutputStream;.<init>:(Ljava/io/OutputStream;)V // method@0006
        6e20 ??00 2100  // invoke-virtual {v1, v2}, Ljava/io/BufferedOutputStream;.write:([B)V // method@0009
        6e10 ??00 0100  // invoke-virtual {v1}, Ljava/io/BufferedOutputStream;.flush:()V // method@0008
        6e10 ??00 0100  // invoke-virtual {v1}, Ljava/io/BufferedOutputStream;.close:()V // method@0007
        6e10 ??00 0600  // invoke-virtual {v6}, Ljava/io/File;.getAbsolutePath:()Ljava/lang/String; // method@000b
        0c03            // move-result-object v3
        6e10 ??00 0e00  // invoke-virtual {v14}, Lyxlhycuqv/weudayy;.getFilesDir:()Ljava/io/File; // method@0019
        0c09            // move-result-object v9
        6e10 ??00 0900  // invoke-virtual {v9}, Ljava/io/File;.getAbsolutePath:()Ljava/lang/String; // method@000b
        0c07            // move-result-object v7
        6e10 ??00 0e00  // invoke-virtual {v14}, Lyxlhycuqv/weudayy;.getClassLoader:()Ljava/lang/ClassLoader; // method@0018
        0c00            // move-result-object v0
        2204 ??00       //  new-instance v4, Ldalvik/system/DexClassLoader; // type@0004
        1209            // const/4 v9, #int 0 // #0
        7050 ??00 3497  // invoke-direct {v4, v3, v7, v9, v0}, Ldalvik/system/DexClassLoader;.<init>:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V // method@0004
        1a09 ??00       // const-string v9, "yabno/blkngwigpd" // string@003d
        6e20 ??00 9400  // invoke-virtual {v4, v9}, Ldalvik/system/DexClassLoader;.loadClass:(Ljava/lang/String;)Ljava/lang/Class; // method@0005
        0c09            // move-result-object v9
        120a            // const/4 v10, #int 0 // #0
        23aa ??00       // new-array v10, v10, [Ljava/lang/Class; // type@0016
        6e20 ??00 a900  // invoke-virtual {v9, v10}, Ljava/lang/Class;.getConstructor:([Ljava/lang/Class;)Ljava/lang/reflect/Constructor; // method@000d
        0c09            // move-result-object v9
        120a            // const/4 v10, #int 0 // #0
        23aa ??00       // new-array v10, v10, [Ljava/lang/Object; // type@0017
        6e20 ??00 a900  // invoke-virtual {v9, v10}, Ljava/lang/reflect/Constructor;.newInstance:([Ljava/lang/Object;)Ljava/lang/Object; // method@0013
        0c09            // move-result-object v9
        5be9 0000       // iput-object v9, v14, Lyxlhycuqv/weudayy;.aaa:Ljava/lang/Object; // field@0000
        54e9 0000       // iget-object v9, v14, Lyxlhycuqv/weudayy;.aaa:Ljava/lang/Object; // field@0000
        6e10 ??00 0900  // invoke-virtual {v9}, Ljava/lang/Object;.getClass:()Ljava/lang/Class; // method@0012
        0c09            // move-result-object v9
        1a0a ??00       // const-string v10, "attachBaseContext" // string@0022
        121b            // const/4 v11, #int 1 // #1
        23bb ??00       // new-array v11, v11, [Ljava/lang/Class; // type@0016
        120c            // const/4 v12, #int 0 // #0
        1c0d ??00       // const-class v13, Landroid/content/Context; // type@0002
        4d0d 0b0c       // aput-object v13, v11, v12
        6e30 ??00 a90b  // invoke-virtual {v9, v10, v11}, Ljava/lang/Class;.getDeclaredMethod:(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method; // method@000e
        0c09            // move-result-object v9
        54ea 0000       // iget-object v10, v14, Lyxlhycuqv/weudayy;.aaa:Ljava/lang/Object; // field@0000
        121b            // const/4 v11, #int 1 // #1
        23bb ??00       // new-array v11, v11, [Ljava/lang/Object; // type@0017
        120c            // const/4 v12, #int 0 // #0
        4d0e 0b0c       // aput-object v14, v11, v12
        6e30 ??00 a90b  // invoke-virtual {v9, v10, v11}, Ljava/lang/reflect/Method;.invoke:(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object; // method@0015
        0e00            // return-void
        0d08            // move-exception v8
        6e10 ??00 0800  // invoke-virtual {v8}, Ljava/lang/Exception;.printStackTrace:()V // method@000f
        28fb            // goto 0073 // -0005
    }

  condition:
    is_dex and $attachBaseContextOpcodes
}



rule cryptoshell_dex : packer
{
  meta:
    description = "CryptoShell"
    url         = "http://cryptoshell.io"
    example     = "d6745c1533b440c93f7bdfbb106470043b23aafdf91506c52332ed192d7b7003"


  strings:

    $attachBaseContextOpcodes = {
        120b            // const/4 v11, 0
        6f20 0100 fe00  // invoke-super {v14, v15}, Landroid/app/Application.attachBaseContext(Landroid/content/Context;)V ; 0x1
        2206 ??00       // new-instance v6, Ljava/io/File; ; 0x180
        6e10 ??00 0e00  // invoke-virtual {v14}, Llctavku/ngbdjdfqf.getFilesDir()Ljava/io/File; ; 0x19
        0c09            // move-result-object v9
        1a0a ??00       // const-string v10, str.mtuECIoALWpjXcVYbOOKBHNTMligrjLQpGFKT.zip ; 0x239c
        7030 ???? 960a  // invoke-direct {v6, v9, v10}, Ljava/io/File.<init>(Ljava/io/File;Ljava/lang/String;)V ; 0xa
        1a09 ??00       // const-string v9, str.UEsDBBQAAAAIAAMAi0tT_4a5ihQAAGArAAALABwAY2xhc3Nlcy5kZXhVVAkAA1Wg....
        7120 ??00 b900  // invoke-static {v9, v11}, Landroid/util/Base64;.decode:(Ljava/lang/String;I)[B // method@0003
        0c02            // move-result-object v2
        2205 ??00       // new-instance v5, Ljava/io/FileOutputStream; // type@0007
        7020 ??00 6500  // invoke-direct {v5, v6}, Ljava/io/FileOutputStream;.<init>:(Ljava/io/File;)V // method@000c
        2201 ??00       // new-instance v1, Ljava/io/BufferedOutputStream; // type@0005
        7020 ??00 5100  // invoke-direct {v1, v5}, Ljava/io/BufferedOutputStream;.<init>:(Ljava/io/OutputStream;)V // method@0006
        6e20 ??00 2100  // invoke-virtual {v1, v2}, Ljava/io/BufferedOutputStream;.write:([B)V // method@0009
        6e10 ??00 0100  // invoke-virtual {v1}, Ljava/io/BufferedOutputStream;.flush:()V // method@0008
        6e10 ??00 0100  // invoke-virtual {v1}, Ljava/io/BufferedOutputStream;.close:()V // method@0007
        6e10 ??00 0600  // invoke-virtual {v6}, Ljava/io/File;.getAbsolutePath:()Ljava/lang/String; // method@000b
        0c03            // move-result-object v3
        6e10 ??00 0e00  // invoke-virtual {v14}, Lyxlhycuqv/weudayy;.getFilesDir:()Ljava/io/File; // method@0019
        0c09            // move-result-object v9
        6e10 ??00 0900  // invoke-virtual {v9}, Ljava/io/File;.getAbsolutePath:()Ljava/lang/String; // method@000b
        0c07            // move-result-object v7
        6e10 ??00 0e00  // invoke-virtual {v14}, Lyxlhycuqv/weudayy;.getClassLoader:()Ljava/lang/ClassLoader; // method@0018
        0c00            // move-result-object v0
        2204 ??00       //  new-instance v4, Ldalvik/system/DexClassLoader; // type@0004
        1209            // const/4 v9, #int 0 // #0
        7050 ??00 3497  // invoke-direct {v4, v3, v7, v9, v0}, Ldalvik/system/DexClassLoader;.<init>:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V // method@0004
        1a09 ??00       // const-string v9, "yabno/blkngwigpd" // string@003d
        6e20 ??00 9400  // invoke-virtual {v4, v9}, Ldalvik/system/DexClassLoader;.loadClass:(Ljava/lang/String;)Ljava/lang/Class; // method@0005
        0c09            // move-result-object v9
        120a            // const/4 v10, #int 0 // #0
        23aa ??00       // new-array v10, v10, [Ljava/lang/Class; // type@0016
        6e20 ??00 a900  // invoke-virtual {v9, v10}, Ljava/lang/Class;.getConstructor:([Ljava/lang/Class;)Ljava/lang/reflect/Constructor; // method@000d
        0c09            // move-result-object v9
        120a            // const/4 v10, #int 0 // #0
        23aa ??00       // new-array v10, v10, [Ljava/lang/Object; // type@0017
        6e20 ??00 a900  // invoke-virtual {v9, v10}, Ljava/lang/reflect/Constructor;.newInstance:([Ljava/lang/Object;)Ljava/lang/Object; // method@0013
        0c09            // move-result-object v9
        5be9 0000       // iput-object v9, v14, Lyxlhycuqv/weudayy;.aaa:Ljava/lang/Object; // field@0000
        54e9 0000       // iget-object v9, v14, Lyxlhycuqv/weudayy;.aaa:Ljava/lang/Object; // field@0000
        6e10 ??00 0900  // invoke-virtual {v9}, Ljava/lang/Object;.getClass:()Ljava/lang/Class; // method@0012
        0c09            // move-result-object v9
        1a0a ??00       // const-string v10, "attachBaseContext" // string@0022
        121b            // const/4 v11, #int 1 // #1
        23bb ??00       // new-array v11, v11, [Ljava/lang/Class; // type@0016
        120c            // const/4 v12, #int 0 // #0
        1c0d ??00       // const-class v13, Landroid/content/Context; // type@0002
        4d0d 0b0c       // aput-object v13, v11, v12
        6e30 ??00 a90b  // invoke-virtual {v9, v10, v11}, Ljava/lang/Class;.getDeclaredMethod:(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method; // method@000e
        0c09            // move-result-object v9
        54ea 0000       // iget-object v10, v14, Lyxlhycuqv/weudayy;.aaa:Ljava/lang/Object; // field@0000
        121b            // const/4 v11, #int 1 // #1
        23bb ??00       // new-array v11, v11, [Ljava/lang/Object; // type@0017
        120c            // const/4 v12, #int 0 // #0
        4d0e 0b0c       // aput-object v14, v11, v12
        6e30 ??00 a90b  // invoke-virtual {v9, v10, v11}, Ljava/lang/reflect/Method;.invoke:(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object; // method@0015
        0e00            // return-void
        0d08            // move-exception v8
        6e10 ??00 0800  // invoke-virtual {v8}, Ljava/lang/Exception;.printStackTrace:()V // method@000f
        28fb            // goto 0073 // -0005
}

  condition:
    is_dex and
    $attachBaseContextOpcodes and
    not apkguard_dex

}

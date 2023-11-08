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

include "common.yara"

rule pangxie_dex : packer
{
  meta:
    description = "PangXie"
    sample      = "ea70a5b3f7996e9bfea2d5d99693195fdb9ce86385b7116fd08be84032d43d2c"

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
    sample      = "b92c0090038f3185908f2fb3b7e927da734040b9332332fc09542e20c615e083"

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
    sample      = "d9c98fff427646883ecb457fc2e9d2a8914ba7a9ee194735e0a18f56baa26cca"

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
    sample      = "d6745c1533b440c93f7bdfbb106470043b23aafdf91506c52332ed192d7b7003"

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


rule jar_pack01 : packer
{
  meta:
    // Official name unknown
    description = "jar_pack01"
    sample      = "faf1e85f878ea52a3b3fbb67126132b527f509586706f242f39b8c1fdb4a2065"

  strings:
    $pre_jar  = { 00 6F 6E 43 72 65 61 74 65 00 28 29 56 00 63 6F 6D 2F 76 } // .onCreate.()V.com/v
    $jar_data = { 2E 6A 61 72 00 2F 64 61 74 61 2F 64 61 74 61 2F 00 2F } // .jar./data/data
    $post_jar = { 2E 6A 61 72 00 77 00 6A 61 76 61 2F 75 74 69 6C 2F 4D 61 70 00 67 65 74 49 6E 74 00 } // .jar.w.java/util/Map.getInt.

  condition:
    is_dex and
    ($pre_jar and $jar_data and $post_jar)
}

rule gaoxor : packer
{
  meta:
    description = "GaoXor"
    url         = "https://github.com/rednaga/APKiD/issues/71"
    sample      = "673b3ab2e06f830e7ece1e3106a6a8c5f4bacd31393998fa73f6096b89f2df47"
    author      = "Eduardo Novella"

  strings:
    $str_0 = { 11 61 74 74 61 63 68 42 61 73 65 43 6F 6E 74 65 78 74 00 } // "attachBaseContext"
    $str_1 = { 04 2F 6C 69 62 00 } // "/lib"
    $str_2 = { 17 4C 6A 61 76 61 2F 6C 61 6E 67 2F 43 6C 61 73 73 4C 6F 61 64 65 72 3B 00 } // Ljava/lang/ClassLoader;
    $str_3 = { 77 72 69 74 65 64 44 65 78 46 69 6C 65 00 } // writedDexFile

    /**
      public void attachBaseContext(Context base) {
          super.attachBaseContext(base);
          try {
              getClass().getDeclaredMethod(GaoAoxCoJpRm("MS4zNiguNyIBJCQ9HAU="), new Class[0]).invoke(this, new Object[0]);
          } catch (Exception e) {
          }
      }
    */
    $attachBaseContextOpcodes = {
        // method.public.Lpykqdxlnyt_iytDlJSoOg.Lpykqdxlnyt_iytDlJSoOg.method.attachBaseContext_Landroid_content_Context__V:
        6f20??004300   // invoke-super {v3, v4}, Landroid/app/Application.attachBaseContext(Landroid/content/Context;)V
        6e10??000300   // invoke-virtual {v3}, Ljava/lang/Object.getClass()Ljava/lang/Class;
        0c00           // move-result-object v0
        1a01??00       // const-string v1, str.MS4zNiguNyIBJCQ9HAU ; 0xdfd
        6e20??001300   // invoke-virtual {v3, v1}, Lpykqdxlnyt/iytDlJSoOg.GaoAoxCoJpRm(Ljava/lang/String;)Ljava/lang/String;
        0c01           // move-result-object v1
        1202           // const/4 v2, 0               ; Protect.java:79
        2322??00       // new-array v2, v2, [Ljava/lang/Class; ; 0x3b8
        6e30??001002   // invoke-virtual {v0, v1, v2}, Ljava/lang/Class.getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
        0c00           // move-result-object v0
        1201           // const/4 v1, 0
        2311??00       // new-array v1, v1, [Ljava/lang/Object; ; 0x3bc
        6e30??003001   // invoke-virtual {v0, v3, v1}, Ljava/lang/reflect/Method.invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
        0e00           // return-void
        0d00           // move-exception v0
        28fe           // goto 0x00002984
    }

    /**
        private byte[] mMuKJXDuYr(byte[] a, byte[] key) {
            byte[] out = new byte[a.length];
            for (int i = 0; i < a.length; i++) {
                out[i] = (byte) (a[i] ^ key[i % key.length]);
            }
            return out;
        }
    */
    $xor_key = {
       21 ?2         //  array-length        v2, p1
       23 21 17 00   //  new-array           v1, v2, [B
       12 00         //  const/4             v0, 0
       21 ?2         //  array-length        v2, p1
       35 20 10 00   //  if-ge               v0, v2, :2A
       48 02 0? 00   //  aget-byte           v2, p1, v0
       21 ?3         //  array-length        v3, p2
       94 03 00 03   //  rem-int             v3, v0, v3
       48 03 0? 03   //  aget-byte           v3, p2, v3
       B7 32         //  xor-int/2addr       v2, v3
       8D 22         //  int-to-byte         v2, v2
       4F 02 01 00   //  aput-byte           v2, v1, v0
       D8 00 00 01   //  add-int/lit8        v0, v0, 1
       28 F0         //  goto                :8
       11 01         //  return-object       v1
    }

  condition:
    $attachBaseContextOpcodes and $xor_key and is_dex and 3 of ($str_*)
}

rule appsealing_loader_1_2_2 : packer
{
  meta:
    // Commercial packer
    description = "AppSealing Loader v1.2.2"
    url         = "https://www.appsealing.com/"
    sample      = "61a983b032aee2e56159e682ad1588ad30fa8c3957bf849d1afe6f10e1d9645d"
    author      = "zeroload"

  strings:
    $loader_ver = /AppSealingLoader [.]+ v1.2.2/
    $class = "Lcom/inka/appsealing/AppSealingApplication;"

  condition:
    is_dex and all of them
}

rule tencent : packer
{
  meta:
    description = "Mobile Tencent Protect"
    url         = "https://intl.cloud.tencent.com/product/mtp"
    sample      = "7c6024abc61b184ddcc9fa49f9fac1a7e5568d1eab09ee748f8c4987844a3f81"

  strings:
    $libshell_a = { 00 0C 6C 69 62 73 68 65 6C 6C 61 2E 73 6F 00 } // libshella.so
    $libshell_b = { 00 0C 6C 69 62 73 68 65 6C 6C 62 2E 73 6F 00 } // libshellb.so
    $libshell_c = { 00 0C 6C 69 62 73 68 65 6C 6C 63 2E 73 6F 00 } // libshellc.so
    // Lcom/tencent/StubShell/TxAppEntry;
    $class_app_entry = {
        00 22 4C 63 6F 6D 2F 74 65 6E 63 65 6E 74 2F 53 74 75 62 53 68 65
        6C 6C 2F 54 78 41 70 70 45 6E 74 72 79 3B 00
    }
    // Lcom/tencent/StubShell/a
    $class_stubshell = {
        00 19 4C 63 6F 6D 2F 74 65 6E 63 65 6E 74 2F 53 74 75 62 53 68 65
        6C 6C 2F 61 3B 00
    }

  condition:
    is_dex
    and 2 of ($libshell_*)
    or 1 of ($class_*)
}

rule crazy_dog_wrapper : packer
{
  meta:
    description = "Crazy Dog Wrapper"
    url         = "https://github.com/rednaga/APKiD/issues/31"
    sample      = "b1f0143c22a588aea89d3a9c0a53fa6d8cea07dd64dec1f82d905f5599acea94"

  strings:
    // libhdog-x86.so
    $lib1 = { 00 0E 6C 69 62 68 64 6F 67 2D 78 38 36 2E 73 6F 00 }
    // libhdog.so
    $lib2 = { 00 0A 6C 69 62 68 64 6F 67 2E 73 6F 00 }
    // Lcom/vdog/VDogApplication;
    $class1 = { 00 1A 4C 63 6F 6D 2F 76 64 6F 67 2F 56 44 6F 67 41 70 70 6C 69 63 61 74 69 6F 6E 3B 00 }
    // Lcom/vdog/VLibrary;
    $class2 = { 00 13 4C 63 6F 6D 2F 76 64 6F 67 2F 56 4C 69 62 72 61 72 79 3B 00 }
    // /.cache/libvdog.so
    $str1 = { 00 12 2F 2E 63 61 63 68 65 2F 6C 69 62 76 64 6F 67 2E 73 6F 00 }

  condition:
    is_dex
    and 2 of them
}

rule jsonpacker : packer
{
  meta:
    description = "JsonPacker"
    sample      = "e23f0a124fdaba30c07a3c40011dd99240af081cec4cdfcb990c811126867e59"
    author      = "Axelle Apvrille"

  strings:
    /* typical XOR algo with junk operations */
    $algo = {
      b0 9b               // add-int/2addr       v11, v9
      da 0? 0? 00         // mul-int/lit8        v12, v11, 0
      b3 9c               // div-int/2addr       v12, v9
      b0 1c               // add-int/2addr       v12, v1
      b0 5c               // add-int/2addr       v12, v5
      93 0? 0? 0?         // div-int             v5, v6, v6
      d8 0? 0? ff         // add-int/lit8        v5, v5, -1
      b0 5c               // add-int/2addr       v12, v5
      b4 66               // rem-int/2addr       v6, v6
      b0 6c               // add-int/2addr       v12, v6
      97 05 0c 0a         // xor-int             v5, v12, v10
    }
    $algo2 = {
      b0 ??                     // add-int/2addr       v4, v12
      da 0? 0? 00               // mul-int/lit8        v4, v4, 0
      b0 ??                     // add-int/2addr       v4, v9
      93 0? 0? 0?               // div-int             v9, v12, v12
      (b3 69 | db 04 04 01)     // div-int/2addr       v9, v6
                                // or:  div-int/lit8        v4, v4, 0x1
      (b7 69 | df 04 04 01)     // xor-int/2addr       v9, v6
                                // or: xor-int/lit8        v4, v4, 0x1
      b0 ??                     // add-int/2addr       v4, v9
      94 0? 0? 0?               // rem-int             v9, v12, v12
      b0 ??                     // add-int/2addr       v4, v9
      (b7 b4 | 97 04 07 09 )    // xor-int/2addr       v4, v11
                                // or: xor-int             v4, v7, v9
    }
    $algo3 = {
      b0 36
      dc 07 05 02         // add-int/2addr       v6, v3
      48 07 02 07         // rem-int/lit8        v7, v5, 0x2
      d8 08 06 e5         // aget-byte           v7, v2, v7
      d8 08 08 26         // add-int/lit8        v8, v6, -27
      91 03 08 03         // sub-int             v3, v8, v3
      b7 74               // xor-int/2addr       v4, v7
    }
    $dexclass = {
      6e 20 ?? ?? 10 00   // invoke-virtual      {v0, v1}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;
      0c ??               // move-result-object  p1
      1f 0?               // check-cast          p1, Ldalvik/system/DexClassLoader;
    }

   condition:
     is_dex
     and ($algo or $algo2 or $algo3)
     and $dexclass
}

rule multidexpacker : packer
{
  meta:
    description = "MultidexPacker"
    sample      = "49d167f8f7427f0340297ae1c89ce4a216a8e64c55294f8e422f1f972732bae7"
    author      = "Axelle Apvrille"
    url         = "https://cryptax.medium.com/multidex-trick-to-unpack-android-bianlian-ed52eb791e56"

  strings:
    /* the strings for the implementation of MultiDex are de-obfuscated */
    $multidex_deobfuscation = {
      13 00 58 01         // const/16            v0, 344
      71 10 ?? ?? 00 00   // invoke-static       b->a(I)String, v0     # DECRYPTED_STRING: "multidex.version"
      0C 00               // move-result-object  v0
      69 00 ?? ??         // sput-object         v0, b->e:String
      13 00 67 01         // const/16            v0, 359
      71 10 ?? ?? 00 00   // invoke-static       b->a(I)String, v0     # DECRYPTED_STRING: "timestamp" (0x1)
      0C 00               // move-result-object  v0
      69 00 ?? ??         // sput-object         v0, b->f:String
      13 00 76 01         // const/16            v0, 374
      71 10 ?? ?? 00 00   // invoke-static       b->a(I)String, v0     # DECRYPTED_STRING: "crc" (0x1)
    }

    /* decrypting the DEX and writing it in classes.dex */
    $decrypt_dex = {
      70 20 ?? ?? 40 00   // invoke-direct       ZipEntry-><init>(String)V, v0, v4
      6E 10 ?? ?? 0? 00   // invoke-virtual      ZipEntry->getTime()J, p1
      0B 0?               // move-result-wide    v4
      6E 30 ?? ?? 40 05   // invoke-virtual      ZipEntry->setTime(J)V, v0, v4, v5
      6E 20 ?? ?? 03 00   // invoke-virtual      ZipOutputStream->putNextEntry(ZipEntry)V, v3, v0
      62 00 ?? ??         // sget-object         v0, b->decryption_key:String
      22 04 ?? ??         // new-instance        v4, InflaterInputStream
      70 20 ?? ?? 14 00   // invoke-direct       InflaterInputStream-><init>(InputStream)V, v4, v1
      22 05 ?? ??         // new-instance        v5, InflaterOutputStream
      70 20 ?? ?? 35 00   // invoke-direct       InflaterOutputStream-><init>(OutputStream)V, v5, v3
      71 30 ?? ?? 40 05   // invoke-static       k->decrypt(String, InputStream, OutputStream)V, v0, v4, v5
    }

  condition:
     is_dex
     and $multidex_deobfuscation
     and $decrypt_dex
}

rule appguard_dex : packer
{
  meta:
    description = "AppGuard"
    url         = "http://appguard.nprotect.com/en/index.html"
    sample      = "23cd2af10d46459065ea65b2d40fb706fd4847a1f8ef195cbebf1c6d8d54a48a"
    author      = "Eduardo Novella"

  strings:
    $class1 = { 00?? 4c63 6f6d 2f69 6e63 612f 7365 6375 7269 7479 2f
               (49|69) (49|69) (49|69) (49|69) (49|69) (49|69) (49|69)
               [0-10] 3b 00} // Lcom/inca/security/IIIiiiiIii;
    $class2 = { 00 254c 636f 6d2f 696e 6361 2f73 6563
                7572 6974 792f 5072 6f78 792f 4a4e 4953
                6f78 5072 6f78 793b 00} // .%Lcom/inca/security/Proxy/JNISoxProxy;.
    $class3 = { 00 2b4c 636f 6d2f 696e 6361 2f73 6563
                7572 6974 792f 5365 7276 6963 652f 4170
                7047 7561 7264 5365 7276 6963 653b 00} // .+Lcom/inca/security/Service/AppGuardService;.

  condition:
    is_dex and any of them
}

rule custom_multidex : packer
{
  meta:
    description = "Custom Multidex"
    sample1     = "b8f8948187846371eb32b2d7ef4f537c94997329e08d762b9ac6b3bfcbc86993"
    sample2     = "fdf5b6930d38da33ec117d7c0f83f142db1c33013d020f0ab4801d1fd781f552"
    author      = "ReBensk"

  strings:
    $cipher = {
      1a00 ????       // const-string v0, // string@00c9
      7110 ???? 0000  // invoke-static {v0}, Ljava/nio/charset/Charset;.forName:(Ljava/lang/String;)Ljava/nio/charset/Charset; // method@0067
      0c00            // move-result-object v0
      6900 ????       // sput-object v0, Lᵔˎʻᐧـˏ/יﹳﹶˆˆ/ˊﾞᵔٴʼי/ᴵˆᵔᵎˑʾ/ʼˈˏﾞˎˉ;.defaultCharset:Ljava/nio/charset/Charset; // field@0069
      1a00 ????       // const-string v0, "ﾞﹳﾞـⁱᐧʿـʿʿⁱᵎﹶʽʾﾞʽٴיᵎﹶʼʼʽˑˉᵎʼٴי// ˋᵎʼـʿʿʼˈʽᵔ" // string@01a2
      7110 ???? 0000  // invoke-static {v0}, Lᵔˎʻᐧـˏ/יﹳﹶˆˆ/ˊﾞᵔٴʼי/ᴵˆᵔᵎˑʾ/ʼˈˏﾞˎˉ;.encodePass:(Ljava/lang/String;)Ljava/lang/String; // method@0082
      0c00            // move-result-object v0
      6900 ????       // sput-object v0 Lᵔˎʻᐧـˏ/יﹳﹶˆˆ/ˊﾞᵔٴʼי/ᴵˆᵔᵎˑʾ/ʼˈˏﾞˎˉ;.globalPass:Ljava/lang/String; // field@006a
      0e00            // return-void
    }
    $cipher2 = {
      1201            // const/4 v1, #int 0 // #0 
      2203 ????       // new-instance v3, Ljavax/crypto/spec/SecretKeySpec; // type@006a
      6e10 ???? 0700  // invoke-virtual {v7}, Ljava/lang/String;.getBytes:()[B // method@004f
      0c04            // move-result-object v4
      1a05 ????       // const-string v5, "AES" // string@001e
      7030 ???? 4305  // invoke-direct {v3, v4, v5}, Ljavax/crypto/spec/SecretKeySpec;.<init>:([BLjava/lang/String;)V // method@0072
      1a04 ????       // const-string v4, "AES" // string@001e
      7110 ???? 0400  // invoke-static {v4}, Ljavax/crypto/Cipher;.getInstance:(Ljava/lang/String;)Ljavax/crypto/Cipher; // method@0070
      0c00            // move-result-object v0
      1224            // const/4 v4, #int 2 // #2
      6e30 ???? 4003  // invoke-virtual {v0, v4, v3}, Ljavax/crypto/Cipher;.init:(ILjava/security/Key;)V // method@0071
      6e20 ???? 6000  // invoke-virtual {v0, v6}, Ljavax/crypto/Cipher;.doFinal:([B)[B // method@006f
      0c01            // move-result-object v1
      1101            // return-object v1
      0d02            // move-exception v2
      6e10 ???? 0200  // invoke-virtual {v2}, Ljava/lang/Exception;.printStackTrace:()V // method@0043
      28fb            // goto 001a // -0005
    }
    $cipher3 = {
      7110 ???? 0100  // invoke-static {v1}, Lᵔˎʻᐧـˏ/יﹳﹶˆˆ/ˊﾞᵔٴʼי/ᴵˆᵔᵎˑʾ/ʼˈˏﾞˎˉ;.encodeToMD516:(Ljava/lang/String;)Ljava/lang/String; // method@0085
      0c00            // move-result-object v0 
      6e10 ???? 0000  // invoke-virtual {v0}, Ljava/lang/String;.toLowerCase:()Ljava/lang/String; // method@0056
      0c00            // move-result-object v0
      1100            // return-object v0
    }

  condition:
    is_dex and all of them
}

rule custom_flutter : packer 
{
  meta:
    description = "Custom Flutter"
    sample1     = "d91a793d7a63ca6279da81ea5986ba51663f0762399ce122d85b09a020521a0c"
    sample2     = "130f9d4c200f8c45df48e49360eb422710db8999f3dc571f10cfb04b139ed0d0"
    author      = "ReBensk"

  strings:
    $attachBaseContextOpcodes = {
      6f20 0100 ba00  // invoke-super {v10, v11}, Landroid/app/Application;.attachBaseContext:(Landroid/content/Context;)V // method@0001
      1a0b ????       // const-string v11, "AppasyOlsoNaMdq_XoCdqeMx" // string@0005
      7110 ???? 0b00  // invoke-static {v11}, Lcom/zzWrgZUeZn;.reewRNuvCn:(Ljava/lang/String;)Ljava/lang/String; // method@0012
      0c0b            // move-result-object v11
      1203            // const/4 v3, #int 0 // #0
      6e30 ???? ba03  // invoke-virtual {v10, v11, v3}, Lcom/zzWrgZUeZn;.getDir:(Ljava/lang/String;I)Ljava/io/File; // method@000e
      0c0b            // move-result-object v11
      1a04 ????       // const-string v4, "ipwaIyIlxoxajdm_VdNeDx" // string@00f3
      7110 ???? 0400  // invoke-static {v4}, Lcom/zzWrgZUeZn;.reewRNuvCn:(Ljava/lang/String;)Ljava/lang/String; // method@0012
      0c04            // move-result-object v4
      6e30 ???? 4a03  // invoke-virtual {v10, v4, v3}, Lcom/zzWrgZUeZn;.getDir:(Ljava/lang/String;I)Ljava/io/File; // method@000e
      0c04            // move-result-object v4
      6e10 ???? 0400  // invoke-virtual {v4}, Ljava/io/File;.listFiles:()[Ljava/io/File; // method@0020
      0c05            // move-result-object v5
      2155            // array-length v5, v5
      3905 0d00       // if-nez v5, 0030 // +000d
    }
    $cipher = {
      1a00 ????       // const-string v0, "WATEPSY/cEDCnBZ/jPdKNCNSL5GPjawdmdkiWnzg" // string@00b2 // AES/ECB/PKCS5Padding
      7110 ???? 0000  // invoke-static {v0}, Lcom/zzWrgZUeZn;.reewRNuvCn:(Ljava/lang/String;)Ljava/lang/String; // method@0012
      0c00            // move-result-object v0
      1a01 ????       // const-string v1, "3662583155221358" // string@0001
      1a02 ????       // const-string v2, "7243279461549821" // string@0002
      7140 ???? 2140  // invoke-static {v1, v2, v0, v4}, Lcom/zzWrgZUeZn;.DgQYvfuzRk:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[B)[B // method@0006
      0c04            // move-result-object v4
      1104            // return-object v4
    }

  condition:
    is_dex and all of them
}

rule jiagu_k : packer
{
  meta:
    description = "Jiagu K"
    sample1     = "aa666b75ffb3588dd41c8e546d53e353cda67cf278b167c7737b1169262856bb"
    sample2     = "d9baf66e7ac116a8c68599ef16fae5397ac4fd0847e2fcfe3ee2c155ecf4f850"
    author      = "ReBensk"

  strings:
    $classNameString = { 00 10 4C 76 69 72 62 6F 78 2F 53 74 75 62 41 70 70 3B 00 } // Lvirbox/StubApp;
   
  condition:
    is_dex and all of them and (dex.header.data_size + dex.header.data_offset) < dex.header.file_size
}

/*
 * Copyright (C) 2019  RedNaga. https://rednaga.io
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

private rule uses_build_class : internal
{
  meta:
    description = "References android.os.Build class"

  strings:
    // Landroid/os/Build;
    $a = {00 12 4C 61 6E 64 72 6F 69 64 2F 6F 73 2F 42 75 69 6C 64 3B 00}
  condition:
    is_dex
    and $a
}

private rule uses_debug_class : internal
{
  meta:
    description = "References android.os.Debug class"

  strings:
    // Landroid/os/Debug;
    $a = {00 12 4C 61 6E 64 72 6F 69 64 2F 6F 73 2F 44 65 62 75 67 3B 00}
  condition:
    is_dex
    and $a
}

private rule uses_telephony_class : internal
{
  meta:
    description = "References android.telephony.TelephonyManager class"

  strings:
    // Landroid/telephony/TelephonyManager;
    $a = {00 24 4C 61 6E 64 72 6F 69 64 2F 74 65 6C 65 70 68 6F 6E 79 2F 54
          65 6C 65 70 68 6F 6E 79 4D 61 6E 61 67 65 72 3B 00}
  condition:
    is_dex
    and $a
}

rule checks_build_fingerprint : anti_vm
{
  meta:
    description = "Build.FINGERPRINT check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    // FINGERPRINT
    $prop = {00 0B 46 49 4E 47 45 52 50 52 49 4E 54 00}
    // generic
    $str_1 = {00 07 67 65 6E 65 72 69 63 00 0A}
    // unknown
    $str_2 = {00 07 75 6E 6B 6E 6F 77 6E 00}
    $str_3 = "generic/sdk/generic"
    $str_4 = "generic/generic/generic"
    $str_5 = "generic/google_sdk/generic"
    $str_6 = "generic_x86/sdk_x86/generic_x86"
    $str_7 = "Android/full_x86/generic_x86"
    $str_8 = "generic/vbox86p/vbox86p"

  condition:
    uses_build_class
    and $prop
    and 1 of ($str_*)
}

rule checks_debugger_present : anti_debug
{
  meta:
    description = "Debug.isDebuggerConnected() check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    $debug = "Debug"
    $debugger_connected = "isDebuggerConnected"

  condition:
    uses_debug_class
    and $debug and $debugger_connected
}

rule checks_build_model : anti_vm
{
  meta:
    description = "Build.MODEL check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    // MODEL
    $prop = {00 05 4D 4F 44 45 4C 00}
    // google_sdk
    $str_1 = {00 0A 67 6F 6F 67 6C 65 5F 73 64 6B 00}
    // sdk
    $str_2 = {00 03 73 64 6B 00}
    // Emulator
    $str_3 = {00 08 45 6D 75 6C 61 74 6F 72 00}
    // Android SDK built for x86
    $str_4 = "Android SDK built for x86"
    $str_5 = "Full Android on x86"

  condition:
    uses_build_class
    and $prop
    and 1 of ($str_*)
}

rule checks_build_manufacturer : anti_vm
{
  meta:
    description = "Build.MANUFACTURER check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    // MANUFACTURER
    $prop = {00 0C 4D 41 4E 55 46 41 43 54 55 52 45 52 00}
    // Genymotion
    $str_1 = {00 0A 47 65 6E 79 6D 6F 74 69 6F 6E 00}
    // unknown
    $str_2 = {00 07 75 6E 6B 6E 6F 77 6E 00}

  condition:
    uses_build_class
    and $prop
    and 1 of ($str_*)
}

rule checks_build_brand : anti_vm
{
  meta:
    description = "Build.BRAND check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    // BRAND
    $prop = {00 05 42 52 41 4E 44 00}
    // generic
    $str_1 = {00 07 67 65 6E 65 72 69 63 00 0A}

  condition:
    uses_build_class
    and $prop
    and 1 of ($str_*)
}

rule checks_build_device : anti_vm
{
  meta:
    description = "Build.DEVICE check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    // DEVICE
    $prop = {00 06 44 45 56 49 43 45 00}
    // generic
    $str_1 = {00 07 67 65 6E 65 72 69 63 00 0A}

  condition:
    uses_build_class
    and $prop
    and 1 of ($str_*)
}

rule checks_build_product : anti_vm
{
  meta:
    description = "Build.PRODUCT check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    // PRODUCT
    $prop = {00 07 50 52 4F 44 55 43 54 00}
    // google_sdk
    $str_1 = {00 0A 67 6F 6F 67 6C 65 5F 73 64 6B 00}
    // sdk
    $str_2 = {00 03 73 64 6B 00}

  condition:
    uses_build_class
    and $prop
    and 1 of ($str_*)
}

rule checks_build_hardware : anti_vm
{
  meta:
    description = "Build.HARDWARE check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    // HARDWARE
    $prop = {00 08 48 41 52 44 57 41 52 45 00}
    // goldfish
    $str_1 = {00 08 67 6F 6C 64 66 69 73 68 00}
    // ranchu
    $str_2 = {00 06 72 61 6E 63 68 75 00}
    $str_4 = "vbox86"

  condition:
    uses_build_class
    and $prop
    and 1 of ($str_*)
}

rule checks_build_board : anti_vm
{
  meta:
    description = "Build.BOARD check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    // BOARD
    $prop = {00 05 42 4F 41 52 44 00}
    // unknown
    $str_1 = {00 07 75 6E 6B 6E 6F 77 6E 00}

  condition:
    uses_build_class
    and $prop
    and 1 of ($str_*)
}

rule checks_build_id : anti_vm
{
  meta:
    description = "Build.ID check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    // ID
    $prop = {00 02 49 44 00}
    // FRF91
    $str_1 = {00 05 46 52 46 39 31 00}

  condition:
    uses_build_class
    and $prop
    and 1 of ($str_*)
}

rule possible_build_serial_check : anti_vm
{
  meta:
    description = "possible Build.SERIAL check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    // SERIAL
    $prop = {00 06 53 45 52 49 41 4C 00}
    // Serial is checked for null / 0x0, so no literal

  condition:
    uses_build_class
    and $prop
}

rule checks_build_tags : anti_vm
{
  meta:
    description = "Build.TAGS check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    // TAGS
    $prop = {00 04 54 41 47 53 00}
    // test-keys
    $str_1 = {00 09 74 65 73 74 2D 6B 65 79 73 00}

  condition:
    uses_build_class
    and $prop
    and 1 of ($str_*)
}

rule checks_build_user : anti_vm
{
  meta:
    description = "Build.USER check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    // TAGS
    $prop = {00 04 54 41 47 53 00}
    // android-build
    $str_1 = {00 0D 61 6E 64 72 6F 69 64 2D 62 75 69 6C 64 00}

  condition:
    uses_build_class
    and $prop
    and 1 of ($str_*)
}

rule checks_sim_operator : anti_vm
{
  meta:
    description = "SIM operator check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    // getSimOperator
    $a = {00 0E 67 65 74 53 69 6D 4F 70 65 72 61 74 6F 72 00}
    // Android
    $b = {00 07 41 6E 64 72 6F 69 64 00}

  condition:
    uses_telephony_class
    and all of them
}

rule checks_network_operator : anti_vm
{
  meta:
    description = "network operator name check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    // getNetworkOperatorName
    $a = {00 16 67 65 74 4E 65 74 77 6F 72 6B 4F 70 65 72 61 74 6F 72 4E 61 6D 65 00}
    // Android
    $b = {00 07 41 6E 64 72 6F 69 64 00}

  condition:
    uses_telephony_class
    and all of them
}

rule checks_device_id : anti_vm
{
  meta:
    description = "device ID check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    // getDeviceId
    $a = {00 0B 67 65 74 44 65 76 69 63 65 49 64 00}
    // 000000000000000
    $b = {00 0F 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 00}

  condition:
    uses_telephony_class
    and all of them
}

rule checks_line1_number : anti_vm
{
  meta:
    description = "line 1 number check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    // getLine1Number
    $a = {00 0E 67 65 74 4C 69 6E 65 31 4E 75 6D 62 65 72 00}
    // 155552155
    $b = {00 09 31 35 35 35 35 32 31 35 35 00}

  condition:
    uses_telephony_class
    and all of them
}

rule checks_voicemail_number : anti_vm
{
  meta:
    description = "voice mail number check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    // getVoiceMailNumber
    $a = {00 12 67 65 74 56 6F 69 63 65 4D 61 69 6C 4E 75 6D 62 65 72 00}
    // 15552175049
    $b = {00 0B 31 35 35 35 32 31 37 35 30 34 39 00}

  condition:
    uses_telephony_class
    and all of them
}

rule checks_subscriber_id: anti_vm
{
  meta:
    description = "subscriber ID check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    // getSubscriberId
    $a = {00 0F 67 65 74 53 75 62 73 63 72 69 62 65 72 49 64 00}
    $b = "0000000000"

  condition:
    uses_telephony_class
    and all of them
}

rule checks_network_interface_names: anti_vm
{
  meta:
    description = "network interface name check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    // Ljava/net/NetworkInterface;
    $a = {00 1B 4C 6A 61 76 61 2F 6E 65 74 2F 4E 65 74 77 6F 72 6B 49 6E 74 65 72 66 61 63 65 3B 00}
    // getName
    $b = {00 07 67 65 74 4E 61 6D 65 00 0F}
    // eth0
    $c = {00 04 65 74 68 30 00}

  condition:
    is_dex
    and all of them
}

rule checks_cpuinfo : anti_vm
{
  meta:
    description = "/proc/cpuinfo check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    $a = "/proc/cpuinfo"
    $b = "Goldfish"

  condition:
    is_dex
    and all of them
}

rule checks_build_type : anti_vm
{
  meta:
    description = "ro.build.type check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    $a = "ro.build.type"
    $b = "user"

  condition:
    is_dex
    and all of them
}

rule checks_hardware : anti_vm
{
  meta:
    description = "ro.hardware check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    $a = "ro.hardware"
    $str_1 = "goldfish"
    $str_2 = "ranchu"

  condition:
    is_dex
    and $a
    and 2 of ($str_*)
}

rule checks_product_device : anti_vm
{
  meta:
    description = "ro.product.device check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    $a = "ro.product.device"
    $b = "generic"

  condition:
    is_dex
    and all of them
}

rule checks_kernel_qemu : anti_vm
{
  meta:
    description = "ro.kernel.qemu check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    $a = "ro.kernel.qemu"

  condition:
    is_dex
    and all of them
}

rule possible_ro_secure_check : anti_vm
{
  meta:
    description = "possible ro.secure check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    $a = "ro.secure"

  condition:
    is_dex
    and all of them
}

rule checks_qemu_file : anti_vm
{
  meta:
    description = "emulator file check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    $a = "/init.goldfish.rc"
    $b = "/sys/qemu_trace"
    $c = "/system/bin/qemud"
    $d = "/system/bin/qemu-props"
    $e = "/system/lib/libc_malloc_debug_qemu.so"
    $f = "/dev/qemu_pipe"
    $g = "/dev/socket/qemud"

    // Geny detections
    $h = "/dev/socket/genyd"
    $i = "/dev/socket/baseband_genyd"

  condition:
    1 of them
}

rule possible_vm_check : anti_vm
{
  meta:
    description = "possible VM check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"

  strings:
    $a = "isEmulator"

  condition:
    any of them
}

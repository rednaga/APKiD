import "elf"
include "../apk/packers.yar"

private rule upx_elf32_arm_stub : Packer {
  strings:
    $UPX_STUB = { 1E 20 A0 E3 14 10 8F E2 02 00 A0 E3 04 70 A0 E3 00 00 00 EF 7F 00 A0 E3 01 70 A0 E3 00 00 00 EF }

  condition:
    elf.machine == elf.EM_ARM and $UPX_STUB
}

private rule upx_stub : Packer {
  condition:
    upx_elf32_arm_stub
}

private rule upx_unmodified {
  strings:
    $upx = "UPX!"

  condition:
    $upx in (0..200) and $upx in (filesize - 50 .. filesize) and upx_elf32_arm_stub
}

rule upx_sharedlib_unmodifed {
  strings:
    $upx = "UPX!"

  condition:
    elf.type == elf.ET_DYN
    and $upx in (filesize - 50 .. filesize) and upx_stub
}

// Technically unreleased, fixes included for Android shared libs
rule upx_elf_3_92 : Packer Unmodified {
  strings:
    $copyright = "UPX 3.92 Copyright"

  condition:
    upx_unmodified and $copyright
}

rule upx_elf_3_91 : Packer Unmodified {
  strings:
    $copyright = "UPX 3.91 Copyright"

  condition:
    upx_unmodified and $copyright
}
rule upx_elf_3_09 : Packer Unmodified {
    strings:
	    $copyright = "UPX 3.09 Copyright"

    condition:
        upx_unmodified and $copyright
}

rule upx_elf_3_08 : Packer Unmodified {
    strings:
        $copyright = "UPX 3.08 Copyright"

    condition:
        upx_unmodified and $copyright
}

rule upx_elf_3_07 : Packer Unmodified { 
    strings:
     	$copyright = "UPX 3.07 Copyright"

    condition:
	    upx_unmodified and $copyright
}

rule upx_elf_3_04 : Packer Unmodified {
    strings:
        $copyright = "UPX 3.04 Copyright"

    condition:
        upx_unmodified and $copyright
}

rule upx_elf_3_03 : Packed Unmodified {
    strings:
    	$copyright = "UPX 3.03 Copyright"

	condition:
		upx_unmodified and $copyright
}

rule upx_elf_3_02 : Packed Unmodified {
    strings:
        $copyright = "UPX 3.02 Copyright"
    condition:
        upx_unmodified and $copyright
}

rule upx_elf_3_01 : Packed Unmodified {
  strings:
    $copyright = "UPX 3.01 Copyright"
  condition:
    upx_unmodified and $copyright
}

rule upx_elf_bangcle_secneo : Packed Modified Bangle SecNeo {
  strings:
    // They replace UPX! with SEC!
    $sec = "SEC!"
  condition:
    $sec in (0..200) and $sec in (filesize - 50 .. filesize) and upx_stub
}

rule upx_elf_bangcle_secneo_newer : Packed Modified Bangle SecNeo {
  strings:
    // They replace UPX! with \x03\x02\x01\x00
    $TTO = { 03 02 01 00 }
  condition:
    $TTO in (filesize - 50 .. filesize) and upx_stub
}

rule upx_elf_ijiami : Packed Modified Ijiami {
  strings:
    // They replace UPX! with AJM!
    $ajm = "AJM!"
  condition:
    $ajm in (filesize - 50 .. filesize) and upx_stub
}

private rule upx_unknown_version : Packer {
  condition:
    upx_stub
    // We could extend this for more comprehensive rules, however lower versions than this should not be
    // appears on arm/android devices
    and not (upx_elf_3_01 or upx_elf_3_02 or upx_elf_3_03 or upx_elf_3_04 or upx_elf_3_07 or upx_elf_3_08 or upx_elf_3_09 or upx_elf_3_91 or upx_elf_3_92)
    and not (upx_elf_ijiami or upx_elf_bangcle_secneo or upx_elf_bangcle_secneo_newer)
}

rule upx_embedded_inside_elf : Dropper Packer {
  strings:
    $elf_magic = { 7F 45 4C 46 }

  condition:
    $elf_magic at 0 and $elf_magic in (256..filesize)
    and upx_unknown_version
    and not upx_unmodified
    and not upx_sharedlib_unmodifed
}

rule upx_unknown_version_modified : Packer {
  condition:
    upx_unknown_version
    and not apk
    and not upx_unmodified
    and not bangcle
    and not upx_elf_bangcle_secneo
    and not upx_elf_bangcle_secneo_newer
    and not upx_elf_ijiami
    and not ijiami
    and not upx_sharedlib_unmodifed
    and not upx_embedded_inside_elf
}

rule upx_compressed_apk : Packer Compressed Android {
  condition:
    upx_unknown_version and apk
    and not (upx_unmodified or ijiami or bangcle or jiangu)
}

rule upx_unknown_version_unmodified : Packer Unmodified {
  condition:
    upx_unknown_version and upx_unmodified
    and not upx_compressed_apk
}

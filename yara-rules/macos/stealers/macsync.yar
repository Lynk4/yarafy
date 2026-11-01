rule MALW_macOS_MacSync_Stealer_Universal {
    meta:
        description = "Universal multi-architecture detection for macOS MacSync Stealer (Intel x86_64 & Apple Silicon ARM64 / Universal Fat Binaries)"
        date = "2026-08-31"
        family = "MacSync"
        threat_type = "Infostealer / Stager / Exfiltrator"
        platform = "macOS (x86_64 & ARM64)"

    strings:
        // XOR Modifier: Scans all 256 keys: 0x00 - 0xFF across Intel & ARM)
        $xor_httpcode   = "/tmp/.httpcode" xor
        $xor_archive    = "/tmp/osalogging.zip" xor
        $xor_osascript  = "osascript" xor
        $xor_curl       = "curl -k -s" xor
        $xor_dd_slice   = "dd if=" xor
        $xor_chunk_fmt  = "chunk_index=" xor
        $xor_dynamic    = "/dynamic?txd=" xor
        $xor_gate       = "/gate?buildtxd=" xor
        $xor_agent      = "CFNetwork/Darwin" xor

        // Unencrypted Format String Tokens & Compiler Artifacts
        $fmt_sess_id    = "%ld-%08x" ascii wide
        $str_obf_class  = "ObfuscatedString" ascii

        // Multi-Architecture C++ Decryption Engine Machine Code
        // x86_64: movsx eax, byte [reg+reg] ; xor eax, <KEY> ; mov byte [reg+reg], dl/al
        $op_xor_x86_64  = { 0F BE ?? ?? 35 ?? 00 00 00 88 }

        // POSIX Daemonization & Stream Manipulation System Imports (Identical across dyld on Intel & ARM64)
        $imp_freopen    = "_freopen" ascii
        $imp_setsid     = "_setsid" ascii
        $imp_stat       = "_stat$INODE64" ascii
        $imp_system     = "_system" ascii
        $imp_fork       = "_fork" ascii

    condition:
        // Mach-O Magic Checks: Thin 64-bit/32-bit (Intel & ARM64) OR Universal Fat Binaries (FAT_MAGIC 0xCAFEBABE / FAT_MAGIC_64 0xCAFEBABF)
        (
            uint32(0) == 0xFEEDFACF or uint32(0) == 0xCFFAEDFE or  // Thin Mach-O 64-bit (x86_64 & ARM64)
            uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or  // Thin Mach-O 32-bit (Legacy x86/ARM)
            uint32(0) == 0xCAFEBABE or uint32(0) == 0xBEBAFECA or  // Universal Fat Binary (32-bit offsets)
            uint32(0) == 0xCAFEBABF or uint32(0) == 0xBFBAFECA     // Universal Fat Binary 64-bit
        ) and
        filesize < 15MB and
        (
            // Primary Detection: Matches any 3 core behavioral strings regardless of XOR key (0x00-0xFF on Intel & ARM)
            (3 of ($xor_*)) or

            // Stripped Variant Detection: XOR loop opcodes + daemonization API imports
            ($op_xor_x86_64 and $imp_freopen and ($imp_setsid or $imp_fork or $imp_stat)) or

            // Universal Pipeline Detection: osascript pipe / dd slice + dyld execution APIs (Intel & ARM64)
            (2 of ($xor_osascript, $xor_dd_slice, $xor_curl, $xor_gate) and $imp_system and ($imp_freopen or $imp_stat)) or

            // Unstripped Variant Detection: ObfuscatedString class template + any single behavioral token
            ($str_obf_class and (1 of ($xor_*) or $fmt_sess_id))
        )
}

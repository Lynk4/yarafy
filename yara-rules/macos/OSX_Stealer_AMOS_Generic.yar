rule OSX_Stealer_AMOS_Generic {
    meta:
        description = "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants"
        date = "2026-08-20"
        sample = "5277bb0dd553d54d81dbd8a12d4634f9"
        malware_family = "Atomic Stealer / AMOS"
        os = "macos"
        silent = 1

    strings:
        // Layer 1: C++ Symbols for serialized build config
        $sym_1 = "build_info_t" ascii
        $sym_2 = "serialized_build_info_t" ascii
        $sym_3 = "_g_serialized_build_info" ascii

        // Layer 2: AMOS Persistence & Artifact Names
        $persist_1 = "com.hlpr.agent" ascii
        $persist_2 = ".hlpr" ascii
        $persist_3 = ".agnt" ascii

        // Layer 3: AMOS C2 Endpoints and Upload Form Fields
        $c2_api_1 = "/api/reports/upload" ascii
        $c2_api_2 = "/api/download/app-bundle" ascii
        $c2_api_3 = "/api/agent/download" ascii
        $c2_field_1 = "report_file=@" ascii
        $c2_field_2 = "build_tag=" ascii

        // Layer 4: Characteristic AMOS Command Lines & TTP Sequences
        $cmd_1 = "SPSoftwareDataType SPHardwareDataType SPDisplaysDataType" ascii
        $cmd_2 = "ditto -c -k --sequesterRsrc" ascii
        $cmd_3 = "security find-generic-password" ascii
        $cmd_4 = "dscl . -authonly" ascii
        $cmd_5 = "com.apple.notificationcenterui doNotDisturb" ascii

        // Layer 5: Bytecode Signatures (ARM64)
        // Rolling-ROR Decryption Loop: bfxil, ldrb, add, ldrb, eor, strb, ror x9, x9, #1
        $op_arm64_dec = { 4b 09 40 b3 6b 01 40 39 [2-6] 8d 41 40 39 ab 01 0b 4a 8b 41 00 39 29 05 c9 93 }

        // Stack-string 32-byte XOR key loader sequences:
        // mov wX, #0x5b22 ; movk wX, #0xf39f, lsl #16 (0xf39f5b22)
        $op_key_load_1 = { 4? 64 8b 52 e? 73 be 72 }
        // mov wX, #0x60cd ; movk wX, #0x5929, lsl #16 (0x592960cd)
        $op_key_load_2 = { a? 19 8c 52 2? 25 ab 72 }

    condition:
        // Mach-O 64-bit, 32-bit, or Universal/FAT binary headers
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or 
         uint32(0) == 0xbebafeca or uint32(0) == 0xcafebabe) and (
            //Symbol indicators + at least one behavioral artifact
            (2 of ($sym_*) and (1 of ($c2_*) or 1 of ($cmd_*) or 1 of ($persist_*) or $op_arm64_dec or 1 of ($op_key_load_*))) or
            
            // C2 endpoints + Recon / Persistence commands / Form fields
            (1 of ($c2_api_*) and (1 of ($cmd_*) or 1 of ($persist_*) or 1 of ($c2_field_*))) or
            
            // Decryption loop + any AMOS artifact / symbol / key loader
            ($op_arm64_dec and (1 of ($sym_*) or 1 of ($c2_*) or 1 of ($cmd_*) or 1 of ($persist_*) or 1 of ($op_key_load_*))) or
            
            // High density of stack string key loader opcodes (for stripped/packed variants)
            (#op_key_load_1 > 3 and #op_key_load_2 > 3) or
            
            // High density of characteristic TTP commands
            (3 of ($cmd_*) and 2 of ($persist_*))
        )
}

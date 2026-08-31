rule macOS_ClickFix_AppleScript_Dropper {
    meta:
        description    = "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader"
        date           = "2026-08-31"
        sample_sha256  = "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72"
        threat_type    = "Dropper / Infostealer Loader"
        platform       = "macOS"
        confidence     = "High"

    strings:
        // Mach-O Magic Header Identification
        $macho_fat_be  = { CA FE BA BE }
        $macho_fat_le  = { BE BA FE CA }
        $macho_64_be   = { FE ED FA CF }
        $macho_64_le   = { CF FA ED FE }

        // S-Box / Key Table (256-byte static table header)
        $sbox = {
            BE 85 31 24 C3 7D 0C 55 74 5D BE 72 FE B1 DE 80
            A7 06 DC 9B 74 F1 9B C1 C1 69 9B E4 86 47 BE EF
        }

        // PBKDF2 / Key Derivation Salt (32 bytes)
        $pbkdf2_salt = {
            B1 CD FF 97 CC 3E B0 8F 2B 4A 53 89 4E CD 52 15
            1A E5 AD 86 89 EA 99 45 06 F9 70 26 F0 34 6A BE
        }

        // HKDF Salt Constant
        $hkdf_salt = {
            85 CD 9E 60 B3 7D E0 B7 33 F7 36 D0 66 DC 49 1A
            54 94 A7 E8 63 1F 03 24 BF 3E 08 2F CC D5 06 5D
        }

        // Hardcoded SHA-256 verification hashes for decrypted payloads
        $payload_hash1 = {
            9E 0B 82 E1 6D 94 C4 8F BF C7 12 00 4D B9 95 BE
            A8 23 E8 97 7A C7 A9 4C D7 C3 A4 F2 FE 08 05 07
        }
        $payload_hash2 = {
            7D B4 3F F8 79 96 2B 55 70 44 2C 2A E5 D2 1F D4
            F6 D8 7D C0 CF DD E7 28 94 39 B4 71 8B 2B EE B9
        }

        // Multi-chunk encrypted payload length table (0x3ef6, 0x410f, 0x3ba4, 0x40f4, 0x3f79)
        $chunk_lengths = {
            F6 3E 00 00 00 00 00 00 0F 41 00 00 00 00 00 00
            A4 3B 00 00 00 00 00 00 F4 40 00 00 00 00 00 00
            79 3F 00 00 00 00 00 00
        }

        // Obfuscated XOR (0x1D) Anti-Analysis / VM Artifact Strings
        $xor_hw_model   = "uj3pryxq"                // "hw.model" ^ 0x1d
        $xor_model_id   = "Pryxq=Tyxsit{txo\x27="   // "Model Identifier: " ^ 0x1d
        $xor_cpu_brand  = "syBniotszvxos3urnihhty9" // "machdep.cpu.brand_string" ^ 0x1d
        $xor_vm_uuid    = "zf4dtjrdmf"              // VM UUID prefix ^ 0x1d

        // Dropper Build / Component Identifier
        $setup_id = "setup-d192a316d9094048ce8251c66418fa61a3f2d45c"

        // ChaCha20 constant
        $chacha20_const = "expand 32-byte k"

    condition:
        // Ensure valid Mach-O file format and size bounds
        ($macho_fat_be at 0 or $macho_fat_le at 0 or $macho_64_be at 0 or $macho_64_le at 0) and
        filesize < 2MB and
        (
            $sbox or
            $setup_id or
            $chunk_lengths or
            ($pbkdf2_salt and ($payload_hash1 or $payload_hash2)) or
            2 of ($xor_hw_model, $xor_model_id, $xor_cpu_brand, $xor_vm_uuid) or
            ($chacha20_const and ($pbkdf2_salt or $hkdf_salt or $payload_hash1 or $payload_hash2))
        )
}

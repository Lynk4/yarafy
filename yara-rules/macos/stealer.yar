rule OSX_Foxveil_AMOS_Stage4_Generic {
    meta:
        description = "Generic detection for Foxveil macOS Loader (AMOS / Atomic macOS Stealer Stage 4) utilizing PBKDF2 key stretching, ChaCha20-Poly1305 payload encryption, LCG stack-string decryption, and memory zeroing wipers"
        date = "2026-09-16"
        reference = "https://bazaar.abuse.ch/sample/841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb/"
        malware_family = "Foxveil / AMOS (Atomic macOS Stealer)"
        threat_type = "Dropper / Loader / InfoStealer"

    strings:
        // Generic ad-hoc signing identifier pattern for disguised fake setups/installers/helpers
        $id_pattern = /(setup|install|installer|update|helper|patch|cleaner|daemon|task|agent|app)-[0-9a-f]{16,64}/ ascii nocase

        // Constructor table reconstruction in __mod_init_func (x86_64)
        $mod_init_x86 = { 8B ?? ?? 03 ?? ?? 89 ?? ?? 48 83 C0 04 48 ( 3D ?? ?? 00 00 | 83 F8 ?? ) 75 }

        // Constructor table reconstruction in __mod_init_func (arm64)
        $mod_init_arm64 = { ?? ?? 68 B8 ?? ?? 68 B8 ?? ?? 0? 0B ?? ?? 28 B8 08 11 00 91 1F ?? ?? F1 ?? ?? ?? 54 }

        // Dynamic API resolution call: dlsym(RTLD_DEFAULT, str) in x86_64 (movq $-2, %rdi; callq _dlsym)
        $dlsym_call_x86 = { 48 C7 C7 FE FF FF FF E8 ?? ?? 00 00 }

        // Dynamic API resolution call: dlsym(RTLD_DEFAULT, str) in arm64 (mov x0, #-2; bl _dlsym)
        $dlsym_call_arm64 = { 20 00 80 92 ?? ?? 00 94 }

        // Linear Congruential Generator (LCG) PRNG constants for string decryption (A = 1103515245, C = 12345) in x86_64
        $lcg_consts_x86 = { 6D 4E C6 41 [0-16] 39 30 00 00 }

        // LCG instruction step in arm64: madd w8, w9, w8, w10 (occurs 200+ times)
        $lcg_madd_arm64 = { 28 29 08 1B }

        // LCG increment constant load in arm64: mov w9, #12345 (occurs 15+ times)
        $lcg_const_arm64 = { 29 07 86 52 }

        // Stack zeroing memory wiper loop after dynamic API resolution (x86_64)
        $wiper_loop_x86 = { C6 84 ?? ?? ?? FF FF 00 48 FF (C0 | C8) [0-4] 75 }

        // PBKDF2 vector XOR accumulation loop (x86_64)
        $pbkdf2_accum_x86 = { 66 0F 6F 84 05 ?? ?? FF FF 66 0F EF 84 05 ?? ?? FF FF 66 0F 7F 84 05 ?? ?? FF FF 48 83 C0 10 48 83 F8 20 75 }

        // High-iteration PBKDF2 key stretching loop bound check (x86_64: 65k to 131k iterations)
        $key_stretch_x86 = { 41 81 FE ?? ?? 01 00 0F 85 }

        // HMAC vector constant initialization on arm64 (ipad = 0x36 / 54, opad = 0x5c / 92)
        $hmac_consts_arm64 = { C0 E6 01 4F [0-8] 81 E7 02 4F }

        // Characteristic minimal dynamic symbol imports
        $sym_dlsym = "_dlsym" ascii
        $sym_chkstk = "____chkstk_darwin" ascii

    condition:
        // Mach-O binary format validation (Fat universal or standalone Mach-O 32/64)
        (uint32(0) == 0xbebafeca or uint32(0) == 0xcafebabe or
         uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe)
        and filesize < 20MB
        and (
            // Condition 1: Fake installer identifier combined with any Foxveil loader engine artifact
            ($id_pattern and 1 of ($mod_init_*, $lcg_*, $wiper_*, $pbkdf2_*, $hmac_*)) or

            // Condition 2: Generic x86_64 Foxveil loader characteristics
            (
                $mod_init_x86 and
                ($lcg_consts_x86 or $pbkdf2_accum_x86 or $key_stretch_x86) and
                #wiper_loop_x86 >= 3 and
                #dlsym_call_x86 >= 5
            ) or

            // Condition 3: Generic arm64 Foxveil loader characteristics
            (
                $mod_init_arm64 and
                ($hmac_consts_arm64 or #lcg_const_arm64 >= 3) and
                #lcg_madd_arm64 >= 10 and
                #dlsym_call_arm64 >= 5
            ) or

            // Condition 4: Multi-architecture core engine match with minimal symbol indicators
            (
                all of ($sym_*) and
                2 of ($mod_init_*, $lcg_consts_x86, $pbkdf2_accum_x86, $hmac_consts_arm64) and
                (#dlsym_call_x86 >= 5 or #dlsym_call_arm64 >= 5)
            )
        )
}

rule Macho_Trojan_CloudSync_1006YR {
    meta:
        silent = 1
        author = "Chandra Kant Bauri"
        description = "Generic detection for CloudSync "
        date = "2026-10-06"
        family = "CloudSync"
        platform = "macOS"

    strings:

        // Invariant 32-byte substitution table (resides in __TEXT,__const, survives full symbol stripping)
        $sobf_sbox = { d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51 }

        // x86_64 machine code sequence for sobf::reveal (imull $-0x7d, %r12d, %eax; andl $0x1f, %r12d)
        $sobf_code_x86 = { 41 6b c4 83 41 83 e4 1f }

        // ARM64 machine code sequence for sobf::reveal (mov w9, #0x83; mul x9, x22, x9; and x11, x22, #0x1f)
        $sobf_code_arm = { 69 10 80 52 c9 7e 09 9b cb 12 40 92 }


        $ns1 = "cloudsync_impl" ascii
        $ns2 = "CSURLInsecureDelegate" ascii
        $ns3 = "_ct_APP_PROCESS_DISGUISE_NAME" ascii
        $ns4 = "_ct_APP_INSTALL_DIR" ascii
        $ns5 = "_ct_APP_OPS_URL" ascii
        $ns6 = "_ct_APP_AUTH_JSON_NAME" ascii
        $ns7 = "_ct_APP_PACKAGE_DAEMON_BIN" ascii
        $ns8 = "_ct_APP_TMP_SPAWN_S_PREFIX" ascii
        $ns9 = "cloudsyncd" ascii

        $ui1 = "AuthDialog" ascii
        $ui2 = "showPasswordDialog" ascii
        $ui3 = "renderCompositeAuthIcon" ascii
        $ui4 = "ModernStatusWindow" ascii
        $ui5 = "AlertButtonHandler" ascii


        // 4. Stage 2 Backdoor Crypto & TLS Evasion Artifacts

        $c1 = "chacha20poly1305" ascii
        $c2 = "chacha20_stream" ascii
        $c3 = "SecTrustSetExceptions" ascii
        $c4 = "SecTrustCopyExceptions" ascii

    condition:
        // Mach-O Magic Header: 64-bit, 32-bit, Universal/Fat binary (Little/Big Endian)
        (
            uint32(0) == 0xfeedfacf or 
            uint32(0) == 0xcafebabe or 
            uint32(0) == 0xbebafeca or 
            uint32(0) == 0xfeedface or 
            uint32(0) == 0xcffaedfe
        ) and
        filesize < 25MB and
        (
            // High-entropy compile-time obfuscator signatures (matches stripped & unstripped variants)
            $sobf_sbox or
            $sobf_code_x86 or
            $sobf_code_arm or

            // Symbol-based detection requiring 3+ specific internal namespace markers
            (3 of ($ns*)) or

            // Phishing dropper detection: fake password dialog combined with namespace/malware strings
            (2 of ($ui*) and (1 of ($ns*) or $c3)) or

            // Backdoor C2 delegate detection: custom insecure delegate combined with trust override & crypto
            ($ns2 and ($c3 or $c4) and (1 of ($c1, $c2) or 1 of ($ns*)))
        )
}

rule Macho_Trojan_CloudSync_1007YR {
    meta:
        silent = 1
        author = "Chandra Kant Bauri"
        description = "Detects CloudSync trojanized DMG disk image containers"
        date = "2026-10-06"
        family = "CloudSync"
        platform = "macOS"

    strings:
        $koly = "koly"
        $xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" ascii
        $plist = "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\"" ascii
        $part = "whole disk (unknown partition : 0)" ascii
        $mish_hdr = "bWlzaAAAAAEAAAAAAAAAAAAAAAAAANg" ascii
        $crc_part = "PbEzG" ascii // Base64 encoding of partition CRC 0x3DB13318

    condition:
        $koly at (filesize - 512) and
        filesize > 1MB and filesize < 100MB and
        $xml in (filesize-100000..filesize) and
        $plist in (filesize-100000..filesize) and
        $part and
        ($mish_hdr or $crc_part)
}
 

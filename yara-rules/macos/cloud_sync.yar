rule Macho_Trojan_CloudSync_Generic {
    meta:
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

        // -------------------------------------------------------------------------
        // 4. Stage 2 Backdoor Crypto & TLS Evasion Artifacts
        // -------------------------------------------------------------------------
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

rule Macho_Trojan_CloudSync_DMG {
    meta:
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

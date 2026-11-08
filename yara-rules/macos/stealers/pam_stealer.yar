rule OSX_Avenger_Stealer {
    meta:
        description = "Avenger / PAM Stealer macOS information stealer binaries"
        author = "Chandra Kant Bauri"
        date = "2026-11-09"
        malware_family = "AvengerStealer"
				hash = "06fdd1d97df1105c542ddb881d751b659d555b5522c266f6364dae9f350fcfd0"
    strings:
        // Cryptographic cha20 RFC 7539 state initialization
        $chacha = "expand 32-byte k" ascii

        // Subprocess IPC execution primitives
        $ipc_pipe   = "_pipe" ascii
        $ipc_spawn  = "_posix_spawnp" ascii
        $ipc_dup2   = "posix_spawn_file_actions_adddup2" ascii

        // Variant 1 (v1.3.x): PAM verification, clipboard harvesting, and embedded helpers
        $crate       = "avenger_agent" ascii
        $kh_id       = "kh-57aebaab0e5de898" ascii
        $api_pam     = "_pam_authenticate" ascii
        $api_pb      = "_NSPasteboardTypeString" ascii
        $api_csr     = "_csr_get_active_config" ascii
        $macho_embed = { CF FA ED FE 0C 00 00 01 }

        // Variant 2 Chrome DevTools Protocol (CDP) & Cocoa workspace automation
        $cdp_nav    = "Page.navigate" ascii
        $cdp_dl1    = "Browser.setDownloadBehavior" ascii
        $cdp_dl2    = "Page.setDownloadBehavior" ascii
        $cocoa_ws   = "NSWorkspaceOpenConfiguration" ascii
        $cocoa_inst = "setCreatesNewApplicationInstance:" ascii
        $cocoa_open = "openApplicationAtURL:configuration:completionHandler:" ascii

    condition:
        (
            (uint32(0) == 0xfeedfacf and (uint32(4) == 0x0100000c or uint32(4) == 0x01000007)) or
            uint32(0) == 0xcafebabe or
            uint32be(0) == 0xcafebabe
        ) and

        filesize < 10MB and

        (
            $crate or

            (
                $chacha and
                2 of ($ipc_*) and
                (
                    ($api_pam and ($api_pb or $api_csr)) or
                    $kh_id or
                    #macho_embed > 1 or

                    (1 of ($cdp_*) and 1 of ($cocoa_*))
                )
            )
        )
}

rule OSX_Avenger_Stealer_Keychain_Helper {
    meta:
        description = "carved or standalone keychain dumper helper dropped by Avenger / PAM Stealer"
        author = "Chandra Kant Bauri"
        date = "2026-11-09"
        malware_family = "AvengerStealer"
        platform = "macOS"

    strings:
        // Keychain Dumper Helper (kh): Unique ad-hoc code-signing identifier & API
        $kh_id  = "kh-57aebaab0e5de898" ascii
        $sec1   = "SecItemCopyMatching" ascii
        $sec2   = "kSecClassGenericPassword" ascii

    condition:
        uint32(0) == 0xfeedfacf and
        (uint32(4) == 0x0100000c or uint32(4) == 0x01000007) and
        filesize < 200KB and
        $kh_id and
        all of ($sec*)
}

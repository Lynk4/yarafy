rule infostealer_macos_amos {
    meta:
        author = "Yarafy Detection Team"
        description = "Detects Atomic macOS Stealer (AMOS) payloads and AppleScript / Mach-O extraction routines"
        os = "macos"
        category = "infostealer"
        malware_family = "AtomicStealer"
        reference = "https://www.sentinelone.com/blog/atomic-stealer-amos-malware-targets-macos-users-via-malvertising/"
        date = "2024-01-15"
        severity = "HIGH"

    strings:
        // AMOS Stealer file targets and commands
        $str_keychain = "Library/Keychains/login.keychain" ascii
        $str_keychain_db = "login.keychain-db" ascii
        $str_wallet1 = "Exodus/exodus.wallet" ascii
        $str_wallet2 = "Electrum/wallets" ascii
        $str_wallet3 = "Coinomi/wallets" ascii
        $str_browser1 = "Library/Application Support/Google/Chrome" ascii
        $str_browser2 = "Library/Application Support/BraveSoftware" ascii
        $str_browser3 = "Library/Application Support/com.operasoftware.Opera" ascii
        
        // AMOS Exfiltration and system profiling indicators
        $cmd_profile1 = "system_profiler SPHardwareDataType" ascii
        $cmd_profile2 = "ioreg -l | grep IOPlatformSerialNumber" ascii
        $cmd_prompt = "osascript -e 'display dialog" ascii wide
        $amos_c2_param = "/api/v1/log" ascii

        // Mach-O Magic Numbers (32-bit / 64-bit / Universal Fat)
        $macho_64 = { CF FA ED FE }
        $macho_fat = { CA FE BA BE }

    condition:
        ($macho_64 at 0 or $macho_fat at 0 or uint32(0) == 0xfeedfacf or uint32(0) == 0xcafebabe) and
        (
            3 of ($str_wallet*) or
            (1 of ($str_keychain*) and 1 of ($str_browser*) and 1 of ($cmd_profile*)) or
            ($cmd_prompt and 2 of ($str_browser*)) or
            ($amos_c2_param and 2 of ($str_wallet*, $str_browser*, $str_keychain*))
        )
}

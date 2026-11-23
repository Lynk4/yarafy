rule osx_stealer_icmacos {
    meta:
        description = "ICMacOs Apple Silicon stealer across multiple campaign domains"
        author = "Chandra Kant Bauri"
        date = "2026-11-14"
        platform = "macOS"
        family = "ICMacOs"
        sample = "d9df05a3fb68d302ecf134a1214b609c6ec0a3fb9122907214afac3908b587f4"

    strings:
        // Author and module anchors
        $author_mod       = "github.com/ultra-supara/ICMacOs" ascii
        $author_tg        = "https://t.me/ICMACOS" ascii
        $author_forum     = "https://forum.exploit.in/topic/291615/" ascii

        // Staging and persistence markers
        $op_plist         = "com.apple.systemupdater.plist" ascii
        $op_pdir          = ".systemd-helper" ascii
        $op_stage         = "/tmp/.systemd-private-helper" ascii
        $op_zip           = "organized.zip" ascii
        $op_log           = "/tmp/.cache-update.log" ascii

        // Evasion and operational indicators
        $op_tcc           = "Safari: TCC BLOCKED" ascii
        $op_cis           = "CIS country detected" ascii
        $op_pwd           = "Restuck: invalid password" ascii
        $op_shell         = "Command timeout (30s)" ascii
        $op_keychain      = "moond4rk/keychainbreaker" ascii

        // Cloud and developer secret harvesting
        $op_dev_start     = "collectDevSecrets START" ascii
        $op_dev_env       = "DevSecrets: %d env files collected" ascii
        $op_gcloud        = "gcloud_credentials.json" ascii

        // Messaging and communication theft
        $op_msg_wa        = "group.net.whatsapp.WhatsApp.shared" ascii
        $op_msg_im        = "Messages: dir not found, skip" ascii
        $op_msg_tg        = "Telegram: tdata copied" ascii
        $op_msg_dc        = "Discord leveldb: %s copied" ascii

        // Cryptocurrency wallets and file harvesting
        $op_wallets       = "Wallets: %d collected" ascii
        $op_exodus        = "Exodus: collection done" ascii
        $op_grabber       = "Filegrabber" ascii

    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe) and
        
        // file size envelope (Go compiled stealer cluster is ~14.8 MB)
        (filesize > 5MB and filesize < 35MB) and
        
        // Either author identity matches, OR at least 4 operational markers co-occur
        (
            1 of ($author*) or
            4 of ($op_*)
        )
}

rule infostealer_macos_banshee {
    meta:
        author = "Yarafy Detection Team"
        description = "Detects Banshee macOS infostealer targeting Apple Keychain, crypto wallets, and browser credentials"
        os = "macos"
        category = "infostealer"
        malware_family = "BansheeStealer"
        reference = "https://www.huntress.com/blog/banshee-stealer-macos"
        date = "2024-08-14"
        severity = "HIGH"

    strings:
        // Banshee specific AppleScript password dialog prompting
        $dialog1 = "osascript -e 'display dialog \"Enter system password to continue\"" ascii nocase
        $dialog2 = "osascript -e 'display dialog" ascii
        $with_icon = "with icon caution" ascii
        $hidden_ans = "with hidden answer" ascii

        // Targeted crypto wallets & applications
        $wallet_phantom = "Phantom" ascii
        $wallet_metamask = "MetaMask" ascii
        $wallet_exodus = "Exodus" ascii
        $app_notes = "Library/Group Containers/group.com.apple.notes" ascii

        // System information queries
        $sys_ram = "sysctl hw.memsize" ascii
        $sys_vm = "sysctl kern.hv_vmm_present" ascii

        // Mach-O Magic
        $macho_64 = { CF FA ED FE }
        $macho_fat = { CA FE BA BE }

    condition:
        ($macho_64 at 0 or $macho_fat at 0 or uint32(0) == 0xfeedfacf or uint32(0) == 0xcafebabe) and
        (
            ($dialog2 and ($hidden_ans or $with_icon) and 1 of ($wallet_*)) or
            ($sys_vm and 2 of ($wallet_*, $app_notes)) or
            ($sys_ram and $dialog1)
        )
}

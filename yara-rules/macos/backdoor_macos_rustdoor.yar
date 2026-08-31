rule backdoor_macos_rustdoor {
    meta:
        author = "Yarafy Detection Team"
        description = "Detects RustDoor / RustBucket macOS malware family written in Rust"
        os = "macos"
        category = "backdoor"
        malware_family = "RustDoor"
        reference = "https://www.s3c.io/blog/rustdoor-macos-malware"
        date = "2024-02-10"
        severity = "CRITICAL"

    strings:
        // Rust runtime artifacts and specific paths
        $rust_id1 = "rust_begin_unwind" ascii
        $rust_id2 = "src/main.rs" ascii
        
        // Characteristic commands and exfiltration strings
        $cmd1 = "osascript -e" ascii
        $cmd2 = "systeminfo" ascii
        $cmd3 = "screencapture" ascii
        $cmd4 = "tar -czf" ascii
        $cmd5 = "/Library/LaunchAgents" ascii
        
        // Specific internal function names / modules
        $func1 = "client::handle_command" ascii
        $func2 = "bot::run" ascii
        $func3 = "persist::install" ascii

        // Mach-O Magic
        $macho_64 = { CF FA ED FE }
        $macho_fat = { CA FE BA BE }

    condition:
        ($macho_64 at 0 or $macho_fat at 0 or uint32(0) == 0xfeedfacf or uint32(0) == 0xcafebabe) and
        (1 of ($rust_id*)) and
        (
            2 of ($func*) or
            (3 of ($cmd*) and 1 of ($func*)) or
            (4 of ($cmd*))
        )
}

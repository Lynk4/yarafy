rule APT_macOS_RustBucket_Behavioral_Indicators {
    meta:
        description = "Broad hunting rule for macOS RustBucket/Lazarus loaders and drop-and-execute variants"
        date = "2026-09-18"
        severity = "High"
        malware_family = "RustBucket"

    strings:
        // C2 User-Agent anomaly (Legacy IE on macOS)
        $ua_anom_01 = "msie 8.0; windows nt 5.1" ascii nocase
        $ua_anom_02 = "trident/4.0" ascii nocase

        // Subprocess spawning via Cocoa NSTask APIs
        $task_sel_01 = "setLaunchPath:" ascii
        $task_sel_02 = "launchAndReturnError:" ascii
        $task_sel_03 = "setArguments:" ascii

        // File-handling & staging indicators
        $file_01 = "temporaryDirectory" ascii
        $file_02 = "defaultManager" ascii
        $file_03 = "appendingPathComponent" ascii

        // Anti-forensic wiping primitives
        $wipe_01 = "swift_stdlib_random" ascii
        $wipe_02 = "_unlink" ascii

        // Swift-specific execution scaffolding
        $swift_cmd = "CommandLine" ascii
        $swift_sem = "OS_dispatch_semaphore" ascii

    condition:
        // Mach-O Magic Numbers: 64-bit LE/BE or FAT Universal
        (
            uint32(0) == 0xfeedfacf or 
            uint32(0) == 0xcffaedfe or 
            uint32(0) == 0xbebafeca
        )
        and
        (
            // Direct hit: Any variation of the legacy MSIE 8.0 User-Agent inside a macOS Mach-O
            1 of ($ua_anom_*) or

            // Behavioral composition: Temp path resolution + Process spawning + Anti-forensics
            (
                2 of ($task_sel_*) and
                2 of ($file_*) and
                1 of ($wipe_*) and
                all of ($swift_*)
            )
        )
}
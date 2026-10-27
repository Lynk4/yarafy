rule macOS_Backdoor_C5_Implant {
    meta:
        description = "Detects custom macOS x86_64 C2 implant featuring in-memory BOF execution and direct BSD syscalls"
        author = "Chandra Kant Bauri"
        date = "2026-10-28"
        hash = "e2b8c46e9673699357002778d81335d78a42b008af5c2f9296cc95ae9934fa9e"


    strings:
        // Dedicated custom configuration section name and magic markers
        $section_c5cfg = "__c5cfg" fullword ascii
        $cfg_magic_header = { f2 f8 f2 f8 f2 f8 f2 f8 }
        $cfg_magic_footer = { f8 f2 f8 f2 }

        // Session and protocol indicators
        $proto_session = "c5-session-v1" fullword ascii
        $proto_magic   = "c5-magic" fullword ascii

        // In-memory BOF) loader artifacts
        $bof_error = "EncryptedBofTooShort" fullword ascii
        $bof_api1  = "InstanceDataParse" fullword ascii
        $bof_api2  = "InstanceOutput" fullword ascii
        $bof_api3  = "InstancePrintf" fullword ascii
        $bof_api4  = "InstanceFormatAlloc" fullword ascii

        // TCC / Full Disk Access permission 
        $tcc_path = "/Library/Application Support/com.apple.TCC" ascii
        $tcc_fda1 = "fda.system" fullword ascii
        $tcc_fda2 = "fda.user" fullword ascii

    condition:
        
        uint32(0) == 0xfeedfacf and
        
        filesize < 5MB and


        (
            // Signature A: Contains the custom config section and magic markers
            ($section_c5cfg and ($cfg_magic_header or $cfg_magic_footer)) or

            // Signature B: Custom C5 protocol identifiers
            ($proto_session and $proto_magic) or

            // Signature C: In-memory BOF TCC probing
            ($bof_error and 2 of ($bof_api*) and 1 of ($tcc_*))
        )
}

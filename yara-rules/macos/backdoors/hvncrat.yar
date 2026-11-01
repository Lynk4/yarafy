rule Macho_hVNCRat_generic {
    meta:
        author = "Chandra Kant Bauri"
        description = "Detects generic macOS HVNC (Hidden VNC) browser hijacking implant"
        date = "2026-10-14"
        malware_family = "macOS.hvnc"
        family = "HVNC"
        platform = "macOS"

    strings:
        // Unique custom JavaScript injected into victim browsers for covert interaction
        $js_find = "window.__hvncFind" ascii
        $js_copy = "window.__hvncCopySel" ascii
        $js_zoom = "window.__hvncZoomSet" ascii
        $css_find = "::highlight(hvnc-find)" ascii

        // Unique SQLite shadow backup & APFS clone strings
        $sqlite_bak = ".backup '$T.hvncbak'" ascii
        $pkill_clone = "/usr/bin/pkill -f 'hvnc_clone_'" ascii
        $apfs_clone = "chromium clone: APFS clonefile snapshot" ascii

        // Unique DevTools Protocol manipulation & crash prompt suppression
        $cdp_bounds = "{\"windowId\":%d,\"bounds\":{\"left\":-32000,\"top\":-32000}}" ascii
        $cdp_crash1 = "s/\"exit_type\":\"Crashed\"/\"exit_type\":\"Normal\"/g" ascii
        $cdp_crash2 = "browser.sessionstore.resume_from_crash" ascii

    condition:
        // Enforce valid Mach-O binary (64-bit, 32-bit, or Fat/Universal)
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32(0) == 0xcafebabe or uint32(0) == 0xcffaedfe or uint32(0) == 0xbebafeca)
        and (
            2 of ($js_find, $js_copy, $js_zoom, $css_find) or
            2 of ($sqlite_bak, $pkill_clone, $apfs_clone) or
            ($cdp_bounds and 1 of ($cdp_crash1, $cdp_crash2)) or
            (3 of them)
        )
}

rule Macho_hVNCRat_campaign {
    meta:
        author = "Chandra Kant Bauri"
        description = "Detects specific campaign build of macOS HVNC implant"
        date = "2026-10-14"
        malware_family = "macOS.HVNC"
        family = "HVNC"
        platform = "macOS"
        sample_hash = "5681c400f0ed8431b3950e92864e52cffb0bf93a359edffb49e423ad5e8ef0b8"

    strings:
        $c2 = "agent.torrentsbyjimboslimfit.xyz" ascii
        $tag = "HVNC_MAC_TAG:8panel" ascii
        $psk = "hvnc-remote-default-psk" ascii
        $id = "hvnc_agent_macos_universal" ascii

    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32(0) == 0xcafebabe or uint32(0) == 0xcffaedfe or uint32(0) == 0xbebafeca)
        and 2 of ($c2, $tag, $psk, $id)
}

rule Macho_hVNCRat_shelldropper {
    meta:
        author = "Chandra Kant Bauri"
        description = "Detects shell dropper script for macOS HVNC agent"
        date = "2026-10-14"
        malware_family = "macOS.HVNC"
        family = "HVNC"
        platform = "macOS"
        sample_hash = "dce578f5af994c77785b96087e4fd4d8124482eab896dceb175a26342a84e31b"

    strings:
        $sh = "#!/bin/" ascii
        $c2 = "txrouteuifbfewfubewfbhgrabbing.xyz" ascii
        $uri = "/wohnung/agent" ascii
        $dest = "Downloads/wohnung" ascii
        $plist = "com.system.updater.plist" ascii
        $check_magic = "cafebabe|cffaedfe" ascii

    condition:
        $sh at 0
        and (
            $c2 or
            (3 of ($uri, $dest, $plist, $check_magic))
        )
}

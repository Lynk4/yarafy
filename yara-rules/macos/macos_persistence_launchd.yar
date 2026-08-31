rule macos_persistence_launchd_suspicious {
    meta:
        author = "Yarafy Detection Team"
        description = "Detects suspicious LaunchAgent or LaunchDaemon property list configurations used for macOS persistence"
        os = "macos"
        category = "persistence"
        date = "2024-03-01"
        severity = "MEDIUM"

    strings:
        // Plist headers
        $plist_tag = "<plist version=" ascii
        $label_key = "<key>Label</key>" ascii
        $prog_args = "<key>ProgramArguments</key>" ascii
        $run_at_load = "<key>RunAtLoad</key>" ascii
        $keep_alive = "<key>KeepAlive</key>" ascii

        // Suspicious target execution paths in LaunchAgents
        $susp_path1 = "/tmp/" ascii
        $susp_path2 = "/Users/Shared/" ascii
        $susp_path3 = "/var/tmp/" ascii
        $susp_path4 = "/dev/shm" ascii
        $susp_path5 = ".hidden" ascii
        
        // Suspicious inline interpreters / script executions
        $susp_cmd1 = "/bin/sh" ascii
        $susp_cmd2 = "/bin/bash" ascii
        $susp_cmd3 = "curl " ascii
        $susp_cmd4 = "python" ascii
        $susp_cmd5 = "osascript" ascii
        $susp_cmd6 = "base64" ascii

    condition:
        $plist_tag at 0 and
        $label_key and
        $prog_args and
        ($run_at_load or $keep_alive) and
        (
            1 of ($susp_path*) or
            2 of ($susp_cmd*) or
            ($susp_cmd3 and $susp_cmd1)
        )
}

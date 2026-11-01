rule Macho_Jockey_Implant {
    meta:
        description = "JOCKY Forensic Agent macOS arm64 implant family"
        author = "Chandra Kant Bauri"
        date = "2026-11-01"
        os = "macOS"
        architecture = "arm64"
        category = "Malware / Surveillance Implant"
        hash = "a1be741da7083f06e2e67b2ea5e854af4b780bc1af077b9d1220b288abee2584"

    strings:
        // Set 1: Unique malware symbol markers (for unstripped or partially stripped variants)
        $sym_cicd_start      = "_j_cicd_start" ascii
        $sym_cicd_gen        = "_j_cicd_generation" ascii
        $sym_morph           = "_j_morph_mutate" ascii
        $sym_sandbox         = "_j_sandbox_run" ascii
        $sym_c2              = "_j_net_c2_submit" ascii
        $sym_persist_cron    = "_j_persist_cron" ascii
        $sym_persist_inst    = "_j_persist_install" ascii
        $sym_fs_hijack       = "_j_fs_path_hijack" ascii
        $sym_crypto_aes_enc  = "_j_crypto_aes_gcm_encrypt" ascii
        $sym_crypto_aes_dec  = "_j_crypto_aes_gcm_decrypt" ascii
        $sym_evtx            = "_j_evtx_parse" ascii
        $sym_lnk             = "_j_lnk_parse" ascii

        // Set 2: Internal deployment and campaign identifier tags
        $id_dep              = "gen_dep-" ascii
        $id_tag              = "dep-mum" ascii

        // Set 3: Distinctive ARM64 machine instruction sequences (detects fully stripped variants)
        // Stream-cipher inner loop: ldrb, lsr #16, mul, eor, strb
        // 4d 69 69 38 : ldrb w13, [x10, x9]
        // 8e 7d 10 53 : lsr  w14, w12, #16
        // ?? 7d ?? 1b : mul  w14, w14, w11
        // ?? 01 ?? 4a : eor  w11, w13, w11
        // 4b 69 ?? 38 : strb w11, [x10, x9]
        $code_stream_cipher = { 4d 69 69 38 8e 7d 10 53 ?? 7d ?? 1b ?? 01 ?? 4a 4b 69 ?? 38 }

        // Metamorphic thread loop: nanosleep followed by mutation call and loopback branch
        // bl _nanosleep ... bl _j_morph_mutate ... tbnz
        $code_morph_loop = { 55 b9 00 94 [0-16] a4 43 00 94 [0-16] 28 fe 07 37 }

    condition:
        // Performance guardrails: Evaluates header magic and file size first
        (uint32(0) == 0xfeedfacf and uint32(4) == 0x0100000c)
        and filesize < 5MB
        and (
            // Match condition 1: Unstripped binary containing 4 or more family symbols
            4 of ($sym_*)
            // Match condition 2: Deployment tag combined with at least 2 family symbols
            or (any of ($id_*) and 2 of ($sym_*))
            // Match condition 3: Stripped binary matching the custom stream cipher and metamorphic worker loop
            or ($code_stream_cipher and ($code_morph_loop or any of ($sym_*)))
        )
}

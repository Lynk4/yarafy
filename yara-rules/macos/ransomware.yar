rule OSX_Malware_EvilQuest_ThiefQuest {
    meta:
        description     = "Detects OSX.EvilQuest / ThiefQuest / MacRansom.K multi-stage macOS malware"
        author          = "Chandra kant"
        date            = "2026-10-30"
        threat_type     = "Ransomware / InfoStealer / Backdoor / Keylogger"
        platform        = "macOS"
        family          = "OSX.EvilQuest"
        reference       = "https://objective-see.org/blog/blog_0x59.html"
        sample_sha256   = "7273b091529f3fa0fc9fd642553ff3b26daa9b1afc4f6ad49fd853e9d420fc7a"


    strings:
        // 1. High-Entropy Cryptographic Artifacts (High-Quality 4-byte AC Atoms)
        $crypto_key_seed    = "XY345N5s#p$(<d6HjaKvt!DL+Maiy]-0;amP5Be?a}GHI|RQ_2[7%aV{8a.^)~E>:" ascii fullword
        $crypto_alpha_61    = "ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvxyz01234567890" ascii fullword
        $crypto_prime_table = { 02 03 05 07 0B 0D 11 13 17 1D 1F 25 29 2B 2F 35 3B 3D 43 47 49 4F 53 59 61 65 67 6B 6D 71 7F 83 }

        // 2. Author's Reversed Source Tree Tokens ("effectiveidiot")
        $path_rev_1    = "/e/toidievitceffe/libpersist/rennur.c" ascii
        $path_rev_2    = "/e/toidievitceffe/libtpyrc/tpyrc.c" ascii
        $path_rev_3    = "/e/toidievitceffe/libpersist/persist.c" ascii
        $path_rev_base = "/e/toidievitceffe/" ascii

        // 3. Reflective In-Memory Bundle Loader Symbols & Assertions
        $loader_entry    = "kBundleEntryPointName" ascii fullword
        $loader_assert_1 = "_16taSim->magic == FAT_MAGIC" ascii
        $loader_assert_2 = "_16taSim->nfat_arch > 0" ascii
        $loader_assert_3 = "(1 << _16vXzmm->align) <= getpagesize()" ascii
        $loader_assert_4 = "(dyldErr == NSObjectFileImageSuccess) == (*ofiPtr != NULL)" ascii
        $loader_assert_5 = "*codeSizePtr >= (sizeof(*_16taSim) + (sizeof(*_16uCPmm) * _16taSim->nfat_arch))" ascii

        // 4. Exact Obfuscation Symbol Tags (Optimized linear string search; avoids regex overhead)
        $tag_1 = "_16HEASh" ascii fullword
        $tag_2 = "_16taSim" ascii fullword
        $tag_3 = "_16ythNm" ascii fullword
        $tag_4 = "_16iPrGk" ascii fullword
        $tag_5 = "_16ZRHQh" ascii fullword
        $tag_6 = "_16fUggs" ascii fullword

        // 5. Execution & Runtime Strings
        $str_priv_1 = "This application has to be run by root" ascii
        $str_priv_2 = "This program is designed to run with admin privileges" ascii
        $str_ver    = "EI %s\n\n" ascii
        $str_spot   = "Error writing spot data" ascii

    condition:
        // Performance Guard: Immediately skip files > 15MB without deep scanning
        filesize < 15MB
        // Format Guard: Validate Mach-O Magic Header at offset 0
        // (64-bit LE/BE, 32-bit LE/BE, Universal FAT LE/BE)
        and (
            uint32(0) == 0xfeedfacf or
            uint32(0) == 0xcffaedfe or
            uint32(0) == 0xfeedface or
            uint32(0) == 0xcefaedfe or
            uint32(0) == 0xcafebabe or
            uint32(0) == 0xbebafeca
        )
        and (
            // Zero-FP Tier 1: Unique 67-char high-entropy seed or reversed project paths
            $crypto_key_seed or
            $path_rev_base or
            // Zero-FP Tier 2: Crypto tables corroborated with secondary artifacts
            ($crypto_alpha_61 and ($crypto_prime_table or 1 of ($path_rev_*) or 1 of ($loader_*) or 1 of ($str_*))) or
            ($crypto_prime_table and (1 of ($path_rev_*) or 1 of ($loader_*) or 1 of ($str_*))) or
            // Zero-FP Tier 3: Corroborated reflective loader & obfuscated symbol tags
            (2 of ($loader_*) and (1 of ($tag_*) or 1 of ($str_*))) or
            (3 of ($tag_*) and 1 of ($str_*))
        )
}

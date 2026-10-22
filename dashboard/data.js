window.YARAFY_DATA = {
  "stats": {
    "total_scanned": 17388,
    "total_hits": 189,
    "last_run": "2026-10-22T19:15:34.846800+00:00",
    "hits_by_platform": {
      "macos": 189,
      "windows": 0,
      "linux": 0,
      "non-pe": 0
    },
    "hits_by_rule": {
      "macOS_ClickFix_AppleScript_Dropper": 113,
      "OSX_Stealer_AMOS_Generic": 38,
      "MALW_macOS_MacSync_Stealer_Universal": 7,
      "OSX_Foxveil_AMOS_Stage4_Generic": 18,
      "APT_macOS_RustBucket_Behavioral_Indicators": 3,
      "Macho_Trojan_CloudSync_Generic": 3,
      "Macho_Trojan_CloudSync_1006YR": 2,
      "Macho_Trojan_CloudSync_1007YR": 1,
      "Macho_Trojan_CloudSync_DMG": 1,
      "Macho_hVNCRat_generic": 1,
      "Macho_hVNCRat_campaign": 1,
      "Macho_hVNCRat_shelldropper": 1
    },
    "hits_by_source": {
      "MalwareBazaar": 136,
      "VirusTotal Enterprise": 43,
      "Local File": 10
    },
    "new_hits_this_run": 1,
    "refreshed_hits_this_run": 30,
    "total_rules": 12
  },
  "hits": [
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0xf020",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x36e70",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x10080",
          "identifier": "$pbkdf2_salt",
          "data_preview": "b1 cd ff 97 cc 3e b0 8f 2b 4a 53 89 4e cd 52 15 1a e5 ad 86 89 ea 99 45 06 f9 70 26 f0 34 6a be"
        },
        {
          "offset": "0x38080",
          "identifier": "$pbkdf2_salt",
          "data_preview": "b1 cd ff 97 cc 3e b0 8f 2b 4a 53 89 4e cd 52 15 1a e5 ad 86 89 ea 99 45 06 f9 70 26 f0 34 6a be"
        },
        {
          "offset": "0x10060",
          "identifier": "$hkdf_salt",
          "data_preview": "85 cd 9e 60 b3 7d e0 b7 33 f7 36 d0 66 dc 49 1a 54 94 a7 e8 63 1f 03 24 bf 3e 08 2f cc d5 06 5d"
        },
        {
          "offset": "0x38060",
          "identifier": "$hkdf_salt",
          "data_preview": "85 cd 9e 60 b3 7d e0 b7 33 f7 36 d0 66 dc 49 1a 54 94 a7 e8 63 1f 03 24 bf 3e 08 2f cc d5 06 5d"
        },
        {
          "offset": "0x100a0",
          "identifier": "$payload_hash1",
          "data_preview": "9e 0b 82 e1 6d 94 c4 8f bf c7 12 00 4d b9 95 be a8 23 e8 97 7a c7 a9 4c d7 c3 a4 f2 fe 08 05 07"
        },
        {
          "offset": "0x380a0",
          "identifier": "$payload_hash1",
          "data_preview": "9e 0b 82 e1 6d 94 c4 8f bf c7 12 00 4d b9 95 be a8 23 e8 97 7a c7 a9 4c d7 c3 a4 f2 fe 08 05 07"
        },
        {
          "offset": "0x100c0",
          "identifier": "$payload_hash2",
          "data_preview": "7d b4 3f f8 79 96 2b 55 70 44 2c 2a e5 d2 1f d4 f6 d8 7d c0 cf dd e7 28 94 39 b4 71 8b 2b ee b9"
        },
        {
          "offset": "0x380c0",
          "identifier": "$payload_hash2",
          "data_preview": "7d b4 3f f8 79 96 2b 55 70 44 2c 2a e5 d2 1f d4 f6 d8 7d c0 cf dd e7 28 94 39 b4 71 8b 2b ee b9"
        },
        {
          "offset": "0xf720",
          "identifier": "$chunk_lengths",
          "data_preview": "f6 3e 00 00 00 00 00 00 0f 41 00 00 00 00 00 00 a4 3b 00 00 00 00 00 00 f4 40 00 00 00 00 00 00"
        },
        {
          "offset": "0x37068",
          "identifier": "$chunk_lengths",
          "data_preview": "f6 3e 00 00 00 00 00 00 0f 41 00 00 00 00 00 00 a4 3b 00 00 00 00 00 00 f4 40 00 00 00 00 00 00"
        },
        {
          "offset": "0xfac0",
          "identifier": "$xor_hw_model",
          "data_preview": "uj3pryxq"
        },
        {
          "offset": "0x373ea",
          "identifier": "$xor_hw_model",
          "data_preview": "uj3pryxq"
        }
      ],
      "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
      "sample_md5": "39b0878c62984b3f3ec751118174c63e",
      "sample_name": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72.macho",
      "sample_size_bytes": 347088,
      "mb_metadata": {
        "first_seen": "2026-08-23 11:00:08",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "ClickFix",
          "machO",
          "stealer"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 25,
        "total_engines": 61,
        "detection_ratio": "25/61",
        "suggested_threat_label": "trojan.amos/camelot",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 16
          }
        ],
        "names": [
          "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72.macho"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "64bits",
          "self-signed",
          "checks-cpu-name",
          "macho",
          "multi-arch"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bx",
          "ESET-NOD32": "OSX/PSW.Agent.JL trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72"
      },
      "detected_at": "2026-08-31T14:41:41.676801+00:00",
      "source_feed": "MalwareBazaar",
      "last_seen_at": "2026-10-19T02:32:11.677388+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [
        {
          "offset": "0x54ffa",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x55017",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5508f",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadec9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadee6",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadef9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5500c",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0xadedb",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0x55632",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0xae44a",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0x99418",
          "identifier": "$op_arm64_dec",
          "data_preview": "4b 09 40 b3 6b 01 40 39 cc 02 0a 8b 8d 41 40 39 ab 01 0b 4a 8b 41 00 39 29 05 c9 93"
        },
        {
          "offset": "0x5b7ac",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x9948c",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99e80",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99f14",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        }
      ],
      "sample_sha256": "0f808ec0e7d9fb413f44331ba5fc6a23ca282363f244062f0acaa418e55b2ec8",
      "sample_md5": "c00317bc309b92bb2865b005e363e381",
      "sample_name": "0f808ec0e7d9fb413f44331ba5fc6a23ca282363f244062f0acaa418e55b2ec8.macho",
      "sample_size_bytes": 723072,
      "mb_metadata": {
        "first_seen": "2026-08-12 18:14:01",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "machO",
          "whack.sh"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 33,
        "total_engines": 62,
        "detection_ratio": "33/62",
        "suggested_threat_label": "trojan.stealer/amos",
        "popular_threat_category": [
          {
            "count": 19,
            "value": "trojan"
          }
        ],
        "names": [
          "1vo6lm4y50k3ww0f",
          "0f808ec0e7d9fb413f44331ba5fc6a23ca282363f244062f0acaa418e55b2ec8.macho"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "macho",
          "64bits",
          "multi-arch",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/AmosStealer.DB!MTB",
          "SentinelOne": "Static AI - Suspicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bg",
          "Sophos": "OSX/InfoStl-GW",
          "ESET-NOD32": "OSX/PSW.Agent.GF trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/0f808ec0e7d9fb413f44331ba5fc6a23ca282363f244062f0acaa418e55b2ec8"
      },
      "detected_at": "2026-08-31T14:41:41.676801+00:00",
      "source_feed": "MalwareBazaar",
      "last_seen_at": "2026-09-16T10:24:15.725648+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [
        {
          "offset": "0x54ffa",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x55017",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5508f",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadec9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadee6",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadef9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5500c",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0xadedb",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0x55632",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0xae44a",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0x99418",
          "identifier": "$op_arm64_dec",
          "data_preview": "4b 09 40 b3 6b 01 40 39 cc 02 0a 8b 8d 41 40 39 ab 01 0b 4a 8b 41 00 39 29 05 c9 93"
        },
        {
          "offset": "0x5b7ac",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x9948c",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99e80",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99f14",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        }
      ],
      "sample_sha256": "9e221f45649bdd5d7fdd77949083b1d37ac34f8cf3cbf91b686edb1c6b2262f6",
      "sample_md5": "39dffdbdd1cdfd93ee47ed072ce99e23",
      "sample_name": "9e221f45649bdd5d7fdd77949083b1d37ac34f8cf3cbf91b686edb1c6b2262f6.macho",
      "sample_size_bytes": 723072,
      "mb_metadata": {
        "first_seen": "2026-08-12 18:13:58",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "machO",
          "whack.sh"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 33,
        "total_engines": 62,
        "detection_ratio": "33/62",
        "suggested_threat_label": "trojan.stealer/amos",
        "popular_threat_category": [
          {
            "count": 19,
            "value": "trojan"
          }
        ],
        "names": [
          "zeb8cgwmkkpvu7pc",
          "9e221f45649bdd5d7fdd77949083b1d37ac34f8cf3cbf91b686edb1c6b2262f6.macho"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "multi-arch",
          "self-signed",
          "arm",
          "macho"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/AmosStealer.DB!MTB",
          "SentinelOne": "Static AI - Suspicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bg",
          "Sophos": "OSX/InfoStl-GW",
          "ESET-NOD32": "OSX/PSW.Agent.GF trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/9e221f45649bdd5d7fdd77949083b1d37ac34f8cf3cbf91b686edb1c6b2262f6"
      },
      "detected_at": "2026-08-31T14:41:41.676801+00:00",
      "source_feed": "MalwareBazaar",
      "last_seen_at": "2026-09-16T07:02:51.230791+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [
        {
          "offset": "0x54ffa",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x55017",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5508f",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadec9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadee6",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadef9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5500c",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0xadedb",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0x55632",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0xae44a",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0x99418",
          "identifier": "$op_arm64_dec",
          "data_preview": "4b 09 40 b3 6b 01 40 39 cc 02 0a 8b 8d 41 40 39 ab 01 0b 4a 8b 41 00 39 29 05 c9 93"
        },
        {
          "offset": "0x5b7ac",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x9948c",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99e80",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99f14",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        }
      ],
      "sample_sha256": "275aeaa88d853ddb93c6e3c102beb1aa2ba41ca1b68af25b47781d9f4460bc5d",
      "sample_md5": "e1d35d2d895b0399bff341875f722173",
      "sample_name": "275aeaa88d853ddb93c6e3c102beb1aa2ba41ca1b68af25b47781d9f4460bc5d.macho",
      "sample_size_bytes": 723072,
      "mb_metadata": {
        "first_seen": "2026-08-12 13:12:14",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "adhoc-signed",
          "AMOS",
          "Gatekeeper-bypass",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 34,
        "total_engines": 61,
        "detection_ratio": "34/61",
        "suggested_threat_label": "trojan.stealer/amos",
        "popular_threat_category": [
          {
            "count": 19,
            "value": "trojan"
          }
        ],
        "names": [
          "y6b3fuzj0w6pt97e",
          "275aeaa88d853ddb93c6e3c102beb1aa2ba41ca1b68af25b47781d9f4460bc5d.macho"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "64bits",
          "arm",
          "multi-arch",
          "self-signed"
        ],
        "reputation": -52,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/AmosStealer.DB!MTB",
          "SentinelOne": "Static AI - Malicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bg",
          "Sophos": "OSX/InfoStl-GW",
          "ESET-NOD32": "OSX/PSW.Agent.GF trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/275aeaa88d853ddb93c6e3c102beb1aa2ba41ca1b68af25b47781d9f4460bc5d"
      },
      "detected_at": "2026-08-31T14:41:41.676801+00:00",
      "source_feed": "MalwareBazaar",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0xa718",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x29c98",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0xb090",
          "identifier": "$payload_hash1",
          "data_preview": "9e 0b 82 e1 6d 94 c4 8f bf c7 12 00 4d b9 95 be a8 23 e8 97 7a c7 a9 4c d7 c3 a4 f2 fe 08 05 07"
        },
        {
          "offset": "0x2c0c0",
          "identifier": "$payload_hash1",
          "data_preview": "9e 0b 82 e1 6d 94 c4 8f bf c7 12 00 4d b9 95 be a8 23 e8 97 7a c7 a9 4c d7 c3 a4 f2 fe 08 05 07"
        }
      ],
      "sample_sha256": "c48bd4f678a498b9173353d8fd400093541326e6b40a1a99c9a15fd28721ed69",
      "sample_md5": "cfbd77887c6ba5525f9651da652c558e",
      "sample_name": "c48bd4f678a498b9173353d8fd400093541326e6b40a1a99c9a15fd28721ed69.macho",
      "sample_size_bytes": 297968,
      "mb_metadata": {
        "first_seen": "2026-08-09 15:22:53",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "AtomicStealer",
          "freshfix",
          "machO",
          "WaterDaruanak"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 30,
        "total_engines": 63,
        "detection_ratio": "30/63",
        "suggested_threat_label": "trojan.infostl/stealer",
        "popular_threat_category": [
          {
            "count": 17,
            "value": "trojan"
          }
        ],
        "names": [
          "atomicstealer_3",
          "c48bd4f678a498b9173353d8fd400093541326e6b40a1a99c9a15fd28721ed69.macho",
          "amos.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "self-signed",
          "64bits",
          "macho",
          "multi-arch",
          "arm"
        ],
        "reputation": -51,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/AmosStealer.DC!MTB",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Agent.ag",
          "Sophos": "OSX/InfoStl-HA",
          "ESET-NOD32": "OSX/PSW.Agent.JE trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/c48bd4f678a498b9173353d8fd400093541326e6b40a1a99c9a15fd28721ed69"
      },
      "detected_at": "2026-08-31T14:41:41.676801+00:00",
      "source_feed": "MalwareBazaar",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "29be0f56275f051181ea3ec37ddc3d3807cde34cb65de855709fae0e13786a40",
      "sample_md5": "ab477021780e553be4271cb34bb8394b",
      "sample_name": "29be0f56275f051181ea3ec37ddc3d3807cde34cb65de855709fae0e13786a40.macho",
      "sample_size_bytes": 297968,
      "mb_metadata": {
        "first_seen": "2026-08-06 23:09:06",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "machO"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 29,
        "total_engines": 62,
        "detection_ratio": "29/62",
        "suggested_threat_label": "trojan.stealer/amosstealer",
        "popular_threat_category": [
          {
            "count": 18,
            "value": "trojan"
          }
        ],
        "names": [
          "payload.bin",
          "bd5a94643df64a4f8901513fbf99d15993d94b8a",
          "29be0f56275f051181ea3ec37ddc3d3807cde34cb65de855709fae0e13786a40.macho"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "self-signed",
          "macho",
          "multi-arch",
          "arm"
        ],
        "reputation": -52,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/AmosStealer.DC!MTB",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Agent.ag",
          "ESET-NOD32": "OSX/PSW.Agent.JE trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/29be0f56275f051181ea3ec37ddc3d3807cde34cb65de855709fae0e13786a40"
      },
      "detected_at": "2026-08-31T14:41:41.676801+00:00",
      "source_feed": "MalwareBazaar"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x31d18",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x70388",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "ec0d13eb92a22465723e904b2ace56ddf20489810971f3b437197fdc78d10098",
      "sample_md5": "2682871c759800d029608e7b80e01ceb",
      "sample_name": "ec0d13eb92a22465723e904b2ace56ddf20489810971f3b437197fdc78d10098.macho",
      "sample_size_bytes": 568368,
      "mb_metadata": {
        "first_seen": "2026-08-03 12:40:21",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "AtomicStealer",
          "ClickFix",
          "InstallFix",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 34,
        "total_engines": 63,
        "detection_ratio": "34/63",
        "suggested_threat_label": "trojan.amos/infostl",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 20
          },
          {
            "value": "dropper",
            "count": 7
          }
        ],
        "names": [
          "atomicstealer_5.dmg",
          "ec0d13eb92a22465723e904b2ace56ddf20489810971f3b437197fdc78d10098.macho",
          "f5e2d7126b110ad4c5267796641ec5ffda11b4b6",
          "1.macho",
          "fgncmbvnhk.exe"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "arm",
          "checks-cpu-name",
          "macho",
          "multi-arch",
          "self-signed"
        ],
        "reputation": -52,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Stealer.B!AMTB",
          "Kaspersky": "HEUR:Backdoor.OSX.Amos.f",
          "Sophos": "OSX/InfoStl-HF",
          "ESET-NOD32": "OSX/PSW.Agent.JH trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/ec0d13eb92a22465723e904b2ace56ddf20489810971f3b437197fdc78d10098"
      },
      "detected_at": "2026-08-31T14:41:41.676801+00:00",
      "source_feed": "MalwareBazaar",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [],
      "sample_sha256": "4c487d86d904ec55002123163e8db6dfa93918a342036cf0d155ce9c2f662c7a",
      "sample_md5": "7672211e57d1f557c6c3aa013503df28",
      "sample_name": "4c487d86d904ec55002123163e8db6dfa93918a342036cf0d155ce9c2f662c7a.macho",
      "sample_size_bytes": 723072,
      "mb_metadata": {
        "first_seen": "2026-07-26 15:32:56",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "45-94-47-226"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 31,
        "total_engines": 58,
        "detection_ratio": "31/58",
        "suggested_threat_label": "trojan.stealer/amos",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 16
          }
        ],
        "names": [
          "4c487d86d904ec55002123163e8db6dfa93918a342036cf0d155ce9c2f662c7a.macho",
          "cursor"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "self-signed",
          "arm",
          "macho",
          "password-dialog",
          "multi-arch",
          "checks-cpu-name",
          "self-delete"
        ],
        "reputation": -58,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/AmosStealer.DB!MTB",
          "SentinelOne": "Static AI - Suspicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bg",
          "Sophos": "OSX/InfoStl-GW"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/4c487d86d904ec55002123163e8db6dfa93918a342036cf0d155ce9c2f662c7a"
      },
      "detected_at": "2026-08-31T14:41:41.676801+00:00",
      "source_feed": "MalwareBazaar"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [],
      "sample_sha256": "81bedb0639d5857c6d28b23b06cf87f812c1070d2c7c6ee8c985362a0ef2b873",
      "sample_md5": "b9fdf930964edaa587c352d0b2d066c4",
      "sample_name": "81bedb0639d5857c6d28b23b06cf87f812c1070d2c7c6ee8c985362a0ef2b873.macho",
      "sample_size_bytes": 750400,
      "mb_metadata": {
        "first_seen": "2026-07-26 14:30:50",
        "file_type": "macho",
        "signature": null,
        "tags": null
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 32,
        "total_engines": 60,
        "detection_ratio": "32/60",
        "suggested_threat_label": "trojan.stealer/amos",
        "popular_threat_category": [
          {
            "count": 17,
            "value": "trojan"
          }
        ],
        "names": [
          "81bedb0639d5857c6d28b23b06cf87f812c1070d2c7c6ee8c985362a0ef2b873.macho",
          "Yipibul"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "self-signed",
          "arm",
          "multi-arch",
          "password-dialog",
          "self-delete",
          "checks-cpu-name",
          "macho"
        ],
        "reputation": -1,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/AmosStealer.DB!MTB",
          "SentinelOne": "Static AI - Suspicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bg",
          "Sophos": "OSX/InfoStl-GW",
          "ESET-NOD32": "OSX/PSW.Agent.GF trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/81bedb0639d5857c6d28b23b06cf87f812c1070d2c7c6ee8c985362a0ef2b873"
      },
      "detected_at": "2026-08-31T14:41:41.676801+00:00",
      "source_feed": "MalwareBazaar"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0xd3f8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x30d00",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0xe090",
          "identifier": "$payload_hash1",
          "data_preview": "9e 0b 82 e1 6d 94 c4 8f bf c7 12 00 4d b9 95 be a8 23 e8 97 7a c7 a9 4c d7 c3 a4 f2 fe 08 05 07"
        },
        {
          "offset": "0x340c0",
          "identifier": "$payload_hash1",
          "data_preview": "9e 0b 82 e1 6d 94 c4 8f bf c7 12 00 4d b9 95 be a8 23 e8 97 7a c7 a9 4c d7 c3 a4 f2 fe 08 05 07"
        }
      ],
      "sample_sha256": "fc2009166867bee88885f2f889a608260cb971c1e946bbb79ea7d75ae0d429f6",
      "sample_md5": "2990c4b21076c457b7e11c117ba3b3ef",
      "sample_name": "fc2009166867bee88885f2f889a608260cb971c1e946bbb79ea7d75ae0d429f6.macho",
      "sample_size_bytes": 330752,
      "mb_metadata": {
        "first_seen": "2026-07-22 13:04:03",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "machO"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 32,
        "total_engines": 62,
        "detection_ratio": "32/62",
        "suggested_threat_label": "trojan.stealer/infostl",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 18
          }
        ],
        "names": [
          "fc2009166867bee88885f2f889a608260cb971c1e946bbb79ea7d75ae0d429f6.macho",
          "e09bb220036fad6a30ad66539879a17fc0ed548e",
          "malwarepayload"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "multi-arch",
          "macho",
          "self-signed",
          "64bits"
        ],
        "reputation": -52,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/AmosStealer.DC!MTB",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Agent.ag",
          "Sophos": "OSX/InfoStl-HA",
          "ESET-NOD32": "OSX/PSW.Agent.JE trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/fc2009166867bee88885f2f889a608260cb971c1e946bbb79ea7d75ae0d429f6"
      },
      "detected_at": "2026-08-31T14:41:41.676801+00:00",
      "source_feed": "MalwareBazaar",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [],
      "sample_sha256": "b30b4b58eb215b60a8526c506d689ffab91ed43124709bc20b4085edf9d5361b",
      "sample_md5": "77526447f9a15358ff5d991bed9a6359",
      "sample_name": "b30b4b58eb215b60a8526c506d689ffab91ed43124709bc20b4085edf9d5361b.macho",
      "sample_size_bytes": 750400,
      "mb_metadata": {
        "first_seen": "2026-07-20 16:16:01",
        "file_type": "macho",
        "signature": null,
        "tags": null
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 35,
        "total_engines": 63,
        "detection_ratio": "35/63",
        "suggested_threat_label": "trojan.stealer/amos",
        "popular_threat_category": [
          {
            "count": 19,
            "value": "trojan"
          }
        ],
        "names": [
          "gyou90ug9.exe",
          "03f524001f52f4e6b9bdd0a067ccdf1ba7074af0",
          "b30b4b58eb215b60a8526c506d689ffab91ed43124709bc20b4085edf9d5361b.macho",
          "Vozeyuy"
        ],
        "type_description": "Mach-O",
        "tags": [
          "password-dialog",
          "macho",
          "64bits",
          "self-delete",
          "multi-arch",
          "arm",
          "checks-cpu-name",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/AmosStealer.DB!MTB",
          "SentinelOne": "Static AI - Suspicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bg",
          "Sophos": "OSX/InfoStl-GW",
          "ESET-NOD32": "OSX/PSW.Agent.GF trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/b30b4b58eb215b60a8526c506d689ffab91ed43124709bc20b4085edf9d5361b"
      },
      "detected_at": "2026-08-31T14:41:41.676801+00:00",
      "source_feed": "MalwareBazaar"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x23328",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x5258c",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "43e4dfdd3c1295e54a2704158c50e1ce5913f8d700790441367cba8abe07195b",
      "sample_md5": "aad29a9edc86c712461a8efb16f18982",
      "sample_name": "43e4dfdd3c1295e54a2704158c50e1ce5913f8d700790441367cba8abe07195b.macho",
      "sample_size_bytes": 431696,
      "mb_metadata": {
        "first_seen": "2026-07-14 13:59:39",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "machO",
          "macOS",
          "osx.amos",
          "Poseidon"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 30,
        "total_engines": 62,
        "detection_ratio": "30/62",
        "suggested_threat_label": "trojan.amos/stealer",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 18
          }
        ],
        "names": [
          "43e4dfdd3c1295e54a2704158c50e1ce5913f8d700790441367cba8abe07195b.macho"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "checks-cpu-name",
          "macho",
          "multi-arch",
          "64bits",
          "self-signed"
        ],
        "reputation": -52,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Backdoor.OSX.Amos.f",
          "Sophos": "OSX/InfoStl-HF",
          "ESET-NOD32": "OSX/PSW.Agent.IN trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/43e4dfdd3c1295e54a2704158c50e1ce5913f8d700790441367cba8abe07195b"
      },
      "detected_at": "2026-08-31T14:41:41.676801+00:00",
      "source_feed": "MalwareBazaar",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x20a28",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x46d18",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "23f900e9fb8ff57f420901178a087cc5570dcaf1fd161d8e8c0b38fcdb4e68f1",
      "sample_md5": "057e87fb81fe57fc6bcc006a6cffa2be",
      "sample_name": "23f900e9fb8ff57f420901178a087cc5570dcaf1fd161d8e8c0b38fcdb4e68f1.macho",
      "sample_size_bytes": 356496,
      "mb_metadata": {
        "first_seen": "2026-07-14 13:59:07",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "machO",
          "macOS",
          "osx.amos",
          "Poseidon"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 31,
        "total_engines": 63,
        "detection_ratio": "31/63",
        "suggested_threat_label": "trojan.stealer/amos",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 17
          }
        ],
        "names": [
          "23f900e9fb8ff57f420901178a087cc5570dcaf1fd161d8e8c0b38fcdb4e68f1.macho"
        ],
        "type_description": "Mach-O",
        "tags": [
          "self-signed",
          "multi-arch",
          "64bits",
          "arm",
          "macho",
          "checks-cpu-name"
        ],
        "reputation": -52,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Stealer.B!AMTB",
          "SentinelOne": "Static AI - Suspicious Mach-O",
          "Kaspersky": "HEUR:Backdoor.OSX.Amos.f",
          "Sophos": "OSX/InfoStl-HM",
          "ESET-NOD32": "OSX/PSW.Agent.HG trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/23f900e9fb8ff57f420901178a087cc5570dcaf1fd161d8e8c0b38fcdb4e68f1"
      },
      "detected_at": "2026-08-31T14:41:41.676801+00:00",
      "source_feed": "MalwareBazaar",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [
        {
          "offset": "0x54ffa",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x55017",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5508f",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xb1ec9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xb1ee6",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xb1ef9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5500c",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0xb1edb",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0x55632",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0xb244a",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0x9d410",
          "identifier": "$op_arm64_dec",
          "data_preview": "4b 09 40 b3 6b 01 40 39 cc 02 0a 8b 8d 41 40 39 ab 01 0b 4a 8b 41 00 39 29 05 c9 93"
        }
      ],
      "sample_sha256": "f284297b7bf551617553a9c19f101b3aa55f94e3fb60cab2e596e4c287908281",
      "sample_md5": "2e038a38cdf34371d2b64ddd92b971c0",
      "sample_name": "f284297b7bf551617553a9c19f101b3aa55f94e3fb60cab2e596e4c287908281.macho",
      "sample_size_bytes": 750400,
      "mb_metadata": {
        "first_seen": "2026-06-17 00:51:24",
        "file_type": "macho",
        "signature": "AmosStealer",
        "tags": [
          "AMOS",
          "AmosStealer",
          "ClickFix",
          "Mach-O",
          "machO",
          "macOS",
          "MioLab"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 35,
        "total_engines": 63,
        "detection_ratio": "35/63",
        "suggested_threat_label": "trojan.stealer/infostl",
        "popular_threat_category": [
          {
            "count": 18,
            "value": "trojan"
          }
        ],
        "names": [
          "f284297b7bf551617553a9c19f101b3aa55f94e3fb60cab2e596e4c287908281.macho",
          "Fanave"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "multi-arch",
          "self-signed",
          "64bits",
          "macho"
        ],
        "reputation": -1,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/AmosStealer.DB!MTB",
          "SentinelOne": "Static AI - Malicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bg",
          "Sophos": "OSX/InfoStl-GW",
          "ESET-NOD32": "OSX/PSW.Agent.GF trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/f284297b7bf551617553a9c19f101b3aa55f94e3fb60cab2e596e4c287908281"
      },
      "detected_at": "2026-08-31T14:41:41.676801+00:00",
      "source_feed": "MalwareBazaar",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [
        {
          "offset": "0x54ffa",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x55017",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5508f",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadec9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadee6",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadef9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5500c",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0xadedb",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0x55632",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0xae44a",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0x99410",
          "identifier": "$op_arm64_dec",
          "data_preview": "4b 09 40 b3 6b 01 40 39 cc 02 0a 8b 8d 41 40 39 ab 01 0b 4a 8b 41 00 39 29 05 c9 93"
        }
      ],
      "sample_sha256": "a91d954fa5a9a1f167625e7ac8314a481e32a9dbee4635533b52be21be4e508b",
      "sample_md5": "6dd0a512e4e25d256c19f3b41b6fa3b9",
      "sample_name": "a91d954fa5a9a1f167625e7ac8314a481e32a9dbee4635533b52be21be4e508b.macho",
      "sample_size_bytes": 723072,
      "mb_metadata": {
        "first_seen": "2026-06-17 00:51:20",
        "file_type": "macho",
        "signature": "AmosStealer",
        "tags": [
          "AMOS",
          "AmosStealer",
          "ClickFix",
          "Mach-O",
          "machO",
          "macOS",
          "MioLab"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 35,
        "total_engines": 63,
        "detection_ratio": "35/63",
        "suggested_threat_label": "trojan.stealer/infostl",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 18
          }
        ],
        "names": [
          "a91d954fa5a9a1f167625e7ac8314a481e32a9dbee4635533b52be21be4e508b.macho",
          "Dezuboh"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "64bits",
          "self-signed",
          "multi-arch",
          "arm"
        ],
        "reputation": -1,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/AmosStealer.DB!MTB",
          "SentinelOne": "Static AI - Malicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bg",
          "Sophos": "OSX/InfoStl-GW",
          "ESET-NOD32": "OSX/PSW.Agent.GF trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/a91d954fa5a9a1f167625e7ac8314a481e32a9dbee4635533b52be21be4e508b"
      },
      "detected_at": "2026-08-31T14:41:41.676801+00:00",
      "source_feed": "MalwareBazaar",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "a7bb346838db73301fe16e8f6bf2e0caee397570bc0df184484245a2715fb9f5",
      "sample_md5": "455db1c91cdd974a3249172bd0b338fe",
      "sample_name": "a7bb346838db73301fe16e8f6bf2e0caee397570bc0df184484245a2715fb9f5.macho",
      "sample_size_bytes": 810660,
      "mb_metadata": {
        "first_seen": "2023-11-20 13:43:25",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "mac",
          "Mach-O",
          "machO",
          "macOS",
          "Meterpreter",
          "OSX"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 38,
        "total_engines": 62,
        "detection_ratio": "38/62",
        "suggested_threat_label": "trojan.mettle/meterpreter",
        "popular_threat_category": [
          {
            "count": 12,
            "value": "trojan"
          },
          {
            "count": 3,
            "value": "pua"
          }
        ],
        "names": [
          "135fc266af08a28fc7b2d3e0c2ca92e9611e626cec13fb70b9eaad1278b72793.macho",
          "9.macho",
          "a7bb346838db73301fe16e8f6bf2e0caee397570bc0df184484245a2715fb9f5.macho"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "64bits"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Backdoor:MacOS/Meddlingmetal.A",
          "SentinelOne": "Static AI - Malicious Mach-O",
          "Kaspersky": "HEUR:Backdoor.OSX.Agent.l",
          "Sophos": "OSX/Swrort-AX",
          "ESET-NOD32": "OSX/Riskware.Meterpreter.E application"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/a7bb346838db73301fe16e8f6bf2e0caee397570bc0df184484245a2715fb9f5"
      },
      "detected_at": "2026-08-31T14:41:41.676801+00:00",
      "source_feed": "MalwareBazaar"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "a6fd2f09eb81bf3afc83c4b019f21c63aa89a73239e67d0acdf6c8f4e714f2ba",
      "sample_md5": "a369d5c3521cc2a4bdccfd1b9608b4d7",
      "sample_name": "a6fd2f09eb81bf3afc83c4b019f21c63aa89a73239e67d0acdf6c8f4e714f2ba.macho",
      "sample_size_bytes": 810654,
      "mb_metadata": {
        "first_seen": "2023-11-20 13:34:13",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "mac",
          "Mach-O",
          "machO",
          "macOS",
          "Meterpreter",
          "OSX"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 35,
        "total_engines": 59,
        "detection_ratio": "35/59",
        "suggested_threat_label": "trojan.mettle/meterpreter",
        "popular_threat_category": [
          {
            "count": 12,
            "value": "trojan"
          },
          {
            "count": 3,
            "value": "pua"
          }
        ],
        "names": [
          "135fc266af08a28fc7b2d3e0c2ca92e9611e626cec13fb70b9eaad1278b72793.macho",
          "8.macho"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "checks-hostname",
          "macho"
        ],
        "reputation": -13,
        "key_engine_detections": {
          "Microsoft": "Backdoor:MacOS/Meddlingmetal.A",
          "SentinelOne": "Static AI - Malicious Mach-O",
          "Kaspersky": "HEUR:Backdoor.OSX.Agent.l",
          "Sophos": "OSX/Swrort-AX",
          "ESET-NOD32": "OSX/Riskware.Meterpreter.E application"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/a6fd2f09eb81bf3afc83c4b019f21c63aa89a73239e67d0acdf6c8f4e714f2ba"
      },
      "detected_at": "2026-08-31T14:41:41.676801+00:00",
      "source_feed": "MalwareBazaar"
    },
    {
      "rule_name": "MALW_macOS_MacSync_Stealer_Universal",
      "namespace": "macos_MALW_macOS_MacSync_Stealer",
      "tags": [],
      "meta": {
        "description": "Universal multi-architecture detection for macOS MacSync Stealer (Intel x86_64 & Apple Silicon ARM64 / Universal Fat Binaries)",
        "date": "2026-08-31",
        "family": "MacSync",
        "threat_type": "Infostealer / Stager / Exfiltrator",
        "platform": "macOS (x86_64 & ARM64)"
      },
      "matched_strings": [
        {
          "offset": "0x654f",
          "identifier": "$xor_archive",
          "data_preview": "/tmp/osalogging.zip"
        },
        {
          "offset": "0x6581",
          "identifier": "$xor_archive",
          "data_preview": "/tmp/osalogging.zip"
        },
        {
          "offset": "0x129a3",
          "identifier": "$xor_archive",
          "data_preview": "/tmp/osalogging.zip"
        },
        {
          "offset": "0x129d5",
          "identifier": "$xor_archive",
          "data_preview": "/tmp/osalogging.zip"
        },
        {
          "offset": "0x6487",
          "identifier": "$xor_osascript",
          "data_preview": "osascript"
        },
        {
          "offset": "0x6491",
          "identifier": "$xor_osascript",
          "data_preview": "osascript"
        },
        {
          "offset": "0x128db",
          "identifier": "$xor_osascript",
          "data_preview": "osascript"
        },
        {
          "offset": "0x128e5",
          "identifier": "$xor_osascript",
          "data_preview": "osascript"
        },
        {
          "offset": "0x634b",
          "identifier": "$xor_dynamic",
          "data_preview": "/dynamic?txd="
        },
        {
          "offset": "0x1279f",
          "identifier": "$xor_dynamic",
          "data_preview": "/dynamic?txd="
        }
      ],
      "sample_sha256": "4d751dd363298589cb436d78cd302f9d794ae1e3670722a464884be908671a9c",
      "sample_md5": "f9e73c254d7d66e8a99daeb4462e8827",
      "sample_name": "4d751dd363298589cb436d78cd302f9d794ae1e3670722a464884be908671a9c.macho",
      "sample_size_bytes": 136032,
      "mb_metadata": {
        "first_seen": "2025-11-17 15:29:55",
        "file_type": "macho",
        "signature": "MacSync",
        "tags": [
          "infostealer",
          "Mach-O",
          "machO",
          "macOS",
          "MacSync"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 31,
        "total_engines": 58,
        "detection_ratio": "31/58",
        "suggested_threat_label": "trojan.stealer/infostl",
        "popular_threat_category": [
          {
            "count": 18,
            "value": "trojan"
          },
          {
            "count": 3,
            "value": "downloader"
          }
        ],
        "names": [
          "4d751dd363298589cb436d78cd302f9d794ae1e3670722a464884be908671a9c.macho",
          "Order (1).macho",
          "Zoom",
          "_4d751dd363298589cb436d78cd302f9d794ae1e3670722a464884be908671a9c"
        ],
        "type_description": "Mach-O",
        "tags": [
          "multi-arch",
          "arm",
          "macho",
          "self-signed",
          "64bits"
        ],
        "reputation": -55,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/SuspOsaDownload.A",
          "SentinelOne": "Static AI - Suspicious Mach-O",
          "Kaspersky": "HEUR:Trojan-Downloader.OSX.Agent.az",
          "Sophos": "OSX/InfoStl-FI",
          "ESET-NOD32": "OSX/PSW.Agent.FJ trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/4d751dd363298589cb436d78cd302f9d794ae1e3670722a464884be908671a9c"
      },
      "detected_at": "2026-08-31T14:41:41.676801+00:00",
      "source_feed": "MalwareBazaar",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "135fc266af08a28fc7b2d3e0c2ca92e9611e626cec13fb70b9eaad1278b72793",
      "sample_md5": "2a59f062689ca79a5a81fdcdbedf8e19",
      "sample_name": "135fc266af08a28fc7b2d3e0c2ca92e9611e626cec13fb70b9eaad1278b72793.macho",
      "sample_size_bytes": 810648,
      "mb_metadata": {
        "first_seen": "2023-10-02 10:21:33",
        "file_type": "macho",
        "signature": "Meterpreter",
        "tags": [
          "Mach-O",
          "machO",
          "macOS",
          "Meterpreter"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 37,
        "total_engines": 61,
        "detection_ratio": "37/61",
        "suggested_threat_label": "trojan.mettle/meterpreter",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 12
          },
          {
            "value": "pua",
            "count": 3
          }
        ],
        "names": [
          "135fc266af08a28fc7b2d3e0c2ca92e9611e626cec13fb70b9eaad1278b72793.macho",
          "payload.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "checks-hostname",
          "macho",
          "64bits"
        ],
        "reputation": -1,
        "key_engine_detections": {
          "Microsoft": "Backdoor:MacOS/Meddlingmetal.A",
          "SentinelOne": "Static AI - Malicious Mach-O",
          "Kaspersky": "HEUR:Backdoor.OSX.Agent.l",
          "Sophos": "OSX/Swrort-AX",
          "ESET-NOD32": "OSX/Riskware.Meterpreter.E application"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/135fc266af08a28fc7b2d3e0c2ca92e9611e626cec13fb70b9eaad1278b72793"
      },
      "detected_at": "2026-08-31T14:41:41.676801+00:00",
      "source_feed": "MalwareBazaar"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [
        {
          "offset": "0x3c145",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x7d0d1",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x3c579",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0x7d4b3",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0x431c4",
          "identifier": "$op_arm64_dec",
          "data_preview": "4b 09 40 b3 6b 01 40 39 ac 02 0a 8b 8d 41 40 39 ab 01 0b 4a 8b 41 00 39 29 05 c9 93"
        }
      ],
      "sample_sha256": "30f97ae88f8861eeadeb54854d47078724e52e2ef36dd847180663b7f5763168",
      "sample_md5": "760c89959e2d80f9b78a320023a875b7",
      "sample_name": "30f97ae88f8861eeadeb54854d47078724e52e2ef36dd847180663b7f5763168.macho",
      "sample_size_bytes": 521440,
      "mb_metadata": {
        "first_seen": "2026-02-10 15:45:15",
        "file_type": "macho",
        "signature": "AmosStealer",
        "tags": [
          "91-92-242-30",
          "AMOS",
          "AmosStealer",
          "machO",
          "macOS",
          "Trojan:MacOS/Amos.FB!MTB"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 37,
        "total_engines": 62,
        "detection_ratio": "37/62",
        "suggested_threat_label": "trojan.amos/stealer",
        "popular_threat_category": [
          {
            "count": 21,
            "value": "trojan"
          }
        ],
        "names": [
          "sztvvbrvmp.exe",
          "eelmlbmntr.exe",
          "ojoqaintzz.exe",
          "bqzwxvshnd.exe",
          "fpkxbujlke.exe"
        ],
        "type_description": "Mach-O",
        "tags": [
          "self-signed",
          "multi-arch",
          "macho",
          "64bits",
          "arm"
        ],
        "reputation": -160,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/AMOS.HAD!MTB",
          "SentinelOne": "Static AI - Malicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bg",
          "Sophos": "OSX/InfoStl-FX",
          "ESET-NOD32": "OSX/PSW.Agent.GF trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/30f97ae88f8861eeadeb54854d47078724e52e2ef36dd847180663b7f5763168"
      },
      "detected_at": "2026-08-31T14:41:41.676801+00:00",
      "source_feed": "MalwareBazaar",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "00f918996b9192c8ccd0ba4ad80f6f2ed17844d6cbe00eb65afb9df0c8f05430",
      "sample_md5": "0e089ec295022c4bcee6ef0ae15baf4d",
      "sample_name": "00f918996b9192c8.macho",
      "sample_size_bytes": 363504,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 11,
        "total_engines": 76,
        "detection_ratio": "11/76",
        "suggested_threat_label": "trojan.amos/camelot",
        "names": [
          "suspicious",
          "/private/tmp/.w97b0h",
          ".w97b0h"
        ],
        "tags": [
          "macho",
          "multi-arch",
          "arm",
          "64bits",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/00f918996b9192c8ccd0ba4ad80f6f2ed17844d6cbe00eb65afb9df0c8f05430"
      },
      "detected_at": "2026-09-01T07:05:16.190034+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "780dc4cb1bf8697cbc784c8926cc7f55b64c04e8eaa51d20f938cfa352f8c998",
      "sample_md5": "1cf712f1a5b235c7f2baf179a8d2292c",
      "sample_name": "780dc4cb1bf8697c.macho",
      "sample_size_bytes": 163488,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 10,
        "total_engines": 76,
        "detection_ratio": "10/76",
        "suggested_threat_label": "trojan.amos/camelot",
        "names": [
          "localfile~.x64"
        ],
        "tags": [
          "macho",
          "64bits",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/780dc4cb1bf8697cbc784c8926cc7f55b64c04e8eaa51d20f938cfa352f8c998"
      },
      "detected_at": "2026-09-01T07:05:16.190034+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "e4e8aa9a827e820fd98fa061442cac2ac95fbb7ed1b3e5a0d99aef048e4a123e",
      "sample_md5": "82a8dd0979c155a5b937457a055ceec9",
      "sample_name": "e4e8aa9a827e820f.macho",
      "sample_size_bytes": 183168,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 11,
        "total_engines": 76,
        "detection_ratio": "11/76",
        "suggested_threat_label": "trojan.amos/camelot",
        "names": [
          "localfile~.arm64"
        ],
        "tags": [
          "macho",
          "64bits",
          "arm",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/e4e8aa9a827e820fd98fa061442cac2ac95fbb7ed1b3e5a0d99aef048e4a123e"
      },
      "detected_at": "2026-09-01T07:05:16.190034+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "e0ad9eab55dee8da82090915d94b2b07ae2b0537312b4d0397fec8bb1380ad2c",
      "sample_md5": "194e600ceabf884ac24e5e26f809a899",
      "sample_name": "e0ad9eab55dee8da.macho",
      "sample_size_bytes": 363392,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 11,
        "total_engines": 76,
        "detection_ratio": "11/76",
        "suggested_threat_label": "trojan.amos/camelot",
        "names": [
          "helper.bin"
        ],
        "tags": [
          "arm",
          "macho",
          "multi-arch",
          "64bits",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/e0ad9eab55dee8da82090915d94b2b07ae2b0537312b4d0397fec8bb1380ad2c"
      },
      "detected_at": "2026-09-01T07:05:16.190034+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "04465e8d0cebb270bacc5db8bb874cf01bd4ba85afd317b9d8748cbcb53ce5c7",
      "sample_md5": "2a3d2a7f5d237f4043df74f9384a4d1e",
      "sample_name": "04465e8d0cebb270.macho",
      "sample_size_bytes": 159488,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 10,
        "total_engines": 76,
        "detection_ratio": "10/76",
        "suggested_threat_label": "trojan.amos/camelot",
        "names": [
          "localfile~.x64"
        ],
        "tags": [
          "64bits",
          "macho",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/04465e8d0cebb270bacc5db8bb874cf01bd4ba85afd317b9d8748cbcb53ce5c7"
      },
      "detected_at": "2026-09-01T07:05:16.190034+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "e20f38eedb7fd126834250aa43453faa99833e7c0f39029691dad8ca5e9f5ce9",
      "sample_md5": "5830375e56c336e44c31113463061ce9",
      "sample_name": "e20f38eedb7fd126.macho",
      "sample_size_bytes": 183280,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 10,
        "total_engines": 76,
        "detection_ratio": "10/76",
        "suggested_threat_label": "trojan.camelot/multiverze",
        "names": [
          "localfile~.arm64"
        ],
        "tags": [
          "macho",
          "64bits",
          "arm",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/e20f38eedb7fd126834250aa43453faa99833e7c0f39029691dad8ca5e9f5ce9"
      },
      "detected_at": "2026-09-01T07:05:16.190034+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "620662ab495dacef6ac971ab82da995d430b9b0e9f92445acd136e0cd07d6821",
      "sample_md5": "3102e826afb3cbe093361fe42b4f1945",
      "sample_name": "620662ab495dacef.macho",
      "sample_size_bytes": 183184,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 11,
        "total_engines": 76,
        "detection_ratio": "11/76",
        "suggested_threat_label": "trojan.amos/camelot",
        "names": [
          "localfile~.arm64"
        ],
        "tags": [
          "arm",
          "64bits",
          "macho",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/620662ab495dacef6ac971ab82da995d430b9b0e9f92445acd136e0cd07d6821"
      },
      "detected_at": "2026-09-01T07:05:16.190034+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "ef1d615bbf15dbee3d2dd51f843a462230014f0212423182c38d93140e176460",
      "sample_md5": "24acf4e03df9c598499eab765412a14c",
      "sample_name": "ef1d615bbf15dbee.macho",
      "sample_size_bytes": 159392,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 10,
        "total_engines": 76,
        "detection_ratio": "10/76",
        "suggested_threat_label": "trojan.amos/camelot",
        "names": [
          "localfile~.x64"
        ],
        "tags": [
          "macho",
          "64bits",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/ef1d615bbf15dbee3d2dd51f843a462230014f0212423182c38d93140e176460"
      },
      "detected_at": "2026-09-01T07:05:16.190034+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0xef2c",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x35d8c",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x10090",
          "identifier": "$payload_hash1",
          "data_preview": "9e 0b 82 e1 6d 94 c4 8f bf c7 12 00 4d b9 95 be a8 23 e8 97 7a c7 a9 4c d7 c3 a4 f2 fe 08 05 07"
        },
        {
          "offset": "0x38090",
          "identifier": "$payload_hash1",
          "data_preview": "9e 0b 82 e1 6d 94 c4 8f bf c7 12 00 4d b9 95 be a8 23 e8 97 7a c7 a9 4c d7 c3 a4 f2 fe 08 05 07"
        }
      ],
      "sample_sha256": "76c2e4e7fb5290366d7bd04703ea60ec92d314ff651172387b9c6dbfca22b82a",
      "sample_md5": "a19b8d6e37d51b294a96bac703de24cb",
      "sample_name": "76c2e4e7fb529036.macho",
      "sample_size_bytes": 363408,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 30,
        "total_engines": 63,
        "detection_ratio": "30/63",
        "suggested_threat_label": "trojan.amos/stealer",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 18
          }
        ],
        "names": [
          "76c2e4e7fb5290366d7bd04703ea60ec92d314ff651172387b9c6dbfca22b82a.macho",
          "pio4wo.exe",
          "stage3.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "service-scan",
          "arm",
          "self-signed",
          "64bits",
          "multi-arch"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bx",
          "ESET-NOD32": "OSX/PSW.Agent.JL trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/76c2e4e7fb5290366d7bd04703ea60ec92d314ff651172387b9c6dbfca22b82a"
      },
      "detected_at": "2026-09-01T07:05:16.190034+00:00",
      "mb_metadata": {
        "first_seen": "2026-09-13 11:34:57",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "fake-homebrew",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "MALW_macOS_MacSync_Stealer_Universal",
      "namespace": "macos_MALW_macOS_MacSync_Stealer",
      "tags": [],
      "meta": {
        "description": "Universal multi-architecture detection for macOS MacSync Stealer (Intel x86_64 & Apple Silicon ARM64 / Universal Fat Binaries)",
        "date": "2026-08-31",
        "family": "MacSync",
        "threat_type": "Infostealer / Stager / Exfiltrator",
        "platform": "macOS (x86_64 & ARM64)"
      },
      "matched_strings": [],
      "sample_sha256": "a864c989d8a28cc5d2162050bb862775ee7297ce305c19014a0c63a4b73e993b",
      "sample_md5": "6c50481eeea199f059bda10184bea0a6",
      "sample_name": "a864c989d8a28cc5.macho",
      "sample_size_bytes": 137328,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 23,
        "total_engines": 76,
        "detection_ratio": "23/76",
        "suggested_threat_label": "trojan.coins/abtrojan",
        "names": [
          "Launcher",
          "Launcher/Launcher.app/Contents/MacOS/Launcher"
        ],
        "tags": [
          "64bits",
          "multi-arch",
          "macho",
          "self-delete",
          "self-signed",
          "arm"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/a864c989d8a28cc5d2162050bb862775ee7297ce305c19014a0c63a4b73e993b"
      },
      "detected_at": "2026-09-01T10:24:38.407549+00:00"
    },
    {
      "rule_name": "MALW_macOS_MacSync_Stealer_Universal",
      "namespace": "macos_MALW_macOS_MacSync_Stealer",
      "tags": [],
      "meta": {
        "description": "Universal multi-architecture detection for macOS MacSync Stealer (Intel x86_64 & Apple Silicon ARM64 / Universal Fat Binaries)",
        "date": "2026-08-31",
        "family": "MacSync",
        "threat_type": "Infostealer / Stager / Exfiltrator",
        "platform": "macOS (x86_64 & ARM64)"
      },
      "matched_strings": [
        {
          "offset": "0x2a2e",
          "identifier": "$xor_httpcode",
          "data_preview": "85 de c7 da 85 84 c2 de de da c9 c5 ce cf"
        },
        {
          "offset": "0x2dc1",
          "identifier": "$xor_archive",
          "data_preview": "85 de c7 da 85 c5 d9 cb c6 c5 cd cd c3 c4 cd 84 d0 c3 da"
        },
        {
          "offset": "0x2b9a",
          "identifier": "$xor_osascript",
          "data_preview": "c5 d9 cb d9 c9 d8 c3 da de"
        },
        {
          "offset": "0x2d5c",
          "identifier": "$xor_osascript",
          "data_preview": "c5 d9 cb d9 c9 d8 c3 da de"
        },
        {
          "offset": "0x2a72",
          "identifier": "$xor_curl",
          "data_preview": "c9 df d8 c6 8a 87 c1 8a 87 d9"
        },
        {
          "offset": "0x2b55",
          "identifier": "$xor_curl",
          "data_preview": "c9 df d8 c6 8a 87 c1 8a 87 d9"
        },
        {
          "offset": "0x2c34",
          "identifier": "$xor_curl",
          "data_preview": "c9 df d8 c6 8a 87 c1 8a 87 d9"
        },
        {
          "offset": "0x2d17",
          "identifier": "$xor_curl",
          "data_preview": "c9 df d8 c6 8a 87 c1 8a 87 d9"
        },
        {
          "offset": "0x2e04",
          "identifier": "$xor_curl",
          "data_preview": "c9 df d8 c6 8a 87 c1 8a 87 d9"
        },
        {
          "offset": "0x2dd5",
          "identifier": "$xor_dd_slice",
          "data_preview": "ce ce 8a c3 cc 97"
        },
        {
          "offset": "0x2eb3",
          "identifier": "$xor_chunk_fmt",
          "data_preview": "c9 c2 df c4 c1 f5 c3 c4 ce cf d2 97"
        },
        {
          "offset": "0x2a44",
          "identifier": "$xor_dynamic",
          "data_preview": "85 ce d3 c4 cb c7 c3 c9 95 de d2 ce 97"
        },
        {
          "offset": "0x2a62",
          "identifier": "$xor_dynamic",
          "data_preview": "85 ce d3 c4 cb c7 c3 c9 95 de d2 ce 97"
        },
        {
          "offset": "0x2c06",
          "identifier": "$xor_dynamic",
          "data_preview": "85 ce d3 c4 cb c7 c3 c9 95 de d2 ce 97"
        },
        {
          "offset": "0x2c24",
          "identifier": "$xor_dynamic",
          "data_preview": "85 ce d3 c4 cb c7 c3 c9 95 de d2 ce 97"
        }
      ],
      "sample_sha256": "9ff32f7c0108e9d27a3b491edf04827b6ca025f44db68aeadc44eeb97c9aab11",
      "sample_md5": "9678f71ea4cccbc3d511dc8d7f24b113",
      "sample_name": "9ff32f7c0108e9d2.macho",
      "sample_size_bytes": 38800,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 27,
        "total_engines": 76,
        "detection_ratio": "27/76",
        "suggested_threat_label": "trojan.coins/infostl",
        "names": [
          "localfile~.x64"
        ],
        "tags": [
          "macho",
          "64bits",
          "self-signed",
          "malware",
          "self-delete"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/9ff32f7c0108e9d27a3b491edf04827b6ca025f44db68aeadc44eeb97c9aab11"
      },
      "detected_at": "2026-09-01T10:24:38.407549+00:00",
      "last_seen_at": "2026-10-19T02:32:11.677388+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [],
      "sample_sha256": "f2b8d86adc1cfe5833d07c0ac09c69192bd1ca54717cc40dd00977deb426b53f",
      "sample_md5": "fe3fc34719e2266ccf128001bbdbd2b2",
      "sample_name": "f2b8d86adc1cfe58.macho",
      "sample_size_bytes": 362624,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 17,
        "total_engines": 76,
        "detection_ratio": "17/76",
        "suggested_threat_label": "trojan.stealer/amos",
        "names": [
          "localfile~.arm64"
        ],
        "tags": [
          "64bits",
          "macho",
          "arm",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/f2b8d86adc1cfe5833d07c0ac09c69192bd1ca54717cc40dd00977deb426b53f"
      },
      "detected_at": "2026-09-01T15:39:30.104454+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [],
      "sample_sha256": "162740169bc202ab264ebf99a6e1a8789522601986be7965277a77460b103e2b",
      "sample_md5": "d41302d8613de5fe37bb0609254bfdd0",
      "sample_name": "162740169bc202ab.macho",
      "sample_size_bytes": 723072,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 28,
        "total_engines": 76,
        "detection_ratio": "28/76",
        "suggested_threat_label": "trojan.stealer/amos",
        "names": [
          "pbyb1t39qwbbannl"
        ],
        "tags": [
          "multi-arch",
          "arm",
          "64bits",
          "macho",
          "self-signed",
          "self-delete",
          "checks-cpu-name",
          "password-dialog"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/162740169bc202ab264ebf99a6e1a8789522601986be7965277a77460b103e2b"
      },
      "detected_at": "2026-09-01T15:39:30.104454+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "4bae510072353a0493b1bb58f167e1afb7636f11531dfa696df804fa50d582ef",
      "sample_md5": "ed25fafe902949680af83c8c74f7e178",
      "sample_name": "4bae510072353a04.macho",
      "sample_size_bytes": 163520,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 7,
        "total_engines": 76,
        "detection_ratio": "7/76",
        "suggested_threat_label": "trojan.amos/camelot",
        "names": [
          "localfile~.x64"
        ],
        "tags": [
          "64bits",
          "macho",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/4bae510072353a0493b1bb58f167e1afb7636f11531dfa696df804fa50d582ef"
      },
      "detected_at": "2026-09-01T15:39:30.104454+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "fb5f2418abc9c44235a6495f91cb95e6df19dc1fd30181c8ad5bc91797a55f66",
      "sample_md5": "92a8c2e77c47ee4d42e65a9b28d90a68",
      "sample_name": "fb5f2418abc9c442.macho",
      "sample_size_bytes": 199600,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 13,
        "total_engines": 76,
        "detection_ratio": "13/76",
        "suggested_threat_label": "trojan.amos/amosstealer",
        "names": [
          "localfile~.arm64"
        ],
        "tags": [
          "64bits",
          "arm",
          "macho",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/fb5f2418abc9c44235a6495f91cb95e6df19dc1fd30181c8ad5bc91797a55f66"
      },
      "detected_at": "2026-09-01T15:39:30.104454+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "8043fedb8e00499538421af1ffdf4371553c5c93506c6b2d82bf2660823fd05e",
      "sample_md5": "1d2973afb31831d17f6e248452982ed2",
      "sample_name": "8043fedb8e004995.macho",
      "sample_size_bytes": 379824,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 12,
        "total_engines": 76,
        "detection_ratio": "12/76",
        "suggested_threat_label": "trojan.amos/amosstealer",
        "names": [
          "/private/tmp/.ecnemodfxi",
          ".ecnemodfxi"
        ],
        "tags": [
          "macho",
          "64bits",
          "multi-arch",
          "arm",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/8043fedb8e00499538421af1ffdf4371553c5c93506c6b2d82bf2660823fd05e"
      },
      "detected_at": "2026-09-01T15:39:30.104454+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "63cba47e46c0b4051c1d9d7e476743f1ce3b7868ceb425a7e8f877460917d2a0",
      "sample_md5": "70121e1a7b25311b54d06fa14e15e660",
      "sample_name": "63cba47e46c0b405.macho",
      "sample_size_bytes": 183184,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 12,
        "total_engines": 76,
        "detection_ratio": "12/76",
        "suggested_threat_label": "trojan.amos/camelot",
        "names": [
          "localfile~.arm64"
        ],
        "tags": [
          "macho",
          "arm",
          "64bits",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/63cba47e46c0b4051c1d9d7e476743f1ce3b7868ceb425a7e8f877460917d2a0"
      },
      "detected_at": "2026-09-01T15:39:30.104454+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [],
      "sample_sha256": "72a3e5de9427ba286e1eff30367d629db37f327c55801ace3ad3324f8476a794",
      "sample_md5": "c2699c98c169dfc2591771fcf8c14957",
      "sample_name": "72a3e5de9427ba28.macho",
      "sample_size_bytes": 362624,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 19,
        "total_engines": 76,
        "detection_ratio": "19/76",
        "suggested_threat_label": "trojan.stealer/amos",
        "names": [
          "localfile~.arm64"
        ],
        "tags": [
          "64bits",
          "arm",
          "macho",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/72a3e5de9427ba286e1eff30367d629db37f327c55801ace3ad3324f8476a794"
      },
      "detected_at": "2026-09-02T08:06:00.959996+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [],
      "sample_sha256": "1bde09781d733947ff7658c89a4e55af3486f7a9db5e50b24a812e4cc1451e61",
      "sample_md5": "d36a42c9c3dfdb55601646c8be35b24d",
      "sample_name": "1bde09781d733947.macho",
      "sample_size_bytes": 723072,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 28,
        "total_engines": 76,
        "detection_ratio": "28/76",
        "suggested_threat_label": "trojan.stealer/amos",
        "names": [
          "Application"
        ],
        "tags": [
          "arm",
          "64bits",
          "macho",
          "multi-arch",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/1bde09781d733947ff7658c89a4e55af3486f7a9db5e50b24a812e4cc1451e61"
      },
      "detected_at": "2026-09-02T08:06:00.959996+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "e5a00c378da0a2bbcc1233a620a115f73c627d9ac9831f66be713632d9611183",
      "sample_md5": "a4df617e6f0aa3764c61fde8bd12da6c",
      "sample_name": "e5a00c378da0a2bb.macho",
      "sample_size_bytes": 199696,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 12,
        "total_engines": 76,
        "detection_ratio": "12/76",
        "suggested_threat_label": "trojan.amos/amosstealer",
        "names": [
          "localfile~.arm64"
        ],
        "tags": [
          "arm",
          "macho",
          "64bits",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/e5a00c378da0a2bbcc1233a620a115f73c627d9ac9831f66be713632d9611183"
      },
      "detected_at": "2026-09-02T08:06:00.959996+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "55364ff47a8789d5c4b414dd7dae05820e8129d6c7592708778550b6b3e220f3",
      "sample_md5": "4fc01d6085031723c4837bfd9f63c6b8",
      "sample_name": "55364ff47a8789d5.macho",
      "sample_size_bytes": 163616,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 10,
        "total_engines": 76,
        "detection_ratio": "10/76",
        "suggested_threat_label": "trojan.amos/camelot",
        "names": [
          "localfile~.x64"
        ],
        "tags": [
          "macho",
          "64bits",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/55364ff47a8789d5c4b414dd7dae05820e8129d6c7592708778550b6b3e220f3"
      },
      "detected_at": "2026-09-02T08:06:00.959996+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "0ce6c083c86d95df0962b6274a705631ccb87f5eb497b0fadd34d6040bb4913c",
      "sample_md5": "36b24dc1e17aa863c60a25db0995d3c2",
      "sample_name": "0ce6c083c86d95df.macho",
      "sample_size_bytes": 379920,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 12,
        "total_engines": 76,
        "detection_ratio": "12/76",
        "suggested_threat_label": "trojan.amos/amosstealer",
        "names": [
          "/private/tmp/.syu1dko",
          ".syu1dko"
        ],
        "tags": [
          "64bits",
          "multi-arch",
          "macho",
          "arm",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/0ce6c083c86d95df0962b6274a705631ccb87f5eb497b0fadd34d6040bb4913c"
      },
      "detected_at": "2026-09-02T08:06:00.959996+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "ea8f3d6c2bfd3701bf1091f280843e29dec54d9403d77c680079d208fa2924a7",
      "sample_md5": "b7a718f06c1427aa39b2a01e94e3d537",
      "sample_name": "ea8f3d6c2bfd3701.macho",
      "sample_size_bytes": 167776,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 11,
        "total_engines": 76,
        "detection_ratio": "11/76",
        "suggested_threat_label": "trojan.amos/camelot",
        "names": [
          "localfile~.x64"
        ],
        "tags": [
          "64bits",
          "macho",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/ea8f3d6c2bfd3701bf1091f280843e29dec54d9403d77c680079d208fa2924a7"
      },
      "detected_at": "2026-09-02T15:18:39.415006+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "69670fdc892a5794bc78811ef551dcd40bed770cfa4f6aa6851db688c6466dd0",
      "sample_md5": "15c119e598138c4a75b11c5f705c6761",
      "sample_name": "69670fdc892a5794.macho",
      "sample_size_bytes": 183312,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 11,
        "total_engines": 76,
        "detection_ratio": "11/76",
        "suggested_threat_label": "trojan.amos/camelot",
        "names": [
          "localfile~.arm64"
        ],
        "tags": [
          "64bits",
          "arm",
          "macho",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/69670fdc892a5794bc78811ef551dcd40bed770cfa4f6aa6851db688c6466dd0"
      },
      "detected_at": "2026-09-02T15:18:39.415006+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "7ac18a468064212c7c74d602364e43afde5b00a93ac7e84acf321ae2279a1213",
      "sample_md5": "0048461f78477539673e4106e874456e",
      "sample_name": "7ac18a468064212c.macho",
      "sample_size_bytes": 163616,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 10,
        "total_engines": 76,
        "detection_ratio": "10/76",
        "suggested_threat_label": "trojan.amos/camelot",
        "names": [
          "localfile~.x64"
        ],
        "tags": [
          "macho",
          "64bits",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/7ac18a468064212c7c74d602364e43afde5b00a93ac7e84acf321ae2279a1213"
      },
      "detected_at": "2026-09-02T15:18:39.415006+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "23269d1af542f94427f6994c509de9b1c31bdad5cc48ed1acc773130faf5bd9a",
      "sample_md5": "c48ad84d78cc17038647e2c829c77ef2",
      "sample_name": "23269d1af542f944.macho",
      "sample_size_bytes": 183280,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 11,
        "total_engines": 76,
        "detection_ratio": "11/76",
        "suggested_threat_label": "trojan.amos/camelot",
        "names": [
          "localfile~.arm64"
        ],
        "tags": [
          "64bits",
          "arm",
          "macho",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/23269d1af542f94427f6994c509de9b1c31bdad5cc48ed1acc773130faf5bd9a"
      },
      "detected_at": "2026-09-02T15:18:39.415006+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "fad2eda61740a347df03b0f64fee4510fc05631549c4d501487522cb8fb980c4",
      "sample_md5": "8671eb11e5d4abcb6040ae9305586720",
      "sample_name": "fad2eda61740a347.macho",
      "sample_size_bytes": 363504,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 11,
        "total_engines": 76,
        "detection_ratio": "11/76",
        "suggested_threat_label": "trojan.amos/camelot",
        "names": [
          "/private/tmp/.fjaa1",
          ".fjaa1"
        ],
        "tags": [
          "arm",
          "multi-arch",
          "64bits",
          "macho",
          "self-signed",
          "service-scan"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/fad2eda61740a347df03b0f64fee4510fc05631549c4d501487522cb8fb980c4"
      },
      "detected_at": "2026-09-02T15:18:39.415006+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [],
      "sample_sha256": "2a3a9a9d69c8cfa90879da2294d603a81fc9e97349b22e6a0aed3b565e092c1d",
      "sample_md5": "93b8daa2c25a17e0c2abb5d8b0b3cdf2",
      "sample_name": "2a3a9a9d69c8cfa9.macho",
      "sample_size_bytes": 723072,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 28,
        "total_engines": 76,
        "detection_ratio": "28/76",
        "suggested_threat_label": "trojan.stealer/amos",
        "names": [
          "b3untvncvmvxniwl"
        ],
        "tags": [
          "arm",
          "64bits",
          "multi-arch",
          "macho",
          "self-signed",
          "self-delete",
          "checks-cpu-name",
          "password-dialog"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/2a3a9a9d69c8cfa90879da2294d603a81fc9e97349b22e6a0aed3b565e092c1d"
      },
      "detected_at": "2026-09-03T05:14:39.088706+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [],
      "sample_sha256": "1f78a436c529a6da706486ee8bd4a6adfe879bea858ef7d3393833d1158c36ce",
      "sample_md5": "fed2cdf7bf7bd6d18a28a6d60c8a8b46",
      "sample_name": "1f78a436c529a6da.macho",
      "sample_size_bytes": 362624,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 18,
        "total_engines": 76,
        "detection_ratio": "18/76",
        "suggested_threat_label": "trojan.stealer/amos",
        "names": [
          "localfile~.arm64"
        ],
        "tags": [
          "macho",
          "arm",
          "64bits",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/1f78a436c529a6da706486ee8bd4a6adfe879bea858ef7d3393833d1158c36ce"
      },
      "detected_at": "2026-09-03T05:14:39.088706+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [],
      "sample_sha256": "871ef3467b7dfae4117cf63607010299e413c45af28694c2b5aef9c85561a484",
      "sample_md5": "0fbe66449889f961bf036960acdc3d02",
      "sample_name": "871ef3467b7dfae4.macho",
      "sample_size_bytes": 362624,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 18,
        "total_engines": 76,
        "detection_ratio": "18/76",
        "suggested_threat_label": "trojan.stealer/amos",
        "names": [
          "localfile~.arm64"
        ],
        "tags": [
          "64bits",
          "arm",
          "macho",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/871ef3467b7dfae4117cf63607010299e413c45af28694c2b5aef9c85561a484"
      },
      "detected_at": "2026-09-03T05:14:39.088706+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [],
      "sample_sha256": "520ac683d4919cc6cc40104dbf1c147df89baee25a4d591ac635eae8c3b6a1a2",
      "sample_md5": "97dff05e641290f26df3ae1b1f6446b4",
      "sample_name": "520ac683d4919cc6.macho",
      "sample_size_bytes": 723072,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 28,
        "total_engines": 76,
        "detection_ratio": "28/76",
        "suggested_threat_label": "trojan.stealer/amos",
        "names": [
          "1r8usi8o67dob3q7"
        ],
        "tags": [
          "macho",
          "multi-arch",
          "arm",
          "64bits",
          "self-signed",
          "self-delete",
          "checks-cpu-name",
          "password-dialog"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/520ac683d4919cc6cc40104dbf1c147df89baee25a4d591ac635eae8c3b6a1a2"
      },
      "detected_at": "2026-09-03T05:14:39.088706+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "81518176695d31946a991e2ed84c458d687b16ea77b92e718d38a2d915be8bdb",
      "sample_md5": "9a3548a4babcb2e698acd478a1f7604d",
      "sample_name": "81518176695d3194.macho",
      "sample_size_bytes": 159360,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 8,
        "total_engines": 76,
        "detection_ratio": "8/76",
        "suggested_threat_label": "trojan.amos/camelot",
        "names": [
          "localfile~.x64"
        ],
        "tags": [
          "64bits",
          "macho",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/81518176695d31946a991e2ed84c458d687b16ea77b92e718d38a2d915be8bdb"
      },
      "detected_at": "2026-09-03T05:14:39.088706+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "9a2e9044e2c60d273fab7035a00740c7ec49dc1c1b82e8c697b4b90ab2f2db4f",
      "sample_md5": "1d4d545b5aac3a3122751e4978bad5be",
      "sample_name": "9a2e9044e2c60d27.macho",
      "sample_size_bytes": 183168,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 11,
        "total_engines": 76,
        "detection_ratio": "11/76",
        "suggested_threat_label": "trojan.amos/camelot",
        "names": [
          "localfile~.arm64"
        ],
        "tags": [
          "64bits",
          "macho",
          "arm",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/9a2e9044e2c60d273fab7035a00740c7ec49dc1c1b82e8c697b4b90ab2f2db4f"
      },
      "detected_at": "2026-09-03T05:14:39.088706+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [],
      "sample_sha256": "aaa56fb51a0dd7cf74667d090d456cc24f6b5b3b3484831f4371e38481cb9fb4",
      "sample_md5": "7eb816ede6a1d7b913af087b760560bb",
      "sample_name": "aaa56fb51a0dd7cf.macho",
      "sample_size_bytes": 363392,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 11,
        "total_engines": 76,
        "detection_ratio": "11/76",
        "suggested_threat_label": "trojan.amos/camelot",
        "names": [],
        "tags": [
          "multi-arch",
          "arm",
          "macho",
          "64bits",
          "self-signed",
          "checks-cpu-name"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/aaa56fb51a0dd7cf74667d090d456cc24f6b5b3b3484831f4371e38481cb9fb4"
      },
      "detected_at": "2026-09-03T05:14:39.088706+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [],
      "sample_sha256": "a5655a9b4c4889bfd7fcbf928d4979afcacb1577fff3697defae7c0cccafea8a",
      "sample_md5": "d0d9aa01e0f056550e45e63bc626add5",
      "sample_name": "a5655a9b4c4889bf.macho",
      "sample_size_bytes": 362624,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 17,
        "total_engines": 76,
        "detection_ratio": "17/76",
        "suggested_threat_label": "trojan.stealer/amos",
        "names": [
          "localfile~.arm64"
        ],
        "tags": [
          "64bits",
          "arm",
          "macho",
          "self-signed",
          "service-scan"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/a5655a9b4c4889bfd7fcbf928d4979afcacb1577fff3697defae7c0cccafea8a"
      },
      "detected_at": "2026-09-03T17:22:39.836553+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [],
      "sample_sha256": "3b9aa24a02b112fd7881c9c7fdccba1b4677e138b4571d211b54a1cf5b68fe0d",
      "sample_md5": "63dec2e7d422c784e50146223c4091f1",
      "sample_name": "3b9aa24a02b112fd.macho",
      "sample_size_bytes": 723072,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 28,
        "total_engines": 76,
        "detection_ratio": "28/76",
        "suggested_threat_label": "trojan.stealer/amos",
        "names": [
          "momq4l493yfj6gmq"
        ],
        "tags": [
          "self-signed",
          "multi-arch",
          "arm",
          "macho",
          "64bits",
          "self-delete",
          "checks-cpu-name",
          "password-dialog"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/3b9aa24a02b112fd7881c9c7fdccba1b4677e138b4571d211b54a1cf5b68fe0d"
      },
      "detected_at": "2026-09-03T17:22:39.836553+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [],
      "sample_sha256": "aa293672aa84cf35ce0418ce081f23ea7fc028926f5b369464923ea753c33f21",
      "sample_md5": "e2af1093f6d4e2b54d6469a72aa5112d",
      "sample_name": "aa293672aa84cf35.macho",
      "sample_size_bytes": 723072,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 32,
        "total_engines": 76,
        "detection_ratio": "32/76",
        "suggested_threat_label": "trojan.stealer/amos",
        "names": [
          "rnzixa5gl2ixqum9"
        ],
        "tags": [
          "64bits",
          "multi-arch",
          "macho",
          "checks-cpu-name",
          "arm",
          "password-dialog",
          "self-delete",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/aa293672aa84cf35ce0418ce081f23ea7fc028926f5b369464923ea753c33f21"
      },
      "detected_at": "2026-09-04T05:40:37.603450+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [],
      "sample_sha256": "e97f729d30190d8e798254e12bbc95c31c8c6f82718d582fe8fa30a0ac4d2c11",
      "sample_md5": "f2e4525d7b78436b8b94b70e66ad655b",
      "sample_name": "e97f729d30190d8e.macho",
      "sample_size_bytes": 362624,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 18,
        "total_engines": 76,
        "detection_ratio": "18/76",
        "suggested_threat_label": "trojan.stealer/amos",
        "names": [
          "localfile~.arm64"
        ],
        "tags": [
          "64bits",
          "arm",
          "macho",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/e97f729d30190d8e798254e12bbc95c31c8c6f82718d582fe8fa30a0ac4d2c11"
      },
      "detected_at": "2026-09-04T05:40:37.603450+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [],
      "sample_sha256": "a5c87b8f2d582e6c145a4f07b2e1a475e4da74dbfd33dc49fffdfc27a184666c",
      "sample_md5": "b90a9ea037adbfcd49ae7de43006681d",
      "sample_name": "a5c87b8f2d582e6c.macho",
      "sample_size_bytes": 362624,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 18,
        "total_engines": 76,
        "detection_ratio": "18/76",
        "suggested_threat_label": "trojan.stealer/amos",
        "names": [
          "localfile~.arm64"
        ],
        "tags": [
          "macho",
          "arm",
          "64bits",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/a5c87b8f2d582e6c145a4f07b2e1a475e4da74dbfd33dc49fffdfc27a184666c"
      },
      "detected_at": "2026-09-04T05:40:37.603450+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [],
      "sample_sha256": "124f942b3f3dc9052766ba141f76d434f995f83e95a7ce8a53018c4f2f377410",
      "sample_md5": "1ee2961bbc03f8703bbb17021688f8ee",
      "sample_name": "124f942b3f3dc905.macho",
      "sample_size_bytes": 723072,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 27,
        "total_engines": 76,
        "detection_ratio": "27/76",
        "suggested_threat_label": "trojan.stealer/amos",
        "names": [
          "54c2xsfybxekjezb"
        ],
        "tags": [
          "64bits",
          "multi-arch",
          "arm",
          "macho",
          "self-signed",
          "self-delete",
          "checks-cpu-name",
          "password-dialog"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/124f942b3f3dc9052766ba141f76d434f995f83e95a7ce8a53018c4f2f377410"
      },
      "detected_at": "2026-09-04T05:40:37.603450+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [],
      "sample_sha256": "6cbcd5c5b3c1bdef8d23f019fce29221ffc0f6ea32c79e2d1a1b57f40571bca5",
      "sample_md5": "69070869aa9aa3093036c27babc04052",
      "sample_name": "6cbcd5c5b3c1bdef.macho",
      "sample_size_bytes": 723072,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 33,
        "total_engines": 76,
        "detection_ratio": "33/76",
        "suggested_threat_label": "trojan.stealer/amos",
        "names": [
          "d1dxajouzpz3eomc"
        ],
        "tags": [
          "arm",
          "self-delete",
          "self-signed",
          "64bits",
          "multi-arch",
          "checks-cpu-name",
          "password-dialog",
          "macho"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/6cbcd5c5b3c1bdef8d23f019fce29221ffc0f6ea32c79e2d1a1b57f40571bca5"
      },
      "detected_at": "2026-09-04T05:40:37.603450+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [],
      "sample_sha256": "c69dfd8e46ebea022ac512d9596fe5b1345bcd631815f0e759ea2e941d80df93",
      "sample_md5": "3ecebee5d28275a6e6da939f6fa18b20",
      "sample_name": "c69dfd8e46ebea02.macho",
      "sample_size_bytes": 723072,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 33,
        "total_engines": 76,
        "detection_ratio": "33/76",
        "suggested_threat_label": "trojan.stealer/amos",
        "names": [
          "e0stmozypv2fv7xs",
          "D:\\Itch_bordel\\e0stmozypv2fv7xs"
        ],
        "tags": [
          "multi-arch",
          "arm",
          "64bits",
          "macho",
          "self-signed",
          "checks-cpu-name"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/c69dfd8e46ebea022ac512d9596fe5b1345bcd631815f0e759ea2e941d80df93"
      },
      "detected_at": "2026-09-04T05:40:37.603450+00:00"
    },
    {
      "rule_name": "MALW_macOS_MacSync_Stealer_Universal",
      "platform": "macos",
      "namespace": "macos_MALW_macOS_MacSync_Stealer",
      "tags": [],
      "meta": {
        "description": "Universal multi-architecture detection for macOS MacSync Stealer (Intel x86_64 & Apple Silicon ARM64 / Universal Fat Binaries)",
        "date": "2026-08-31",
        "family": "MacSync",
        "threat_type": "Infostealer / Stager / Exfiltrator",
        "platform": "macOS (x86_64 & ARM64)"
      },
      "matched_strings": [],
      "sample_sha256": "9a8d315d8cde1cb627c6844997f9db980174a478dbb1c936a9cd245d9f5745bb",
      "sample_md5": "24f440340a461587ce1a5226f22922c1",
      "sample_name": "9a8d315d8cde1cb6.macho",
      "sample_size_bytes": 38800,
      "source_feed": "VirusTotal Enterprise",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 8,
        "total_engines": 76,
        "detection_ratio": "8/76",
        "suggested_threat_label": "trojan.coins",
        "names": [
          "localfile~.x64"
        ],
        "tags": [
          "macho",
          "64bits",
          "self-signed"
        ],
        "vt_permalink": "https://www.virustotal.com/gui/file/9a8d315d8cde1cb627c6844997f9db980174a478dbb1c936a9cd245d9f5745bb"
      },
      "detected_at": "2026-09-05T07:20:33.533588+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_64_le",
          "data_preview": "cf fa ed fe"
        },
        {
          "offset": "0x467a8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "aa3934340337aaceee150fd8e2acaa5b5da71a59161585594e53d0477d9d87c6",
      "sample_md5": "22777a448492f0b5b2e1bae53b90c5d5",
      "sample_name": "aa3934340337aaceee150fd8e2acaa5b5da71a59161585594e53d0477d9d87c6.macho",
      "sample_size_bytes": 412584,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-05 13:48:32",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "arm64e",
          "backdoor",
          "Coruna",
          "iOS",
          "machO",
          "PLASMAGRID"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 23,
        "total_engines": 63,
        "detection_ratio": "23/63",
        "suggested_threat_label": "trojan.coruna/falsesign",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 15
          }
        ],
        "names": [
          "h4zjq87.exe",
          "ydivyzn.exe",
          "mfxxg8f9.exe",
          "aa3934340337aaceee150fd8e2acaa5b5da71a59161585594e53d0477d9d87c6.macho"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "lib",
          "ios",
          "macho",
          "arm"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:iPhoneOS/Multiverze!rfn",
          "ESET-NOD32": "iOS/Coruna.B trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/aa3934340337aaceee150fd8e2acaa5b5da71a59161585594e53d0477d9d87c6"
      },
      "detected_at": "2026-09-05T15:21:19.633365+00:00",
      "last_seen_at": "2026-09-18T09:15:01.829625+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_64_le",
          "data_preview": "cf fa ed fe"
        },
        {
          "offset": "0x1fc68",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "7a8aac687ea67207c19e1c74edb73e8a1a341a0fae0b75f2b434054922763f99",
      "sample_md5": "b5d80fd9330f57957e74d553247b054c",
      "sample_name": "7a8aac687ea67207c19e1c74edb73e8a1a341a0fae0b75f2b434054922763f99.macho",
      "sample_size_bytes": 198608,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-05 11:02:43",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "arm64",
          "machO",
          "macOS",
          "ProRAM",
          "RAT"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 15,
        "total_engines": 61,
        "detection_ratio": "15/61",
        "suggested_threat_label": "trojan.macho/multiverze",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 13
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "ekdpmzwmc.exe",
          "7a8aac687ea67207c19e1c74edb73e8a1a341a0fae0b75f2b434054922763f99.macho",
          "bftph4f.exe",
          "helper"
        ],
        "type_description": "Mach-O",
        "tags": [
          "self-signed",
          "macho",
          "64bits",
          "arm"
        ],
        "reputation": -52,
        "key_engine_detections": {
          "Microsoft": "Backdoor:MacOS/Multiverze!rfn",
          "ESET-NOD32": "OSX/Agent.II trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/7a8aac687ea67207c19e1c74edb73e8a1a341a0fae0b75f2b434054922763f99"
      },
      "detected_at": "2026-09-05T15:21:19.633365+00:00",
      "last_seen_at": "2026-10-20T18:52:09.961170+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_64_le",
          "data_preview": "cf fa ed fe"
        },
        {
          "offset": "0x42768",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "170515dc93120111760cc8c9e1deefb9a81939d123749d15f13ad5eca55042da",
      "sample_md5": "10239f4da7b43672422c4ae6877d66ef",
      "sample_name": "170515dc93120111760cc8c9e1deefb9a81939d123749d15f13ad5eca55042da.macho",
      "sample_size_bytes": 398376,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-05 13:48:25",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "arm64",
          "backdoor",
          "Coruna",
          "iOS",
          "machO",
          "PLASMAGRID"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 21,
        "total_engines": 61,
        "detection_ratio": "21/61",
        "suggested_threat_label": "trojan.coruna/falsesign",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 14
          },
          {
            "value": "downloader",
            "count": 1
          }
        ],
        "names": [
          "vwzhzgw.exe",
          "c62yq.exe",
          "64rgbmte.exe",
          "170515dc93120111760cc8c9e1deefb9a81939d123749d15f13ad5eca55042da.macho"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "arm",
          "lib",
          "ios",
          "64bits"
        ],
        "reputation": -52,
        "key_engine_detections": {
          "Microsoft": "Trojan:iPhoneOS/Multiverze!rfn",
          "ESET-NOD32": "iOS/Coruna.B trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/170515dc93120111760cc8c9e1deefb9a81939d123749d15f13ad5eca55042da"
      },
      "detected_at": "2026-09-05T20:36:41.047342+00:00",
      "last_seen_at": "2026-09-18T09:15:01.829625+00:00"
    },
    {
      "rule_name": "OSX_Foxveil_AMOS_Stage4_Generic",
      "platform": "macos",
      "namespace": "macos_stealer",
      "tags": [],
      "meta": {
        "description": "Generic detection for Foxveil macOS Loader (AMOS / Atomic macOS Stealer Stage 4) utilizing PBKDF2 key stretching, ChaCha20-Poly1305 payload encryption, LCG stack-string decryption, and memory zeroing wipers",
        "date": "2026-09-16",
        "reference": "https://bazaar.abuse.ch/sample/841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb/",
        "malware_family": "Foxveil / AMOS (Atomic macOS Stealer)",
        "threat_type": "Dropper / Loader / InfoStealer"
      },
      "matched_strings": [
        {
          "offset": "0x4221c",
          "identifier": "$id_pattern",
          "data_preview": "setup-6aa79328f6164e3659e037ecd971062e6f874279"
        },
        {
          "offset": "0x8c21c",
          "identifier": "$id_pattern",
          "data_preview": "setup-6aa79328f6164e3659e037ecd971062e6f874279"
        },
        {
          "offset": "0x4680",
          "identifier": "$mod_init_x86",
          "data_preview": "8b 3c 10 03 3c 08 89 3c 30 48 83 c0 04 48 3d 00 01 00 00 75"
        },
        {
          "offset": "0x46c0",
          "identifier": "$mod_init_x86",
          "data_preview": "8b 3c 10 03 3c 08 89 3c 30 48 83 c0 04 48 83 f8 20 75"
        },
        {
          "offset": "0x4868c",
          "identifier": "$mod_init_arm64",
          "data_preview": "2c 69 68 b8 4d 69 68 b8 ac 01 0c 0b 6c 69 28 b8 08 11 00 91 1f 01 04 f1 41 ff ff 54"
        },
        {
          "offset": "0x486c8",
          "identifier": "$mod_init_arm64",
          "data_preview": "2c 69 68 b8 4d 69 68 b8 ac 01 0c 0b 6c 69 28 b8 08 11 00 91 1f 81 00 f1 41 ff ff 54"
        },
        {
          "offset": "0x47cb",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 72 92 00 00"
        },
        {
          "offset": "0x4899",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 a4 91 00 00"
        },
        {
          "offset": "0x499c",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 a1 90 00 00"
        },
        {
          "offset": "0x4a87",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 b6 8f 00 00"
        },
        {
          "offset": "0x4c1c",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 21 8e 00 00"
        },
        {
          "offset": "0x4e5b",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 e2 8b 00 00"
        },
        {
          "offset": "0x4f49",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 f4 8a 00 00"
        },
        {
          "offset": "0x523b",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 02 88 00 00"
        },
        {
          "offset": "0x573f",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 fe 82 00 00"
        }
      ],
      "sample_sha256": "841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb",
      "sample_md5": "3d000465564399a53dfd52700c028fc7",
      "sample_name": "841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb.macho",
      "sample_size_bytes": 592688,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-15 09:23:27",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "chacha20-poly1305",
          "machO",
          "macOS",
          "universal-binary"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 33,
        "total_engines": 62,
        "detection_ratio": "33/62",
        "suggested_threat_label": "trojan.stealer/amos",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 19
          }
        ],
        "names": [
          "841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb.macho",
          "xnfzt5ma1.exe",
          "stage3.macho"
        ],
        "type_description": "Mach-O",
        "tags": [
          "self-signed",
          "macho",
          "arm",
          "64bits",
          "multi-arch"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bz",
          "Sophos": "OSX/Dropr-KC",
          "ESET-NOD32": "OSX/PSW.Agent.KB trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb"
      },
      "detected_at": "2026-09-16T10:24:15.725648+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Foxveil_AMOS_Stage4_Generic",
      "platform": "macos",
      "namespace": "macos_stealer",
      "tags": [],
      "meta": {
        "description": "Generic detection for Foxveil macOS Loader (AMOS / Atomic macOS Stealer Stage 4) utilizing PBKDF2 key stretching, ChaCha20-Poly1305 payload encryption, LCG stack-string decryption, and memory zeroing wipers",
        "date": "2026-09-16",
        "reference": "https://bazaar.abuse.ch/sample/841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb/",
        "malware_family": "Foxveil / AMOS (Atomic macOS Stealer)",
        "threat_type": "Dropper / Loader / InfoStealer"
      },
      "matched_strings": [
        {
          "offset": "0x4123c",
          "identifier": "$id_pattern",
          "data_preview": "setup-1c10085c457ec835258fc3538bc32604e5b372ae"
        },
        {
          "offset": "0x8c23c",
          "identifier": "$id_pattern",
          "data_preview": "setup-1c10085c457ec835258fc3538bc32604e5b372ae"
        },
        {
          "offset": "0x4690",
          "identifier": "$mod_init_x86",
          "data_preview": "8b 3c 10 03 3c 08 89 3c 30 48 83 c0 04 48 3d 00 01 00 00 75"
        },
        {
          "offset": "0x46d0",
          "identifier": "$mod_init_x86",
          "data_preview": "8b 3c 10 03 3c 08 89 3c 30 48 83 c0 04 48 83 f8 20 75"
        },
        {
          "offset": "0x4869c",
          "identifier": "$mod_init_arm64",
          "data_preview": "2c 69 68 b8 4d 69 68 b8 ac 01 0c 0b 6c 69 28 b8 08 11 00 91 1f 01 04 f1 41 ff ff 54"
        },
        {
          "offset": "0x486d8",
          "identifier": "$mod_init_arm64",
          "data_preview": "2c 69 68 b8 4d 69 68 b8 ac 01 0c 0b 6c 69 28 b8 08 11 00 91 1f 81 00 f1 41 ff ff 54"
        },
        {
          "offset": "0x47f4",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 86 94 00 00"
        },
        {
          "offset": "0x48dd",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 9d 93 00 00"
        },
        {
          "offset": "0x49fd",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 7d 92 00 00"
        },
        {
          "offset": "0x4b1d",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 5d 91 00 00"
        },
        {
          "offset": "0xa694",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 e6 35 00 00"
        },
        {
          "offset": "0xa795",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 e5 34 00 00"
        },
        {
          "offset": "0xb7d5",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 a5 24 00 00"
        },
        {
          "offset": "0xb8f9",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 81 23 00 00"
        },
        {
          "offset": "0xb9f6",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 84 22 00 00"
        }
      ],
      "sample_sha256": "a981fdba66721eb21e7a3c0ab18e487247bbcf97158737ab8c80e98f4ec240dd",
      "sample_md5": "6f37577cd7cf4b34fd9e7888c086692c",
      "sample_name": "a981fdba66721eb21e7a3c0ab18e487247bbcf97158737ab8c80e98f4ec240dd.macho",
      "sample_size_bytes": 592720,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-14 07:34:52",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 31,
        "total_engines": 63,
        "detection_ratio": "31/63",
        "suggested_threat_label": "trojan.stealer/dropr",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 18
          }
        ],
        "names": [
          "a981fdba66721eb21e7a3c0ab18e487247bbcf97158737ab8c80e98f4ec240dd.macho",
          "0gcvfq.exe",
          "chantfern11.com_macho.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "arm",
          "macho",
          "multi-arch",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bz",
          "Sophos": "OSX/Dropr-KC",
          "ESET-NOD32": "OSX/PSW.Agent.KB trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/a981fdba66721eb21e7a3c0ab18e487247bbcf97158737ab8c80e98f4ec240dd"
      },
      "detected_at": "2026-09-16T10:24:15.725648+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Foxveil_AMOS_Stage4_Generic",
      "platform": "macos",
      "namespace": "macos_stealer",
      "tags": [],
      "meta": {
        "description": "Generic detection for Foxveil macOS Loader (AMOS / Atomic macOS Stealer Stage 4) utilizing PBKDF2 key stretching, ChaCha20-Poly1305 payload encryption, LCG stack-string decryption, and memory zeroing wipers",
        "date": "2026-09-16",
        "reference": "https://bazaar.abuse.ch/sample/841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb/",
        "malware_family": "Foxveil / AMOS (Atomic macOS Stealer)",
        "threat_type": "Dropper / Loader / InfoStealer"
      },
      "matched_strings": [
        {
          "offset": "0x4429c",
          "identifier": "$id_pattern",
          "data_preview": "setup-f542247151f8ad62c7a9f86fe6aa339b90f4105e"
        },
        {
          "offset": "0x9028c",
          "identifier": "$id_pattern",
          "data_preview": "setup-f542247151f8ad62c7a9f86fe6aa339b90f4105e"
        },
        {
          "offset": "0x4c68c",
          "identifier": "$mod_init_arm64",
          "data_preview": "2c 69 68 b8 4d 69 68 b8 ac 01 0c 0b 6c 69 28 b8 08 11 00 91 1f 01 04 f1 41 ff ff 54"
        },
        {
          "offset": "0x491b",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 fd ce 00 00"
        },
        {
          "offset": "0x4a19",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 ff cd 00 00"
        },
        {
          "offset": "0x4b2d",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 eb cc 00 00"
        },
        {
          "offset": "0xc1bd",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 5b 56 00 00"
        },
        {
          "offset": "0xc2e3",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 35 55 00 00"
        },
        {
          "offset": "0xd28a",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 8e 45 00 00"
        },
        {
          "offset": "0xd3e1",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 37 44 00 00"
        },
        {
          "offset": "0xd528",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 f0 42 00 00"
        },
        {
          "offset": "0x4c854",
          "identifier": "$dlsym_call_arm64",
          "data_preview": "20 00 80 92 e7 2b 00 94"
        },
        {
          "offset": "0x4c934",
          "identifier": "$dlsym_call_arm64",
          "data_preview": "20 00 80 92 af 2b 00 94"
        },
        {
          "offset": "0x4ca1c",
          "identifier": "$dlsym_call_arm64",
          "data_preview": "20 00 80 92 75 2b 00 94"
        },
        {
          "offset": "0x4cb24",
          "identifier": "$dlsym_call_arm64",
          "data_preview": "20 00 80 92 33 2b 00 94"
        }
      ],
      "sample_sha256": "204b5d236e4384b23c1f0201bc52c06f32ef8eea679b975e9b432f2b111d1dbc",
      "sample_md5": "5f89411fe64c83e60a78a96a0d569bab",
      "sample_name": "204b5d236e4384b23c1f0201bc52c06f32ef8eea679b975e9b432f2b111d1dbc.macho",
      "sample_size_bytes": 609184,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-14 04:38:06",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 32,
        "total_engines": 63,
        "detection_ratio": "32/63",
        "suggested_threat_label": "trojan.dropr/multiverze",
        "popular_threat_category": [
          {
            "count": 18,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "jx8y2s5qi.exe",
          "204b5d236e4384b23c1f0201bc52c06f32ef8eea679b975e9b432f2b111d1dbc.macho",
          "malwarenoClick",
          "75aovy.exe",
          "ys3fczx96p"
        ],
        "type_description": "Mach-O",
        "tags": [
          "service-scan",
          "multi-arch",
          "64bits",
          "arm",
          "macho",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "Sophos": "OSX/Dropr-KC",
          "ESET-NOD32": "OSX/PSW.Agent.KB trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/204b5d236e4384b23c1f0201bc52c06f32ef8eea679b975e9b432f2b111d1dbc"
      },
      "detected_at": "2026-09-16T10:24:15.725648+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Foxveil_AMOS_Stage4_Generic",
      "platform": "macos",
      "namespace": "macos_stealer",
      "tags": [],
      "meta": {
        "description": "Generic detection for Foxveil macOS Loader (AMOS / Atomic macOS Stealer Stage 4) utilizing PBKDF2 key stretching, ChaCha20-Poly1305 payload encryption, LCG stack-string decryption, and memory zeroing wipers",
        "date": "2026-09-16",
        "reference": "https://bazaar.abuse.ch/sample/841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb/",
        "malware_family": "Foxveil / AMOS (Atomic macOS Stealer)",
        "threat_type": "Dropper / Loader / InfoStealer"
      },
      "matched_strings": [
        {
          "offset": "0x3e23c",
          "identifier": "$id_pattern",
          "data_preview": "setup-091057c2907806ded1cb53a31479c2ad4ee934a3"
        },
        {
          "offset": "0x8823c",
          "identifier": "$id_pattern",
          "data_preview": "setup-091057c2907806ded1cb53a31479c2ad4ee934a3"
        },
        {
          "offset": "0x4697",
          "identifier": "$mod_init_x86",
          "data_preview": "8b 3c 10 03 3c 08 89 3c 30 48 83 c0 04 48 3d 00 01 00 00 75"
        },
        {
          "offset": "0x46c4",
          "identifier": "$mod_init_x86",
          "data_preview": "8b 3c 10 03 3c 08 89 3c 30 48 83 c0 04 48 83 f8 20 75"
        },
        {
          "offset": "0x446ac",
          "identifier": "$mod_init_arm64",
          "data_preview": "2c 69 68 b8 4d 69 68 b8 ac 01 0c 0b 6c 69 28 b8 08 11 00 91 1f 01 04 f1 41 ff ff 54"
        },
        {
          "offset": "0x446e8",
          "identifier": "$mod_init_arm64",
          "data_preview": "2c 69 68 b8 4d 69 68 b8 ac 01 0c 0b 6c 69 28 b8 08 11 00 91 1f 81 00 f1 41 ff ff 54"
        },
        {
          "offset": "0x47c9",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 d2 6a 00 00"
        },
        {
          "offset": "0x48ad",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 ee 69 00 00"
        },
        {
          "offset": "0x499a",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 01 69 00 00"
        },
        {
          "offset": "0x4a7c",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 1f 68 00 00"
        },
        {
          "offset": "0x4c5c",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 3f 66 00 00"
        },
        {
          "offset": "0x4e3a",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 61 64 00 00"
        },
        {
          "offset": "0x4f34",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 67 63 00 00"
        },
        {
          "offset": "0x5161",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 3a 61 00 00"
        },
        {
          "offset": "0x54e5",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 b6 5d 00 00"
        }
      ],
      "sample_sha256": "708a0836a8c20e79f2ae522f097787326a90965e0532f3fd488d8d6e428f77b6",
      "sample_md5": "72d5aa3d8e51e1cf8e37e613c21c450b",
      "sample_name": "708a0836a8c20e79f2ae522f097787326a90965e0532f3fd488d8d6e428f77b6.macho",
      "sample_size_bytes": 576336,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-13 11:35:22",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "fake-cleaner",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 31,
        "total_engines": 63,
        "detection_ratio": "31/63",
        "suggested_threat_label": "trojan.stealer/dropr",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 18
          }
        ],
        "names": [
          "708a0836a8c20e79f2ae522f097787326a90965e0532f3fd488d8d6e428f77b6.macho",
          "uut6ic.exe",
          "ember-bridge_cleaner3_macho.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "arm",
          "self-signed",
          "64bits",
          "multi-arch"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bz",
          "Sophos": "OSX/Dropr-KC",
          "ESET-NOD32": "OSX/PSW.Agent.KB trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/708a0836a8c20e79f2ae522f097787326a90965e0532f3fd488d8d6e428f77b6"
      },
      "detected_at": "2026-09-16T10:24:15.725648+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Foxveil_AMOS_Stage4_Generic",
      "platform": "macos",
      "namespace": "macos_stealer",
      "tags": [],
      "meta": {
        "description": "Generic detection for Foxveil macOS Loader (AMOS / Atomic macOS Stealer Stage 4) utilizing PBKDF2 key stretching, ChaCha20-Poly1305 payload encryption, LCG stack-string decryption, and memory zeroing wipers",
        "date": "2026-09-16",
        "reference": "https://bazaar.abuse.ch/sample/841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb/",
        "malware_family": "Foxveil / AMOS (Atomic macOS Stealer)",
        "threat_type": "Dropper / Loader / InfoStealer"
      },
      "matched_strings": [
        {
          "offset": "0x412bc",
          "identifier": "$id_pattern",
          "data_preview": "setup-71dc1b40225fb288ffb32e79af9084f9d692394c"
        },
        {
          "offset": "0x8c2ac",
          "identifier": "$id_pattern",
          "data_preview": "setup-71dc1b40225fb288ffb32e79af9084f9d692394c"
        },
        {
          "offset": "0x4690",
          "identifier": "$mod_init_x86",
          "data_preview": "8b 3c 10 03 3c 08 89 3c 30 48 83 c0 04 48 3d 00 01 00 00 75"
        },
        {
          "offset": "0x46d0",
          "identifier": "$mod_init_x86",
          "data_preview": "8b 3c 10 03 3c 08 89 3c 30 48 83 c0 04 48 83 f8 20 75"
        },
        {
          "offset": "0x4869c",
          "identifier": "$mod_init_arm64",
          "data_preview": "2c 69 68 b8 4d 69 68 b8 ac 01 0c 0b 6c 69 28 b8 08 11 00 91 1f 01 04 f1 41 ff ff 54"
        },
        {
          "offset": "0x486d8",
          "identifier": "$mod_init_arm64",
          "data_preview": "2c 69 68 b8 4d 69 68 b8 ac 01 0c 0b 6c 69 28 b8 08 11 00 91 1f 81 00 f1 41 ff ff 54"
        },
        {
          "offset": "0x47d6",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 73 9c 00 00"
        },
        {
          "offset": "0x48d7",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 72 9b 00 00"
        },
        {
          "offset": "0x49ad",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 9c 9a 00 00"
        },
        {
          "offset": "0x4aab",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 9e 99 00 00"
        },
        {
          "offset": "0x4fd7",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 72 94 00 00"
        },
        {
          "offset": "0x523b",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 0e 92 00 00"
        },
        {
          "offset": "0x5349",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 00 91 00 00"
        },
        {
          "offset": "0x5654",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 f5 8d 00 00"
        },
        {
          "offset": "0x5ccd",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 7c 87 00 00"
        }
      ],
      "sample_sha256": "b3c05142afc6d7c708c55ba7a97dbb4272f43353205e8cab7b9a8117959cc270",
      "sample_md5": "537852ce16f716ac5f7b133fbf215e50",
      "sample_name": "b3c05142afc6d7c708c55ba7a97dbb4272f43353205e8cab7b9a8117959cc270.macho",
      "sample_size_bytes": 592832,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-13 11:35:18",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "fake-jetbrains",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 32,
        "total_engines": 63,
        "detection_ratio": "32/63",
        "suggested_threat_label": "trojan.stealer/dropr",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 18
          }
        ],
        "names": [
          "b3c05142afc6d7c708c55ba7a97dbb4272f43353205e8cab7b9a8117959cc270.macho",
          "5h8c8of5.exe",
          "quill-flint.com_macho.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "self-signed",
          "service-scan",
          "64bits",
          "macho",
          "multi-arch",
          "arm"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bz",
          "Sophos": "OSX/Dropr-KC",
          "ESET-NOD32": "OSX/PSW.Agent.KB trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/b3c05142afc6d7c708c55ba7a97dbb4272f43353205e8cab7b9a8117959cc270"
      },
      "detected_at": "2026-09-16T10:24:15.725648+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Foxveil_AMOS_Stage4_Generic",
      "platform": "macos",
      "namespace": "macos_stealer",
      "tags": [],
      "meta": {
        "description": "Generic detection for Foxveil macOS Loader (AMOS / Atomic macOS Stealer Stage 4) utilizing PBKDF2 key stretching, ChaCha20-Poly1305 payload encryption, LCG stack-string decryption, and memory zeroing wipers",
        "date": "2026-09-16",
        "reference": "https://bazaar.abuse.ch/sample/841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb/",
        "malware_family": "Foxveil / AMOS (Atomic macOS Stealer)",
        "threat_type": "Dropper / Loader / InfoStealer"
      },
      "matched_strings": [
        {
          "offset": "0x3f29c",
          "identifier": "$id_pattern",
          "data_preview": "setup-3fadee47c208f791843d69d07b03f8626299ffc5"
        },
        {
          "offset": "0x8c29c",
          "identifier": "$id_pattern",
          "data_preview": "setup-3fadee47c208f791843d69d07b03f8626299ffc5"
        },
        {
          "offset": "0x4677",
          "identifier": "$mod_init_x86",
          "data_preview": "8b 3c 10 03 3c 08 89 3c 30 48 83 c0 04 48 3d 00 01 00 00 75"
        },
        {
          "offset": "0x46a4",
          "identifier": "$mod_init_x86",
          "data_preview": "8b 3c 10 03 3c 08 89 3c 30 48 83 c0 04 48 83 f8 20 75"
        },
        {
          "offset": "0x4868c",
          "identifier": "$mod_init_arm64",
          "data_preview": "2c 69 68 b8 4d 69 68 b8 ac 01 0c 0b 6c 69 28 b8 08 11 00 91 1f 01 04 f1 41 ff ff 54"
        },
        {
          "offset": "0x486c8",
          "identifier": "$mod_init_arm64",
          "data_preview": "2c 69 68 b8 4d 69 68 b8 ac 01 0c 0b 6c 69 28 b8 08 11 00 91 1f 81 00 f1 41 ff ff 54"
        },
        {
          "offset": "0x4836",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 39 7d 00 00"
        },
        {
          "offset": "0x4924",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 4b 7c 00 00"
        },
        {
          "offset": "0x49ec",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 83 7b 00 00"
        },
        {
          "offset": "0x4bc1",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 ae 79 00 00"
        },
        {
          "offset": "0x4dab",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 c4 77 00 00"
        },
        {
          "offset": "0x4ec4",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 ab 76 00 00"
        },
        {
          "offset": "0x51d9",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 96 73 00 00"
        },
        {
          "offset": "0x557b",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 f4 6f 00 00"
        },
        {
          "offset": "0x56c5",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 aa 6e 00 00"
        }
      ],
      "sample_sha256": "beac3bae8f10cbb37ddde43f41dc44c0dd1c19e8e38723700e901751f6bd5072",
      "sample_md5": "d3bd04ac994cd674a906f5f1889ec707",
      "sample_name": "beac3bae8f10cbb37ddde43f41dc44c0dd1c19e8e38723700e901751f6bd5072.macho",
      "sample_size_bytes": 592816,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-13 11:35:14",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "fake-codex",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 32,
        "total_engines": 63,
        "detection_ratio": "32/63",
        "suggested_threat_label": "trojan.stealer/dropr",
        "popular_threat_category": [
          {
            "count": 18,
            "value": "trojan"
          }
        ],
        "names": [
          "beac3bae8f10cbb37ddde43f41dc44c0dd1c19e8e38723700e901751f6bd5072.macho",
          "z0lhdnzjd.exe",
          "plume-compass.com_macho.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "multi-arch",
          "64bits",
          "arm",
          "self-signed",
          "macho"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bz",
          "Sophos": "OSX/Dropr-KC",
          "ESET-NOD32": "OSX/PSW.Agent.KB trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/beac3bae8f10cbb37ddde43f41dc44c0dd1c19e8e38723700e901751f6bd5072"
      },
      "detected_at": "2026-09-16T10:24:15.725648+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Foxveil_AMOS_Stage4_Generic",
      "platform": "macos",
      "namespace": "macos_stealer",
      "tags": [],
      "meta": {
        "description": "Generic detection for Foxveil macOS Loader (AMOS / Atomic macOS Stealer Stage 4) utilizing PBKDF2 key stretching, ChaCha20-Poly1305 payload encryption, LCG stack-string decryption, and memory zeroing wipers",
        "date": "2026-09-16",
        "reference": "https://bazaar.abuse.ch/sample/841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb/",
        "malware_family": "Foxveil / AMOS (Atomic macOS Stealer)",
        "threat_type": "Dropper / Loader / InfoStealer"
      },
      "matched_strings": [
        {
          "offset": "0x422bc",
          "identifier": "$id_pattern",
          "data_preview": "setup-f34a44778f40a1fd9d72010887559c7145d3f053"
        },
        {
          "offset": "0x8c2ac",
          "identifier": "$id_pattern",
          "data_preview": "setup-f34a44778f40a1fd9d72010887559c7145d3f053"
        },
        {
          "offset": "0x4690",
          "identifier": "$mod_init_x86",
          "data_preview": "8b 3c 10 03 3c 08 89 3c 30 48 83 c0 04 48 3d 00 01 00 00 75"
        },
        {
          "offset": "0x46d0",
          "identifier": "$mod_init_x86",
          "data_preview": "8b 3c 10 03 3c 08 89 3c 30 48 83 c0 04 48 83 f8 20 75"
        },
        {
          "offset": "0x4869c",
          "identifier": "$mod_init_arm64",
          "data_preview": "2c 69 68 b8 4d 69 68 b8 ac 01 0c 0b 6c 69 28 b8 08 11 00 91 1f 01 04 f1 41 ff ff 54"
        },
        {
          "offset": "0x486d8",
          "identifier": "$mod_init_arm64",
          "data_preview": "2c 69 68 b8 4d 69 68 b8 ac 01 0c 0b 6c 69 28 b8 08 11 00 91 1f 81 00 f1 41 ff ff 54"
        },
        {
          "offset": "0x47fc",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 7c a1 00 00"
        },
        {
          "offset": "0x48ed",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 8b a0 00 00"
        },
        {
          "offset": "0x49f7",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 81 9f 00 00"
        },
        {
          "offset": "0x4adc",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 9c 9e 00 00"
        },
        {
          "offset": "0x5556",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 22 94 00 00"
        },
        {
          "offset": "0x573f",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 39 92 00 00"
        },
        {
          "offset": "0x583e",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 3a 91 00 00"
        },
        {
          "offset": "0x5b2c",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 4c 8e 00 00"
        },
        {
          "offset": "0x6091",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 e7 88 00 00"
        }
      ],
      "sample_sha256": "fd4896cf61b676a39918f119247f3f7c746b29645e732ab09b3318f8479da728",
      "sample_md5": "0548b39a45ac828e7a1f899401edbba1",
      "sample_name": "fd4896cf61b676a39918f119247f3f7c746b29645e732ab09b3318f8479da728.macho",
      "sample_size_bytes": 592832,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-13 11:35:09",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "fake-homebrew",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 33,
        "total_engines": 63,
        "detection_ratio": "33/63",
        "suggested_threat_label": "trojan.stealer/dropr",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 19
          }
        ],
        "names": [
          "fd4896cf61b676a39918f119247f3f7c746b29645e732ab09b3318f8479da728.macho",
          "miqwgq.exe",
          "weave44.com_macho.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "self-signed",
          "arm",
          "64bits",
          "macho",
          "multi-arch"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bz",
          "Sophos": "OSX/Dropr-KC",
          "ESET-NOD32": "OSX/PSW.Agent.KB trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/fd4896cf61b676a39918f119247f3f7c746b29645e732ab09b3318f8479da728"
      },
      "detected_at": "2026-09-16T10:24:15.725648+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Foxveil_AMOS_Stage4_Generic",
      "platform": "macos",
      "namespace": "macos_stealer",
      "tags": [],
      "meta": {
        "description": "Generic detection for Foxveil macOS Loader (AMOS / Atomic macOS Stealer Stage 4) utilizing PBKDF2 key stretching, ChaCha20-Poly1305 payload encryption, LCG stack-string decryption, and memory zeroing wipers",
        "date": "2026-09-16",
        "reference": "https://bazaar.abuse.ch/sample/841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb/",
        "malware_family": "Foxveil / AMOS (Atomic macOS Stealer)",
        "threat_type": "Dropper / Loader / InfoStealer"
      },
      "matched_strings": [
        {
          "offset": "0x243cc",
          "identifier": "$id_pattern",
          "data_preview": "setup-104c93da8932ce1d8b190e4bd668e0e73348ae54"
        },
        {
          "offset": "0x543bc",
          "identifier": "$id_pattern",
          "data_preview": "setup-104c93da8932ce1d8b190e4bd668e0e73348ae54"
        },
        {
          "offset": "0x4839",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 ae 7f 00 00"
        },
        {
          "offset": "0x490e",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 d9 7e 00 00"
        },
        {
          "offset": "0x4a08",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 df 7d 00 00"
        },
        {
          "offset": "0x4af2",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 f5 7c 00 00"
        },
        {
          "offset": "0x4d89",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 5e 7a 00 00"
        },
        {
          "offset": "0x4e72",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 75 79 00 00"
        },
        {
          "offset": "0x506e",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 79 77 00 00"
        },
        {
          "offset": "0x5351",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 96 74 00 00"
        },
        {
          "offset": "0x5511",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 d6 72 00 00"
        },
        {
          "offset": "0x5741",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 a6 70 00 00"
        },
        {
          "offset": "0x582c",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 bb 6f 00 00"
        },
        {
          "offset": "0x5a19",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 ce 6d 00 00"
        },
        {
          "offset": "0x5b1d",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 ca 6c 00 00"
        }
      ],
      "sample_sha256": "3e5097274c863873dfc79f315c39c30eb61e49e74db1bcee76bb372f584b9ff3",
      "sample_md5": "b6557144d308d03bbc72f76a9838d732",
      "sample_name": "3e5097274c863873dfc79f315c39c30eb61e49e74db1bcee76bb372f584b9ff3.macho",
      "sample_size_bytes": 363504,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-13 11:35:05",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "fake-homebrew",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 30,
        "total_engines": 61,
        "detection_ratio": "30/61",
        "suggested_threat_label": "trojan.amos/infostl",
        "popular_threat_category": [
          {
            "count": 19,
            "value": "trojan"
          }
        ],
        "names": [
          "3e5097274c863873dfc79f315c39c30eb61e49e74db1bcee76bb372f584b9ff3.macho",
          "g7vojvc.exe",
          "lyricblaze9.com_macho.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "multi-arch",
          "self-signed",
          "arm",
          "macho",
          "64bits"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bz",
          "Sophos": "OSX/InfoStl-HA",
          "ESET-NOD32": "OSX/PSW.Agent.JL trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/3e5097274c863873dfc79f315c39c30eb61e49e74db1bcee76bb372f584b9ff3"
      },
      "detected_at": "2026-09-16T10:24:15.725648+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Foxveil_AMOS_Stage4_Generic",
      "platform": "macos",
      "namespace": "macos_stealer",
      "tags": [],
      "meta": {
        "description": "Generic detection for Foxveil macOS Loader (AMOS / Atomic macOS Stealer Stage 4) utilizing PBKDF2 key stretching, ChaCha20-Poly1305 payload encryption, LCG stack-string decryption, and memory zeroing wipers",
        "date": "2026-09-16",
        "reference": "https://bazaar.abuse.ch/sample/841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb/",
        "malware_family": "Foxveil / AMOS (Atomic macOS Stealer)",
        "threat_type": "Dropper / Loader / InfoStealer"
      },
      "matched_strings": [
        {
          "offset": "0x243cc",
          "identifier": "$id_pattern",
          "data_preview": "setup-bd0aa41742b62c2c65ea337fad6946f52a21a585"
        },
        {
          "offset": "0x543bc",
          "identifier": "$id_pattern",
          "data_preview": "setup-bd0aa41742b62c2c65ea337fad6946f52a21a585"
        },
        {
          "offset": "0x484b",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 bb 7f 00 00"
        },
        {
          "offset": "0x493f",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 c7 7e 00 00"
        },
        {
          "offset": "0x4a54",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 b2 7d 00 00"
        },
        {
          "offset": "0x4b54",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 b2 7c 00 00"
        },
        {
          "offset": "0x528e",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 78 75 00 00"
        },
        {
          "offset": "0x5379",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 8d 74 00 00"
        },
        {
          "offset": "0x55df",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 27 72 00 00"
        },
        {
          "offset": "0x5a09",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 fd 6d 00 00"
        },
        {
          "offset": "0x5b01",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 05 6d 00 00"
        },
        {
          "offset": "0x5d23",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 e3 6a 00 00"
        },
        {
          "offset": "0x5dff",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 07 6a 00 00"
        },
        {
          "offset": "0x5ff1",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 15 68 00 00"
        },
        {
          "offset": "0x610a",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 fc 66 00 00"
        }
      ],
      "sample_sha256": "60362accd00f57e929f33799f43f6d9588f469577004eb05aba96bc21ca119ba",
      "sample_md5": "60537751c222c333e0316565f5cd0fdb",
      "sample_name": "60362accd00f57e929f33799f43f6d9588f469577004eb05aba96bc21ca119ba.macho",
      "sample_size_bytes": 363504,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-13 11:35:01",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "fake-homebrew",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 33,
        "total_engines": 63,
        "detection_ratio": "33/63",
        "suggested_threat_label": "trojan.amos/infostl",
        "popular_threat_category": [
          {
            "count": 20,
            "value": "trojan"
          }
        ],
        "names": [
          "60362accd00f57e929f33799f43f6d9588f469577004eb05aba96bc21ca119ba.macho",
          "0z2l2.exe",
          ".syu1dko",
          "r2_stage3.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "multi-arch",
          "service-scan",
          "self-signed",
          "macho",
          "64bits",
          "arm"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bz",
          "Sophos": "OSX/InfoStl-HA",
          "ESET-NOD32": "OSX/PSW.Agent.JL trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/60362accd00f57e929f33799f43f6d9588f469577004eb05aba96bc21ca119ba"
      },
      "detected_at": "2026-09-16T10:24:15.725648+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Foxveil_AMOS_Stage4_Generic",
      "platform": "macos",
      "namespace": "macos_stealer",
      "tags": [],
      "meta": {
        "description": "Generic detection for Foxveil macOS Loader (AMOS / Atomic macOS Stealer Stage 4) utilizing PBKDF2 key stretching, ChaCha20-Poly1305 payload encryption, LCG stack-string decryption, and memory zeroing wipers",
        "date": "2026-09-16",
        "reference": "https://bazaar.abuse.ch/sample/841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb/",
        "malware_family": "Foxveil / AMOS (Atomic macOS Stealer)",
        "threat_type": "Dropper / Loader / InfoStealer"
      },
      "matched_strings": [
        {
          "offset": "0x2636c",
          "identifier": "$id_pattern",
          "data_preview": "setup-a5d1f9d3ca841dd10a80f9f11b2e69fa10f32e25"
        },
        {
          "offset": "0x5435c",
          "identifier": "$id_pattern",
          "data_preview": "setup-a5d1f9d3ca841dd10a80f9f11b2e69fa10f32e25"
        },
        {
          "offset": "0x487b",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 47 a5 00 00"
        },
        {
          "offset": "0x493e",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 84 a4 00 00"
        },
        {
          "offset": "0x4a36",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 8c a3 00 00"
        },
        {
          "offset": "0x4b36",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 8c a2 00 00"
        },
        {
          "offset": "0xabdf",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 e3 41 00 00"
        },
        {
          "offset": "0xb8d1",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 f1 34 00 00"
        },
        {
          "offset": "0xb9a0",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 22 34 00 00"
        },
        {
          "offset": "0xbb0b",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 b7 32 00 00"
        },
        {
          "offset": "0x2c874",
          "identifier": "$dlsym_call_arm64",
          "data_preview": "20 00 80 92 e3 24 00 94"
        },
        {
          "offset": "0x2c928",
          "identifier": "$dlsym_call_arm64",
          "data_preview": "20 00 80 92 b6 24 00 94"
        },
        {
          "offset": "0x2ca14",
          "identifier": "$dlsym_call_arm64",
          "data_preview": "20 00 80 92 7b 24 00 94"
        },
        {
          "offset": "0x2cb08",
          "identifier": "$dlsym_call_arm64",
          "data_preview": "20 00 80 92 3e 24 00 94"
        },
        {
          "offset": "0x2d3b0",
          "identifier": "$dlsym_call_arm64",
          "data_preview": "20 00 80 92 14 22 00 94"
        }
      ],
      "sample_sha256": "76c2e4e7fb5290366d7bd04703ea60ec92d314ff651172387b9c6dbfca22b82a",
      "sample_md5": "a19b8d6e37d51b294a96bac703de24cb",
      "sample_name": "76c2e4e7fb5290366d7bd04703ea60ec92d314ff651172387b9c6dbfca22b82a.macho",
      "sample_size_bytes": 363408,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-13 11:34:57",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "fake-homebrew",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 30,
        "total_engines": 63,
        "detection_ratio": "30/63",
        "suggested_threat_label": "trojan.amos/stealer",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 18
          }
        ],
        "names": [
          "76c2e4e7fb5290366d7bd04703ea60ec92d314ff651172387b9c6dbfca22b82a.macho",
          "pio4wo.exe",
          "stage3.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "service-scan",
          "arm",
          "self-signed",
          "64bits",
          "multi-arch"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bx",
          "ESET-NOD32": "OSX/PSW.Agent.JL trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/76c2e4e7fb5290366d7bd04703ea60ec92d314ff651172387b9c6dbfca22b82a"
      },
      "detected_at": "2026-09-16T10:24:15.725648+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Foxveil_AMOS_Stage4_Generic",
      "platform": "macos",
      "namespace": "macos_stealer",
      "tags": [],
      "meta": {
        "description": "Generic detection for Foxveil macOS Loader (AMOS / Atomic macOS Stealer Stage 4) utilizing PBKDF2 key stretching, ChaCha20-Poly1305 payload encryption, LCG stack-string decryption, and memory zeroing wipers",
        "date": "2026-09-16",
        "reference": "https://bazaar.abuse.ch/sample/841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb/",
        "malware_family": "Foxveil / AMOS (Atomic macOS Stealer)",
        "threat_type": "Dropper / Loader / InfoStealer"
      },
      "matched_strings": [
        {
          "offset": "0x223cc",
          "identifier": "$id_pattern",
          "data_preview": "setup-82a8d5df0f36c6ea0fefd4c816ec8a8d55563b5f"
        },
        {
          "offset": "0x4c3bc",
          "identifier": "$id_pattern",
          "data_preview": "setup-82a8d5df0f36c6ea0fefd4c816ec8a8d55563b5f"
        },
        {
          "offset": "0x4814",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 24 62 00 00"
        },
        {
          "offset": "0x48c3",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 75 61 00 00"
        },
        {
          "offset": "0x49a7",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 91 60 00 00"
        },
        {
          "offset": "0x4a77",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 c1 5f 00 00"
        },
        {
          "offset": "0x4ea9",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 8f 5b 00 00"
        },
        {
          "offset": "0x4f70",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 c8 5a 00 00"
        },
        {
          "offset": "0x5148",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 f0 58 00 00"
        },
        {
          "offset": "0x54b5",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 83 55 00 00"
        },
        {
          "offset": "0x5627",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 11 54 00 00"
        },
        {
          "offset": "0x5805",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 33 52 00 00"
        },
        {
          "offset": "0x58bc",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 7c 51 00 00"
        },
        {
          "offset": "0x5aa1",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 97 4f 00 00"
        },
        {
          "offset": "0x5c99",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 9f 4d 00 00"
        }
      ],
      "sample_sha256": "b95ea805469383b5a419c5043de45bb2b13f36b3a513f98bd608b3f7294f064f",
      "sample_md5": "6311d6c827d5e1d932b6991380204f63",
      "sample_name": "b95ea805469383b5a419c5043de45bb2b13f36b3a513f98bd608b3f7294f064f.macho",
      "sample_size_bytes": 330704,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-09 14:51:03",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "machO",
          "macOS",
          "packed"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 32,
        "total_engines": 63,
        "detection_ratio": "32/63",
        "suggested_threat_label": "trojan.amos/amosstealer",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 19
          }
        ],
        "names": [
          "b95ea805469383b5a419c5043de45bb2b13f36b3a513f98bd608b3f7294f064f.macho",
          "tut07.exe",
          "helper.original"
        ],
        "type_description": "Mach-O",
        "tags": [
          "self-signed",
          "macho",
          "arm",
          "64bits",
          "multi-arch"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/AmosStealer.DC!MTB",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bz",
          "Sophos": "OSX/InfoStl-HA",
          "ESET-NOD32": "OSX/PSW.Agent.JL trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/b95ea805469383b5a419c5043de45bb2b13f36b3a513f98bd608b3f7294f064f"
      },
      "detected_at": "2026-09-16T10:24:15.725648+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Foxveil_AMOS_Stage4_Generic",
      "platform": "macos",
      "namespace": "macos_stealer",
      "tags": [],
      "meta": {
        "description": "Generic detection for Foxveil macOS Loader (AMOS / Atomic macOS Stealer Stage 4) utilizing PBKDF2 key stretching, ChaCha20-Poly1305 payload encryption, LCG stack-string decryption, and memory zeroing wipers",
        "date": "2026-09-16",
        "reference": "https://bazaar.abuse.ch/sample/841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb/",
        "malware_family": "Foxveil / AMOS (Atomic macOS Stealer)",
        "threat_type": "Dropper / Loader / InfoStealer"
      },
      "matched_strings": [
        {
          "offset": "0x2134c",
          "identifier": "$id_pattern",
          "data_preview": "setup-ccc431a174b8cc933fa2eb49ee3c49293864cc06"
        },
        {
          "offset": "0x4c34c",
          "identifier": "$id_pattern",
          "data_preview": "setup-ccc431a174b8cc933fa2eb49ee3c49293864cc06"
        },
        {
          "offset": "0x47ef",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 c0 58 00 00"
        },
        {
          "offset": "0x4898",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 17 58 00 00"
        },
        {
          "offset": "0x493c",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 73 57 00 00"
        },
        {
          "offset": "0x49d5",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 da 56 00 00"
        },
        {
          "offset": "0x4e0d",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 a2 52 00 00"
        },
        {
          "offset": "0x4ed0",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 df 51 00 00"
        },
        {
          "offset": "0x5099",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 16 50 00 00"
        },
        {
          "offset": "0x53c9",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 e6 4c 00 00"
        },
        {
          "offset": "0x5539",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 76 4b 00 00"
        },
        {
          "offset": "0x56ff",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 b0 49 00 00"
        },
        {
          "offset": "0x57a0",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 0f 49 00 00"
        },
        {
          "offset": "0x59e3",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 cc 46 00 00"
        },
        {
          "offset": "0x5ad2",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 dd 45 00 00"
        }
      ],
      "sample_sha256": "4903c40fbdb96cf39f35ed592a886a39d230564b26dd80aef3fa6c58bc501551",
      "sample_md5": "c062704203b38a7c4d6e21cd44082d86",
      "sample_name": "4903c40fbdb96cf39f35ed592a886a39d230564b26dd80aef3fa6c58bc501551.macho",
      "sample_size_bytes": 330592,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-09 14:50:57",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "machO",
          "macOS",
          "packed"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 32,
        "total_engines": 63,
        "detection_ratio": "32/63",
        "suggested_threat_label": "trojan.amos/amosstealer",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 20
          }
        ],
        "names": [
          "4903c40fbdb96cf39f35ed592a886a39d230564b26dd80aef3fa6c58bc501551.macho",
          "0lyypdd.exe",
          "stage4_buildA.macho"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "self-signed",
          "arm",
          "macho",
          "multi-arch"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/AmosStealer.DC!MTB",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bz",
          "Sophos": "OSX/InfoStl-HA",
          "ESET-NOD32": "OSX/PSW.Agent.JL trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/4903c40fbdb96cf39f35ed592a886a39d230564b26dd80aef3fa6c58bc501551"
      },
      "detected_at": "2026-09-16T10:24:15.725648+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "APT_macOS_RustBucket_Behavioral_Indicators",
      "platform": "macos",
      "namespace": "macos_rust_bucket",
      "tags": [],
      "meta": {
        "description": "Broad hunting rule for macOS RustBucket/Lazarus loaders and drop-and-execute variants",
        "date": "2026-09-18",
        "severity": "High",
        "malware_family": "RustBucket"
      },
      "matched_strings": [
        {
          "offset": "0x3d89",
          "identifier": "$ua_anom_01",
          "data_preview": "msie 8.0; windows nt 5.1"
        },
        {
          "offset": "0x3da3",
          "identifier": "$ua_anom_02",
          "data_preview": "trident/4.0"
        },
        {
          "offset": "0x3ebd",
          "identifier": "$task_sel_01",
          "data_preview": "setLaunchPath:"
        },
        {
          "offset": "0x3eda",
          "identifier": "$task_sel_02",
          "data_preview": "launchAndReturnError:"
        },
        {
          "offset": "0x3ecc",
          "identifier": "$task_sel_03",
          "data_preview": "setArguments:"
        },
        {
          "offset": "0x3ea5",
          "identifier": "$file_01",
          "data_preview": "temporaryDirectory"
        },
        {
          "offset": "0x3e96",
          "identifier": "$file_02",
          "data_preview": "defaultManager"
        },
        {
          "offset": "0xc40b",
          "identifier": "$file_03",
          "data_preview": "appendingPathComponent"
        },
        {
          "offset": "0xe003",
          "identifier": "$file_03",
          "data_preview": "appendingPathComponent"
        },
        {
          "offset": "0xcc5e",
          "identifier": "$wipe_01",
          "data_preview": "swift_stdlib_random"
        },
        {
          "offset": "0xe90f",
          "identifier": "$wipe_01",
          "data_preview": "swift_stdlib_random"
        },
        {
          "offset": "0xcc91",
          "identifier": "$wipe_02",
          "data_preview": "_unlink"
        },
        {
          "offset": "0xe934",
          "identifier": "$wipe_02",
          "data_preview": "_unlink"
        },
        {
          "offset": "0xc88b",
          "identifier": "$swift_cmd",
          "data_preview": "CommandLine"
        },
        {
          "offset": "0xe419",
          "identifier": "$swift_cmd",
          "data_preview": "CommandLine"
        }
      ],
      "sample_sha256": "9f54ca45b40d1893537bd1899d2343146364d7e3ddca0d51f5c4c0cf238ecae4",
      "sample_md5": "2f1fba8a22f0fcd737a209f8a1979bfe",
      "sample_name": "pd_arm64",
      "sample_size_bytes": 82944,
      "source_feed": "Local File",
      "detected_at": "2026-09-18T07:20:48.612365+00:00",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 28,
        "total_engines": 59,
        "detection_ratio": "28/59",
        "suggested_threat_label": "trojan.lazarus/nukesped",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 16
          },
          {
            "value": "downloader",
            "count": 7
          }
        ],
        "names": [
          "localfile~.arm64",
          "7887638bcafd57e2896c7c16698e927ce92fd7d409aae698d33cdca3ce8d25b8.cpu16777228"
        ],
        "type_description": "Mach-O",
        "tags": [
          "service-scan",
          "arm",
          "macho",
          "64bits",
          "self-signed",
          "signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Nukesped.H!MTB",
          "Kaspersky": "HEUR:Trojan-Downloader.OSX.Agent.gen",
          "Sophos": "OSX/RustBkt-A",
          "ESET-NOD32": "OSX/NukeSped.V trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/9f54ca45b40d1893537bd1899d2343146364d7e3ddca0d51f5c4c0cf238ecae4"
      },
      "last_seen_at": "2026-10-19T02:32:11.677388+00:00"
    },
    {
      "rule_name": "APT_macOS_RustBucket_Behavioral_Indicators",
      "platform": "macos",
      "namespace": "macos_rust_bucket",
      "tags": [],
      "meta": {
        "description": "Broad hunting rule for macOS RustBucket/Lazarus loaders and drop-and-execute variants",
        "date": "2026-09-18",
        "severity": "High",
        "malware_family": "RustBucket"
      },
      "matched_strings": [
        {
          "offset": "0x7d29",
          "identifier": "$ua_anom_01",
          "data_preview": "msie 8.0; windows nt 5.1"
        },
        {
          "offset": "0x1bd89",
          "identifier": "$ua_anom_01",
          "data_preview": "msie 8.0; windows nt 5.1"
        },
        {
          "offset": "0x7d43",
          "identifier": "$ua_anom_02",
          "data_preview": "trident/4.0"
        },
        {
          "offset": "0x1bda3",
          "identifier": "$ua_anom_02",
          "data_preview": "trident/4.0"
        },
        {
          "offset": "0x7ef8",
          "identifier": "$task_sel_01",
          "data_preview": "setLaunchPath:"
        },
        {
          "offset": "0x1bebd",
          "identifier": "$task_sel_01",
          "data_preview": "setLaunchPath:"
        },
        {
          "offset": "0x7f15",
          "identifier": "$task_sel_02",
          "data_preview": "launchAndReturnError:"
        },
        {
          "offset": "0x1beda",
          "identifier": "$task_sel_02",
          "data_preview": "launchAndReturnError:"
        },
        {
          "offset": "0x7f07",
          "identifier": "$task_sel_03",
          "data_preview": "setArguments:"
        },
        {
          "offset": "0x1becc",
          "identifier": "$task_sel_03",
          "data_preview": "setArguments:"
        },
        {
          "offset": "0x7ee0",
          "identifier": "$file_01",
          "data_preview": "temporaryDirectory"
        },
        {
          "offset": "0x1bea5",
          "identifier": "$file_01",
          "data_preview": "temporaryDirectory"
        },
        {
          "offset": "0x7ed1",
          "identifier": "$file_02",
          "data_preview": "defaultManager"
        },
        {
          "offset": "0x1be96",
          "identifier": "$file_02",
          "data_preview": "defaultManager"
        },
        {
          "offset": "0xc4a4",
          "identifier": "$file_03",
          "data_preview": "appendingPathComponent"
        }
      ],
      "sample_sha256": "7887638bcafd57e2896c7c16698e927ce92fd7d409aae698d33cdca3ce8d25b8",
      "sample_md5": "e169d95fffd8ab489f5eae02365d39ca",
      "sample_name": ".pd",
      "sample_size_bytes": 181248,
      "source_feed": "Local File",
      "detected_at": "2026-09-18T07:20:48.612365+00:00",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 33,
        "total_engines": 62,
        "detection_ratio": "33/62",
        "suggested_threat_label": "trojan.nukesped/lazarus",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 19
          },
          {
            "value": "downloader",
            "count": 7
          }
        ],
        "names": [
          "virus.pd"
        ],
        "type_description": "Mach-O",
        "tags": [
          "self-signed",
          "64bits",
          "macho",
          "multi-arch",
          "arm"
        ],
        "reputation": -35,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Nukesped!rfn",
          "Kaspersky": "HEUR:Trojan-Downloader.OSX.Agent.gen",
          "Sophos": "OSX/RustBkt-A",
          "ESET-NOD32": "OSX/NukeSped.V trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/7887638bcafd57e2896c7c16698e927ce92fd7d409aae698d33cdca3ce8d25b8"
      },
      "last_seen_at": "2026-10-19T02:32:11.677388+00:00"
    },
    {
      "rule_name": "APT_macOS_RustBucket_Behavioral_Indicators",
      "platform": "macos",
      "namespace": "macos_rust_bucket",
      "tags": [],
      "meta": {
        "description": "Broad hunting rule for macOS RustBucket/Lazarus loaders and drop-and-execute variants",
        "date": "2026-09-18",
        "severity": "High",
        "malware_family": "RustBucket"
      },
      "matched_strings": [
        {
          "offset": "0x3d29",
          "identifier": "$ua_anom_01",
          "data_preview": "msie 8.0; windows nt 5.1"
        },
        {
          "offset": "0x3d43",
          "identifier": "$ua_anom_02",
          "data_preview": "trident/4.0"
        },
        {
          "offset": "0x3ef8",
          "identifier": "$task_sel_01",
          "data_preview": "setLaunchPath:"
        },
        {
          "offset": "0x3f15",
          "identifier": "$task_sel_02",
          "data_preview": "launchAndReturnError:"
        },
        {
          "offset": "0x3f07",
          "identifier": "$task_sel_03",
          "data_preview": "setArguments:"
        },
        {
          "offset": "0x3ee0",
          "identifier": "$file_01",
          "data_preview": "temporaryDirectory"
        },
        {
          "offset": "0x3ed1",
          "identifier": "$file_02",
          "data_preview": "defaultManager"
        },
        {
          "offset": "0x84a4",
          "identifier": "$file_03",
          "data_preview": "appendingPathComponent"
        },
        {
          "offset": "0xab7b",
          "identifier": "$file_03",
          "data_preview": "appendingPathComponent"
        },
        {
          "offset": "0x8ede",
          "identifier": "$wipe_01",
          "data_preview": "swift_stdlib_random"
        },
        {
          "offset": "0xb5fd",
          "identifier": "$wipe_01",
          "data_preview": "swift_stdlib_random"
        },
        {
          "offset": "0x8f11",
          "identifier": "$wipe_02",
          "data_preview": "_unlink"
        },
        {
          "offset": "0xb622",
          "identifier": "$wipe_02",
          "data_preview": "_unlink"
        },
        {
          "offset": "0x892b",
          "identifier": "$swift_cmd",
          "data_preview": "CommandLine"
        },
        {
          "offset": "0xaf91",
          "identifier": "$swift_cmd",
          "data_preview": "CommandLine"
        }
      ],
      "sample_sha256": "3474d98ec917eac063525284c86585eb283f4188c7df2f31bf35c16f8787e81c",
      "sample_md5": "58a1140c0b22d7118ce9ff0649d87f19",
      "sample_name": "pd_x86",
      "sample_size_bytes": 72480,
      "source_feed": "Local File",
      "detected_at": "2026-09-18T07:20:48.612365+00:00",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 32,
        "total_engines": 63,
        "detection_ratio": "32/63",
        "suggested_threat_label": "trojan.nukesped/lazarus",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 19
          },
          {
            "value": "downloader",
            "count": 8
          }
        ],
        "names": [
          "localfile~.x64",
          "ppp.s",
          "7887638bcafd57e2896c7c16698e927ce92fd7d409aae698d33cdca3ce8d25b8.x64"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "64bits",
          "signed",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Nukesped.H!MTB",
          "Kaspersky": "HEUR:Trojan-Downloader.OSX.Agent.gen",
          "Sophos": "OSX/RustBkt-A",
          "ESET-NOD32": "OSX/NukeSped.V trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/3474d98ec917eac063525284c86585eb283f4188c7df2f31bf35c16f8787e81c"
      },
      "last_seen_at": "2026-10-19T02:32:11.677388+00:00"
    },
    {
      "rule_name": "OSX_Foxveil_AMOS_Stage4_Generic",
      "platform": "macos",
      "namespace": "macos_stealer",
      "tags": [],
      "meta": {
        "description": "Generic detection for Foxveil macOS Loader (AMOS / Atomic macOS Stealer Stage 4) utilizing PBKDF2 key stretching, ChaCha20-Poly1305 payload encryption, LCG stack-string decryption, and memory zeroing wipers",
        "date": "2026-09-16",
        "reference": "https://bazaar.abuse.ch/sample/841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb/",
        "malware_family": "Foxveil / AMOS (Atomic macOS Stealer)",
        "threat_type": "Dropper / Loader / InfoStealer"
      },
      "matched_strings": [
        {
          "offset": "0x567f4",
          "identifier": "$mod_init_arm64",
          "data_preview": "2a 69 68 b8 6b 6a 68 b8 6a 01 0a 0b 6a 6a 28 b8 08 11 00 91 1f 01 01 f1 41 ff ff 54"
        },
        {
          "offset": "0x1a561",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 d3 d9 00 00"
        },
        {
          "offset": "0x1eda4",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 90 91 00 00"
        },
        {
          "offset": "0x1ee92",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 a2 90 00 00"
        },
        {
          "offset": "0x4b068",
          "identifier": "$dlsym_call_arm64",
          "data_preview": "20 00 80 92 d9 57 00 94"
        },
        {
          "offset": "0x4b1ec",
          "identifier": "$dlsym_call_arm64",
          "data_preview": "20 00 80 92 78 57 00 94"
        },
        {
          "offset": "0x4b2dc",
          "identifier": "$dlsym_call_arm64",
          "data_preview": "20 00 80 92 3c 57 00 94"
        },
        {
          "offset": "0x4b488",
          "identifier": "$dlsym_call_arm64",
          "data_preview": "20 00 80 92 d1 56 00 94"
        },
        {
          "offset": "0x4b5f8",
          "identifier": "$dlsym_call_arm64",
          "data_preview": "20 00 80 92 75 56 00 94"
        },
        {
          "offset": "0x4b844",
          "identifier": "$dlsym_call_arm64",
          "data_preview": "20 00 80 92 e2 55 00 94"
        },
        {
          "offset": "0x4b9b0",
          "identifier": "$dlsym_call_arm64",
          "data_preview": "20 00 80 92 87 55 00 94"
        },
        {
          "offset": "0x4bbd8",
          "identifier": "$dlsym_call_arm64",
          "data_preview": "20 00 80 92 fd 54 00 94"
        },
        {
          "offset": "0x4bce8",
          "identifier": "$dlsym_call_arm64",
          "data_preview": "20 00 80 92 b9 54 00 94"
        },
        {
          "offset": "0x4c1b0",
          "identifier": "$dlsym_call_arm64",
          "data_preview": "20 00 80 92 87 53 00 94"
        },
        {
          "offset": "0x4c2fc",
          "identifier": "$dlsym_call_arm64",
          "data_preview": "20 00 80 92 34 53 00 94"
        }
      ],
      "sample_sha256": "a7c0d024ed24dcbc1b17cbda430a39edb52325c30ad9b7207c0267e43fbec4b7",
      "sample_md5": "9fde93ed3b267513a1f21509cda529fe",
      "sample_name": "a7c0d024ed24dcbc1b17cbda430a39edb52325c30ad9b7207c0267e43fbec4b7.macho",
      "sample_size_bytes": 502544,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-22 20:03:15",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 31,
        "total_engines": 63,
        "detection_ratio": "31/63",
        "suggested_threat_label": "trojan.amos/infostl",
        "popular_threat_category": [
          {
            "count": 18,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "saa9gwg.exe",
          "a7c0d024ed24dcbc1b17cbda430a39edb52325c30ad9b7207c0267e43fbec4b7.macho",
          "lykx48.exe",
          "q1wy6zkgp.exe",
          "macho_a7c0d024ed24.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "macho",
          "arm",
          "multi-arch",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "Sophos": "OSX/InfoStl-HF",
          "ESET-NOD32": "OSX/PSW.Agent.JH trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/a7c0d024ed24dcbc1b17cbda430a39edb52325c30ad9b7207c0267e43fbec4b7"
      },
      "detected_at": "2026-09-23T05:01:05.435807+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Foxveil_AMOS_Stage4_Generic",
      "platform": "macos",
      "namespace": "macos_stealer",
      "tags": [],
      "meta": {
        "description": "Generic detection for Foxveil macOS Loader (AMOS / Atomic macOS Stealer Stage 4) utilizing PBKDF2 key stretching, ChaCha20-Poly1305 payload encryption, LCG stack-string decryption, and memory zeroing wipers",
        "date": "2026-09-16",
        "reference": "https://bazaar.abuse.ch/sample/841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb/",
        "malware_family": "Foxveil / AMOS (Atomic macOS Stealer)",
        "threat_type": "Dropper / Loader / InfoStealer"
      },
      "matched_strings": [
        {
          "offset": "0x67c88",
          "identifier": "$mod_init_arm64",
          "data_preview": "2a 69 68 b8 6b 6a 68 b8 6a 01 0a 0b 6a 6a 28 b8 08 11 00 91 1f 01 01 f1 41 ff ff 54"
        },
        {
          "offset": "0x302b5",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 e5 ad 00 00"
        },
        {
          "offset": "0x3234a",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 50 8d 00 00"
        },
        {
          "offset": "0x32526",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 74 8b 00 00"
        },
        {
          "offset": "0x32712",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 88 89 00 00"
        },
        {
          "offset": "0x328df",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 bb 87 00 00"
        },
        {
          "offset": "0x32ab4",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 e6 85 00 00"
        },
        {
          "offset": "0x32c58",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 42 84 00 00"
        },
        {
          "offset": "0x32f4d",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 4d 81 00 00"
        },
        {
          "offset": "0x330ca",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 d0 7f 00 00"
        },
        {
          "offset": "0x34322",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 78 6d 00 00"
        },
        {
          "offset": "0x44ddc",
          "identifier": "$dlsym_call_arm64",
          "data_preview": "20 00 80 92 69 dc 00 94"
        },
        {
          "offset": "0x44ec8",
          "identifier": "$dlsym_call_arm64",
          "data_preview": "20 00 80 92 2e dc 00 94"
        },
        {
          "offset": "0x44fa4",
          "identifier": "$dlsym_call_arm64",
          "data_preview": "20 00 80 92 f7 db 00 94"
        },
        {
          "offset": "0x450b8",
          "identifier": "$dlsym_call_arm64",
          "data_preview": "20 00 80 92 b2 db 00 94"
        }
      ],
      "sample_sha256": "08074ec033c1a5dcfb0125a352f7f499f29f61d8ed2ce2f693d48813074810d4",
      "sample_md5": "cb27f99f797344e9fe6cd55d34f6bee5",
      "sample_name": "08074ec033c1a5dcfb0125a352f7f499f29f61d8ed2ce2f693d48813074810d4.macho",
      "sample_size_bytes": 570640,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-22 20:03:14",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 31,
        "total_engines": 63,
        "detection_ratio": "31/63",
        "suggested_threat_label": "trojan.infostl/multiverze",
        "popular_threat_category": [
          {
            "count": 18,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "lmetvn5.exe",
          "08074ec033c1a5dcfb0125a352f7f499f29f61d8ed2ce2f693d48813074810d4.macho",
          "or2vg984.exe",
          "macho_08074ec033c1.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "multi-arch",
          "macho",
          "self-signed",
          "64bits"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Agent.gen",
          "Sophos": "OSX/InfoStl-IR",
          "ESET-NOD32": "OSX/PSW.Agent.JM trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/08074ec033c1a5dcfb0125a352f7f499f29f61d8ed2ce2f693d48813074810d4"
      },
      "detected_at": "2026-09-23T05:01:05.435807+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Foxveil_AMOS_Stage4_Generic",
      "platform": "macos",
      "namespace": "macos_stealer",
      "tags": [],
      "meta": {
        "description": "Generic detection for Foxveil macOS Loader (AMOS / Atomic macOS Stealer Stage 4) utilizing PBKDF2 key stretching, ChaCha20-Poly1305 payload encryption, LCG stack-string decryption, and memory zeroing wipers",
        "date": "2026-09-16",
        "reference": "https://bazaar.abuse.ch/sample/841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb/",
        "malware_family": "Foxveil / AMOS (Atomic macOS Stealer)",
        "threat_type": "Dropper / Loader / InfoStealer"
      },
      "matched_strings": [
        {
          "offset": "0x1e41c",
          "identifier": "$id_pattern",
          "data_preview": "setup-55554944b320f5469db13eaaab284373f37ec9aa"
        },
        {
          "offset": "0x443fc",
          "identifier": "$id_pattern",
          "data_preview": "setup-55554944b320f5469db13eaaab284373f37ec9aa"
        },
        {
          "offset": "0x4c91",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 6a 53 00 00"
        },
        {
          "offset": "0x4d2b",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 d0 52 00 00"
        },
        {
          "offset": "0x4f03",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 f8 50 00 00"
        },
        {
          "offset": "0x5217",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 e4 4d 00 00"
        },
        {
          "offset": "0x52a0",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 5b 4d 00 00"
        },
        {
          "offset": "0x5481",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 7a 4b 00 00"
        },
        {
          "offset": "0x5510",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 eb 4a 00 00"
        },
        {
          "offset": "0x56df",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 1c 49 00 00"
        },
        {
          "offset": "0x57fd",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 fe 47 00 00"
        },
        {
          "offset": "0x58a2",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 59 47 00 00"
        },
        {
          "offset": "0x5924",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 d7 46 00 00"
        },
        {
          "offset": "0x59b0",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 4b 46 00 00"
        },
        {
          "offset": "0x8ba9",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 52 14 00 00"
        }
      ],
      "sample_sha256": "c48bd4f678a498b9173353d8fd400093541326e6b40a1a99c9a15fd28721ed69",
      "sample_md5": "cfbd77887c6ba5525f9651da652c558e",
      "sample_name": "c48bd4f678a498b9173353d8fd400093541326e6b40a1a99c9a15fd28721ed69.macho",
      "sample_size_bytes": 297968,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-08-09 15:22:53",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "AtomicStealer",
          "freshfix",
          "machO",
          "WaterDaruanak"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 30,
        "total_engines": 63,
        "detection_ratio": "30/63",
        "suggested_threat_label": "trojan.infostl/stealer",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 17
          }
        ],
        "names": [
          "atomicstealer_3",
          "c48bd4f678a498b9173353d8fd400093541326e6b40a1a99c9a15fd28721ed69.macho",
          "amos.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "self-signed",
          "64bits",
          "macho",
          "multi-arch",
          "arm"
        ],
        "reputation": -51,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/AmosStealer.DC!MTB",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Agent.ag",
          "Sophos": "OSX/InfoStl-HA",
          "ESET-NOD32": "OSX/PSW.Agent.JE trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/c48bd4f678a498b9173353d8fd400093541326e6b40a1a99c9a15fd28721ed69"
      },
      "detected_at": "2026-09-23T05:01:05.435807+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "OSX_Foxveil_AMOS_Stage4_Generic",
      "platform": "macos",
      "namespace": "macos_stealer",
      "tags": [],
      "meta": {
        "description": "Generic detection for Foxveil macOS Loader (AMOS / Atomic macOS Stealer Stage 4) utilizing PBKDF2 key stretching, ChaCha20-Poly1305 payload encryption, LCG stack-string decryption, and memory zeroing wipers",
        "date": "2026-09-16",
        "reference": "https://bazaar.abuse.ch/sample/841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb/",
        "malware_family": "Foxveil / AMOS (Atomic macOS Stealer)",
        "threat_type": "Dropper / Loader / InfoStealer"
      },
      "matched_strings": [
        {
          "offset": "0x232bc",
          "identifier": "$id_pattern",
          "data_preview": "setup-c2092ddbc1613230535a3658e01130955edcbf9f"
        },
        {
          "offset": "0x502ac",
          "identifier": "$id_pattern",
          "data_preview": "setup-c2092ddbc1613230535a3658e01130955edcbf9f"
        },
        {
          "offset": "0x4687",
          "identifier": "$mod_init_x86",
          "data_preview": "8b 3c 10 03 3c 08 89 3c 30 48 83 c0 04 48 3d 00 01 00 00 75"
        },
        {
          "offset": "0x46b4",
          "identifier": "$mod_init_x86",
          "data_preview": "8b 3c 10 03 3c 08 89 3c 30 48 83 c0 04 48 83 f8 20 75"
        },
        {
          "offset": "0x2869c",
          "identifier": "$mod_init_arm64",
          "data_preview": "2c 69 68 b8 4d 69 68 b8 ac 01 0c 0b 6c 69 28 b8 08 11 00 91 1f 01 04 f1 41 ff ff 54"
        },
        {
          "offset": "0x286d8",
          "identifier": "$mod_init_arm64",
          "data_preview": "2c 69 68 b8 4d 69 68 b8 ac 01 0c 0b 6c 69 28 b8 08 11 00 91 1f 81 00 f1 41 ff ff 54"
        },
        {
          "offset": "0x47c1",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 57 79 00 00"
        },
        {
          "offset": "0x48b4",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 64 78 00 00"
        },
        {
          "offset": "0x4995",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 83 77 00 00"
        },
        {
          "offset": "0x4a66",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 b2 76 00 00"
        },
        {
          "offset": "0x4c38",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 e0 74 00 00"
        },
        {
          "offset": "0x4e52",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 c6 72 00 00"
        },
        {
          "offset": "0x4f65",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 b3 71 00 00"
        },
        {
          "offset": "0x5287",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 91 6e 00 00"
        },
        {
          "offset": "0x5618",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 00 6b 00 00"
        }
      ],
      "sample_sha256": "3740e3883b64840461b3dfe2ce86695f32a14f28c8e0353c860ff6939a8c2538",
      "sample_md5": "9705d01e2370f9170178b848ff74528e",
      "sample_name": "3740e3883b64840461b3dfe2ce86695f32a14f28c8e0353c860ff6939a8c2538.macho",
      "sample_size_bytes": 346848,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-07 05:12:59",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "machO"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 30,
        "total_engines": 63,
        "detection_ratio": "30/63",
        "suggested_threat_label": "trojan.amos/amosstealer",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 18
          }
        ],
        "names": [
          "3740e3883b64840461b3dfe2ce86695f32a14f28c8e0353c860ff6939a8c2538.macho",
          "du125l6.exe",
          ".s4e8l7w5la"
        ],
        "type_description": "Mach-O",
        "tags": [
          "multi-arch",
          "64bits",
          "macho",
          "arm",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/AmosStealer.DC!MTB",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "Sophos": "OSX/Dropr-KC",
          "ESET-NOD32": "OSX/PSW.Agent.KB trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/3740e3883b64840461b3dfe2ce86695f32a14f28c8e0353c860ff6939a8c2538"
      },
      "detected_at": "2026-10-08T06:28:54.784186+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Foxveil_AMOS_Stage4_Generic",
      "platform": "macos",
      "namespace": "macos_stealer",
      "tags": [],
      "meta": {
        "description": "Generic detection for Foxveil macOS Loader (AMOS / Atomic macOS Stealer Stage 4) utilizing PBKDF2 key stretching, ChaCha20-Poly1305 payload encryption, LCG stack-string decryption, and memory zeroing wipers",
        "date": "2026-09-16",
        "reference": "https://bazaar.abuse.ch/sample/841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb/",
        "malware_family": "Foxveil / AMOS (Atomic macOS Stealer)",
        "threat_type": "Dropper / Loader / InfoStealer"
      },
      "matched_strings": [
        {
          "offset": "0x1f2bc",
          "identifier": "$id_pattern",
          "data_preview": "setup-c2092ddbc1613230535a3658e01130955edcbf9f"
        },
        {
          "offset": "0x687",
          "identifier": "$mod_init_x86",
          "data_preview": "8b 3c 10 03 3c 08 89 3c 30 48 83 c0 04 48 3d 00 01 00 00 75"
        },
        {
          "offset": "0x6b4",
          "identifier": "$mod_init_x86",
          "data_preview": "8b 3c 10 03 3c 08 89 3c 30 48 83 c0 04 48 83 f8 20 75"
        },
        {
          "offset": "0x7c1",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 57 79 00 00"
        },
        {
          "offset": "0x8b4",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 64 78 00 00"
        },
        {
          "offset": "0x995",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 83 77 00 00"
        },
        {
          "offset": "0xa66",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 b2 76 00 00"
        },
        {
          "offset": "0xc38",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 e0 74 00 00"
        },
        {
          "offset": "0xe52",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 c6 72 00 00"
        },
        {
          "offset": "0xf65",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 b3 71 00 00"
        },
        {
          "offset": "0x1287",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 91 6e 00 00"
        },
        {
          "offset": "0x1618",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 00 6b 00 00"
        },
        {
          "offset": "0x1757",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 c1 69 00 00"
        },
        {
          "offset": "0x1929",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 ef 67 00 00"
        },
        {
          "offset": "0x19ee",
          "identifier": "$dlsym_call_x86",
          "data_preview": "48 c7 c7 fe ff ff ff e8 2a 67 00 00"
        }
      ],
      "sample_sha256": "c4c7cc2f8e281b36d0bc29de6e08d354d83c4f734acaded25e7c8dfb1f580db5",
      "sample_md5": "7fe10e128dae844ed9f869bb94bef395",
      "sample_name": "c4c7cc2f8e281b36d0bc29de6e08d354d83c4f734acaded25e7c8dfb1f580db5.macho",
      "sample_size_bytes": 146832,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-07 05:12:39",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "machO"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 25,
        "total_engines": 63,
        "detection_ratio": "25/63",
        "suggested_threat_label": "trojan.amos/lummastealer",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 19
          }
        ],
        "names": [
          "localfile~.x64",
          "c4c7cc2f8e281b36d0bc29de6e08d354d83c4f734acaded25e7c8dfb1f580db5.macho",
          "u52ssm35.exe",
          "",
          "fontdrvhost.exe"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "64bits",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KB trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/c4c7cc2f8e281b36d0bc29de6e08d354d83c4f734acaded25e7c8dfb1f580db5"
      },
      "detected_at": "2026-10-08T06:28:54.784186+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "platform": "macos",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [
        {
          "offset": "0x54ffa",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x55017",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5508f",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadec9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadee6",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadef9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5500c",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0xadedb",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0x55632",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0xae44a",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0x99418",
          "identifier": "$op_arm64_dec",
          "data_preview": "4b 09 40 b3 6b 01 40 39 cc 02 0a 8b 8d 41 40 39 ab 01 0b 4a 8b 41 00 39 29 05 c9 93"
        },
        {
          "offset": "0x5b7ac",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x9948c",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99e80",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99f14",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        }
      ],
      "sample_sha256": "689797d97d31c3893e2c8a792614262f1fa9e714d646aef46bc4a6371fa59126",
      "sample_md5": "6afabe95ea16b5bce0a87994435913f8",
      "sample_name": "689797d97d31c3893e2c8a792614262f1fa9e714d646aef46bc4a6371fa59126.macho",
      "sample_size_bytes": 723072,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-02 15:42:24",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "adhoc-signed",
          "AMOS",
          "machO",
          "macOS",
          "stealer"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 35,
        "total_engines": 63,
        "detection_ratio": "35/63",
        "suggested_threat_label": "trojan.stealer/amos",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 20
          }
        ],
        "names": [
          "689797d97d31c3893e2c8a792614262f1fa9e714d646aef46bc4a6371fa59126.macho",
          "mk2faxcex.exe",
          "8jot5vdohds0imt4"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "self-delete",
          "self-signed",
          "multi-arch",
          "password-dialog",
          "macho",
          "arm",
          "checks-cpu-name"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/AmosStealer.DB!MTB",
          "SentinelOne": "Static AI - Malicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bg",
          "Sophos": "OSX/InfoStl-GW",
          "ESET-NOD32": "OSX/PSW.Agent.GF trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/689797d97d31c3893e2c8a792614262f1fa9e714d646aef46bc4a6371fa59126"
      },
      "detected_at": "2026-10-08T06:28:54.784186+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "Macho_Trojan_CloudSync_Generic",
      "platform": "macos",
      "namespace": "macos_cloud_sync",
      "tags": [],
      "meta": {
        "description": "Generic detection for CloudSync ",
        "date": "2026-10-06",
        "family": "CloudSync",
        "platform": "macOS"
      },
      "matched_strings": [
        {
          "offset": "0x2e8f0",
          "identifier": "$sobf_sbox",
          "data_preview": "d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51"
        },
        {
          "offset": "0x63b30",
          "identifier": "$sobf_sbox",
          "data_preview": "d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51"
        },
        {
          "offset": "0xbbbe0",
          "identifier": "$sobf_sbox",
          "data_preview": "d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51"
        },
        {
          "offset": "0x12ca58",
          "identifier": "$sobf_sbox",
          "data_preview": "d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51"
        },
        {
          "offset": "0x161c98",
          "identifier": "$sobf_sbox",
          "data_preview": "d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51"
        },
        {
          "offset": "0x1b9d48",
          "identifier": "$sobf_sbox",
          "data_preview": "d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51"
        },
        {
          "offset": "0x2097f",
          "identifier": "$sobf_code_x86",
          "data_preview": "41 6b c4 83 41 83 e4 1f"
        },
        {
          "offset": "0x46c0f",
          "identifier": "$sobf_code_x86",
          "data_preview": "41 6b c4 83 41 83 e4 1f"
        },
        {
          "offset": "0x144d77",
          "identifier": "$sobf_code_x86",
          "data_preview": "41 6b c4 83 41 83 e4 1f"
        },
        {
          "offset": "0xa01bc",
          "identifier": "$sobf_code_arm",
          "data_preview": "69 10 80 52 c9 7e 09 9b cb 12 40 92"
        },
        {
          "offset": "0x11f674",
          "identifier": "$sobf_code_arm",
          "data_preview": "69 10 80 52 c9 7e 09 9b cb 12 40 92"
        },
        {
          "offset": "0x19e324",
          "identifier": "$sobf_code_arm",
          "data_preview": "69 10 80 52 c9 7e 09 9b cb 12 40 92"
        },
        {
          "offset": "0x6e72a",
          "identifier": "$ns1",
          "data_preview": "cloudsync_impl"
        },
        {
          "offset": "0x6e767",
          "identifier": "$ns1",
          "data_preview": "cloudsync_impl"
        },
        {
          "offset": "0x6e7a3",
          "identifier": "$ns1",
          "data_preview": "cloudsync_impl"
        }
      ],
      "sample_sha256": "cc54d90920a73cc5e176664f61c6f601c95d693e431e79ae1148cb91e83c9235",
      "sample_md5": "b1f53a08784f2eb9ffb39ac77e1f4f51",
      "sample_name": "cc54d90920a73cc5e176664f61c6f601c95d693e431e79ae1148cb91e83c9235.macho",
      "sample_size_bytes": 2119088,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-30 10:36:44",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "macho"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 29,
        "total_engines": 62,
        "detection_ratio": "29/62",
        "suggested_threat_label": "trojan.cldsync/abtrojan",
        "popular_threat_category": [
          {
            "count": 17,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "hacktool"
          }
        ],
        "names": [
          "cc54d90920a73cc5e176664f61c6f601c95d693e431e79ae1148cb91e83c9235.macho",
          "11sfiq2zy.exe",
          "issrjw643.exe",
          "app_installer"
        ],
        "type_description": "Mach-O",
        "tags": [
          "multi-arch",
          "macho",
          "64bits",
          "dropper",
          "arm",
          "self-signed"
        ],
        "reputation": -2,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Backdoor.OSX.Agent.bs",
          "Sophos": "OSX/CldSync-A",
          "ESET-NOD32": "OSX/PSW.Agent.KO trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/cc54d90920a73cc5e176664f61c6f601c95d693e431e79ae1148cb91e83c9235"
      },
      "detected_at": "2026-10-08T06:28:54.784186+00:00",
      "last_seen_at": "2026-10-16T09:42:46.011654+00:00"
    },
    {
      "rule_name": "Macho_Trojan_CloudSync_Generic",
      "platform": "macos",
      "namespace": "macos_cloud_sync",
      "tags": [],
      "meta": {
        "description": "Generic detection for CloudSync ",
        "date": "2026-10-06",
        "family": "CloudSync",
        "platform": "macOS"
      },
      "matched_strings": [
        {
          "offset": "0x2db10",
          "identifier": "$sobf_sbox",
          "data_preview": "d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51"
        },
        {
          "offset": "0x62db0",
          "identifier": "$sobf_sbox",
          "data_preview": "d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51"
        },
        {
          "offset": "0xbae50",
          "identifier": "$sobf_sbox",
          "data_preview": "d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51"
        },
        {
          "offset": "0x12cc38",
          "identifier": "$sobf_sbox",
          "data_preview": "d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51"
        },
        {
          "offset": "0x161ed8",
          "identifier": "$sobf_sbox",
          "data_preview": "d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51"
        },
        {
          "offset": "0x1b9f78",
          "identifier": "$sobf_sbox",
          "data_preview": "d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51"
        },
        {
          "offset": "0x20f6f",
          "identifier": "$sobf_code_x86",
          "data_preview": "41 6b c4 83 41 83 e4 1f"
        },
        {
          "offset": "0x45e8f",
          "identifier": "$sobf_code_x86",
          "data_preview": "41 6b c4 83 41 83 e4 1f"
        },
        {
          "offset": "0x144fb7",
          "identifier": "$sobf_code_x86",
          "data_preview": "41 6b c4 83 41 83 e4 1f"
        },
        {
          "offset": "0x9f42c",
          "identifier": "$sobf_code_arm",
          "data_preview": "69 10 80 52 c9 7e 09 9b cb 12 40 92"
        },
        {
          "offset": "0x1209d8",
          "identifier": "$sobf_code_arm",
          "data_preview": "69 10 80 52 c9 7e 09 9b cb 12 40 92"
        },
        {
          "offset": "0x19e554",
          "identifier": "$sobf_code_arm",
          "data_preview": "69 10 80 52 c9 7e 09 9b cb 12 40 92"
        },
        {
          "offset": "0x6d99a",
          "identifier": "$ns1",
          "data_preview": "cloudsync_impl"
        },
        {
          "offset": "0x6d9d7",
          "identifier": "$ns1",
          "data_preview": "cloudsync_impl"
        },
        {
          "offset": "0x6da13",
          "identifier": "$ns1",
          "data_preview": "cloudsync_impl"
        }
      ],
      "sample_sha256": "524a7bcc8edcadc6f4381459f79769e1ec534aa78f66e5c38a6678bd55cf2572",
      "sample_md5": "0ea400ad00f00428dbf178ca9488c332",
      "sample_name": "524a7bcc8edcadc6f4381459f79769e1ec534aa78f66e5c38a6678bd55cf2572.macho",
      "sample_size_bytes": 2119024,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-30 10:36:14",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "macho"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 29,
        "total_engines": 62,
        "detection_ratio": "29/62",
        "suggested_threat_label": "trojan.cldsync/abtrojan",
        "popular_threat_category": [
          {
            "count": 18,
            "value": "trojan"
          }
        ],
        "names": [
          "524a7bcc8edcadc6f4381459f79769e1ec534aa78f66e5c38a6678bd55cf2572.macho",
          "ihrf2.exe",
          "9x6bbuhe6.exe",
          "app_installer"
        ],
        "type_description": "Mach-O",
        "tags": [
          "multi-arch",
          "self-delete",
          "macho",
          "arm",
          "dropper",
          "password-dialog",
          "64bits",
          "service-scan",
          "self-signed"
        ],
        "reputation": -1,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Backdoor.OSX.Agent.bs",
          "Sophos": "OSX/CldSync-A",
          "ESET-NOD32": "OSX/PSW.Agent.KO trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/524a7bcc8edcadc6f4381459f79769e1ec534aa78f66e5c38a6678bd55cf2572"
      },
      "detected_at": "2026-10-08T06:28:54.784186+00:00",
      "last_seen_at": "2026-10-16T09:42:46.011654+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x32638",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x707f8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "4504006d1911057be42435d4625f03d83c4d0b7b6898d14beb9cdeba6cf667b9",
      "sample_md5": "e634d35d6ae98935c51de5a23a92e965",
      "sample_name": "4504006d1911057be42435d4625f03d83c4d0b7b6898d14beb9cdeba6cf667b9.macho",
      "sample_size_bytes": 568368,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-28 17:13:38",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "macho"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 35,
        "total_engines": 63,
        "detection_ratio": "35/63",
        "suggested_threat_label": "trojan.amos/amosstealer",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 22
          }
        ],
        "names": [
          "4504006d1911057be42435d4625f03d83c4d0b7b6898d14beb9cdeba6cf667b9.macho",
          "dze6vw.exe",
          "mdworker_shared"
        ],
        "type_description": "Mach-O",
        "tags": [
          "multi-arch",
          "checks-cpu-name",
          "arm",
          "macho",
          "64bits",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Stealer.B!AMTB",
          "Kaspersky": "HEUR:Backdoor.OSX.Amos.f",
          "Sophos": "OSX/InfoStl-HF",
          "ESET-NOD32": "OSX/PSW.Agent.JH trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/4504006d1911057be42435d4625f03d83c4d0b7b6898d14beb9cdeba6cf667b9"
      },
      "detected_at": "2026-10-08T06:28:54.784186+00:00",
      "last_seen_at": "2026-10-16T09:42:46.011654+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x29558",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x5a064",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "6bfcdb4920383375b7e519918df7eb4db751b974b5571a15ce66b82478012620",
      "sample_md5": "3106cffb9da7380fcc0237e8fde0efa0",
      "sample_name": "6bfcdb4920383375b7e519918df7eb4db751b974b5571a15ce66b82478012620.macho",
      "sample_size_bytes": 438576,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-28 17:13:21",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "machO"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 34,
        "total_engines": 63,
        "detection_ratio": "34/63",
        "suggested_threat_label": "trojan.stealer/amos",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 20
          }
        ],
        "names": [
          "6bfcdb4920383375b7e519918df7eb4db751b974b5571a15ce66b82478012620.macho",
          "ssbkb.exe",
          "AccountsHelper"
        ],
        "type_description": "Mach-O",
        "tags": [
          "multi-arch",
          "arm",
          "self-signed",
          "64bits",
          "macho",
          "checks-cpu-name"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Stealer.B!AMTB",
          "Kaspersky": "HEUR:Backdoor.OSX.Amos.f",
          "Sophos": "OSX/InfoStl-HM",
          "ESET-NOD32": "OSX/PSW.Agent.IB trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/6bfcdb4920383375b7e519918df7eb4db751b974b5571a15ce66b82478012620"
      },
      "detected_at": "2026-10-08T06:28:54.784186+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "platform": "macos",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [
        {
          "offset": "0x54ffa",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x55017",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5508f",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadec9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadee6",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadef9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5500c",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0xadedb",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0x55632",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0xae44a",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0x99418",
          "identifier": "$op_arm64_dec",
          "data_preview": "4b 09 40 b3 6b 01 40 39 cc 02 0a 8b 8d 41 40 39 ab 01 0b 4a 8b 41 00 39 29 05 c9 93"
        },
        {
          "offset": "0x5b7ac",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x9948c",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99e80",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99f14",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        }
      ],
      "sample_sha256": "38c8c79ec773bfc700559243293f4b4409756d5adf63ad78a08d7ca2f38ee0dc",
      "sample_md5": "3192e96aa72ddee6802c4efd65882577",
      "sample_name": "38c8c79ec773bfc700559243293f4b4409756d5adf63ad78a08d7ca2f38ee0dc.macho",
      "sample_size_bytes": 723072,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-28 06:19:53",
        "file_type": "macho",
        "signature": null,
        "tags": null
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 35,
        "total_engines": 60,
        "detection_ratio": "35/60",
        "suggested_threat_label": "trojan.stealer/amos",
        "popular_threat_category": [
          {
            "count": 20,
            "value": "trojan"
          }
        ],
        "names": [
          "38c8c79ec773bfc700559243293f4b4409756d5adf63ad78a08d7ca2f38ee0dc.macho",
          "default",
          "ncorxz00.exe"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "self-signed",
          "64bits",
          "macho",
          "password-dialog",
          "checks-cpu-name",
          "multi-arch",
          "self-delete"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Win32/Malgent",
          "SentinelOne": "Static AI - Malicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bg",
          "Sophos": "OSX/InfoStl-GW",
          "ESET-NOD32": "OSX/PSW.Agent.GF trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/38c8c79ec773bfc700559243293f4b4409756d5adf63ad78a08d7ca2f38ee0dc"
      },
      "detected_at": "2026-10-08T06:28:54.784186+00:00",
      "last_seen_at": "2026-10-16T09:42:46.011654+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "platform": "macos",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [
        {
          "offset": "0x54ffa",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x55017",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5508f",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadec9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadee6",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadef9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5500c",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0xadedb",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0x55632",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0xae44a",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0x99418",
          "identifier": "$op_arm64_dec",
          "data_preview": "4b 09 40 b3 6b 01 40 39 cc 02 0a 8b 8d 41 40 39 ab 01 0b 4a 8b 41 00 39 29 05 c9 93"
        },
        {
          "offset": "0x5b7ac",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x9948c",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99e80",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99f14",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        }
      ],
      "sample_sha256": "63320c69b5733e125a587216bf2a93ac239c2a98686b2a1a00ec23f2b4177648",
      "sample_md5": "28e5a79fe13c85d0d26a2c5e8a0af30b",
      "sample_name": "63320c69b5733e125a587216bf2a93ac239c2a98686b2a1a00ec23f2b4177648.macho",
      "sample_size_bytes": 723072,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-28 06:19:51",
        "file_type": "macho",
        "signature": null,
        "tags": null
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 33,
        "total_engines": 60,
        "detection_ratio": "33/60",
        "suggested_threat_label": "trojan.stealer/amos",
        "popular_threat_category": [
          {
            "count": 19,
            "value": "trojan"
          }
        ],
        "names": [
          "63320c69b5733e125a587216bf2a93ac239c2a98686b2a1a00ec23f2b4177648.macho",
          "Toyeruj",
          "okpc73n.exe"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "64bits",
          "checks-cpu-name",
          "password-dialog",
          "self-signed",
          "arm",
          "self-delete",
          "multi-arch"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Win32/Malgent",
          "SentinelOne": "Static AI - Malicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bg",
          "Sophos": "OSX/InfoStl-GW",
          "ESET-NOD32": "OSX/PSW.Agent.GF trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/63320c69b5733e125a587216bf2a93ac239c2a98686b2a1a00ec23f2b4177648"
      },
      "detected_at": "2026-10-08T06:28:54.784186+00:00",
      "last_seen_at": "2026-10-16T09:42:46.011654+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "platform": "macos",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [
        {
          "offset": "0x54ffa",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x55017",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5508f",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadec9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadee6",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadef9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5500c",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0xadedb",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0x55632",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0xae44a",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0x99418",
          "identifier": "$op_arm64_dec",
          "data_preview": "4b 09 40 b3 6b 01 40 39 cc 02 0a 8b 8d 41 40 39 ab 01 0b 4a 8b 41 00 39 29 05 c9 93"
        },
        {
          "offset": "0x5b7ac",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x9948c",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99e80",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99f14",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        }
      ],
      "sample_sha256": "579fb6787dd60d5fb1ebfe275ccfa58e4b73db4cdc4909de23ac5dd3a9c52439",
      "sample_md5": "192247a08c3425d887d4e6fcec623259",
      "sample_name": "579fb6787dd60d5fb1ebfe275ccfa58e4b73db4cdc4909de23ac5dd3a9c52439.macho",
      "sample_size_bytes": 723072,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-28 06:19:48",
        "file_type": "macho",
        "signature": null,
        "tags": null
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 35,
        "total_engines": 61,
        "detection_ratio": "35/61",
        "suggested_threat_label": "trojan.stealer/amos",
        "popular_threat_category": [
          {
            "count": 19,
            "value": "trojan"
          }
        ],
        "names": [
          "579fb6787dd60d5fb1ebfe275ccfa58e4b73db4cdc4909de23ac5dd3a9c52439.macho",
          "Unconfirmed 252257.crdownload",
          "MLD",
          "3h253876t.exe"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "self-delete",
          "multi-arch",
          "checks-cpu-name",
          "arm",
          "64bits",
          "self-signed",
          "password-dialog"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Win32/Malgent",
          "SentinelOne": "Static AI - Malicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bg",
          "Sophos": "OSX/InfoStl-GW",
          "ESET-NOD32": "OSX/PSW.Agent.GF trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/579fb6787dd60d5fb1ebfe275ccfa58e4b73db4cdc4909de23ac5dd3a9c52439"
      },
      "detected_at": "2026-10-08T06:28:54.784186+00:00",
      "last_seen_at": "2026-10-16T09:42:46.011654+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "platform": "macos",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [
        {
          "offset": "0x54ffa",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x55017",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5508f",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadec9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadee6",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadef9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5500c",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0xadedb",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0x55632",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0xae44a",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0x99418",
          "identifier": "$op_arm64_dec",
          "data_preview": "4b 09 40 b3 6b 01 40 39 cc 02 0a 8b 8d 41 40 39 ab 01 0b 4a 8b 41 00 39 29 05 c9 93"
        },
        {
          "offset": "0x5b7ac",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x9948c",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99e80",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99f14",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        }
      ],
      "sample_sha256": "73491d3f3bcfe0c1d4ebefecf8230d0c460fa89703381d9b8923daaa4be170f4",
      "sample_md5": "be2aef8ec1e167c36bc7b9e96027c131",
      "sample_name": "73491d3f3bcfe0c1d4ebefecf8230d0c460fa89703381d9b8923daaa4be170f4.macho",
      "sample_size_bytes": 723072,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-28 06:19:48",
        "file_type": "macho",
        "signature": null,
        "tags": null
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 36,
        "total_engines": 63,
        "detection_ratio": "36/63",
        "suggested_threat_label": "trojan.stealer/amos",
        "popular_threat_category": [
          {
            "count": 20,
            "value": "trojan"
          }
        ],
        "names": [
          "73491d3f3bcfe0c1d4ebefecf8230d0c460fa89703381d9b8923daaa4be170f4.macho",
          "Cleaner",
          "6dv5zyo1.exe"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "arm",
          "self-delete",
          "service-scan",
          "self-signed",
          "multi-arch",
          "password-dialog",
          "macho",
          "checks-cpu-name"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Win32/Malgent",
          "SentinelOne": "Static AI - Malicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bg",
          "Sophos": "OSX/InfoStl-GW",
          "ESET-NOD32": "OSX/PSW.Agent.GF trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/73491d3f3bcfe0c1d4ebefecf8230d0c460fa89703381d9b8923daaa4be170f4"
      },
      "detected_at": "2026-10-08T06:28:54.784186+00:00",
      "last_seen_at": "2026-10-16T09:42:46.011654+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "platform": "macos",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [
        {
          "offset": "0x54ffa",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x55017",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5508f",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadec9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadee6",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadef9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5500c",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0xadedb",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0x55632",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0xae44a",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0x99418",
          "identifier": "$op_arm64_dec",
          "data_preview": "4b 09 40 b3 6b 01 40 39 cc 02 0a 8b 8d 41 40 39 ab 01 0b 4a 8b 41 00 39 29 05 c9 93"
        },
        {
          "offset": "0x5b7ac",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x9948c",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99e80",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99f14",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        }
      ],
      "sample_sha256": "0f5669e692760a1316a750622ecd871897d32da3486dd323f024d680543c368a",
      "sample_md5": "c349e853e926ae9479d22093c22d6e33",
      "sample_name": "0f5669e692760a1316a750622ecd871897d32da3486dd323f024d680543c368a.macho",
      "sample_size_bytes": 723072,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-28 06:19:47",
        "file_type": "macho",
        "signature": null,
        "tags": null
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 35,
        "total_engines": 62,
        "detection_ratio": "35/62",
        "suggested_threat_label": "trojan.stealer/amos",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 21
          }
        ],
        "names": [
          "0f5669e692760a1316a750622ecd871897d32da3486dd323f024d680543c368a.macho",
          "Lavagaluh",
          "2ose5.exe"
        ],
        "type_description": "Mach-O",
        "tags": [
          "checks-cpu-name",
          "64bits",
          "self-signed",
          "arm",
          "multi-arch",
          "password-dialog",
          "macho",
          "self-delete"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Win32/Malgent",
          "SentinelOne": "Static AI - Malicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bg",
          "Sophos": "OSX/InfoStl-GW",
          "ESET-NOD32": "OSX/PSW.Agent.GF trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/0f5669e692760a1316a750622ecd871897d32da3486dd323f024d680543c368a"
      },
      "detected_at": "2026-10-08T06:28:54.784186+00:00",
      "last_seen_at": "2026-10-16T09:42:46.011654+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "platform": "macos",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [
        {
          "offset": "0x54ffa",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x55017",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5508f",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadec9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadee6",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadef9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5500c",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0xadedb",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0x55632",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0xae44a",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0x99418",
          "identifier": "$op_arm64_dec",
          "data_preview": "4b 09 40 b3 6b 01 40 39 cc 02 0a 8b 8d 41 40 39 ab 01 0b 4a 8b 41 00 39 29 05 c9 93"
        },
        {
          "offset": "0x5b7ac",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x9948c",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99e80",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99f14",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        }
      ],
      "sample_sha256": "fd0cd32edfe9b4f68dcc2fddb8f27c6102e9a9c8b90c5def07ac8e62b2a75303",
      "sample_md5": "b6000eb45cc980f5fba975a5ccc9f909",
      "sample_name": "fd0cd32edfe9b4f68dcc2fddb8f27c6102e9a9c8b90c5def07ac8e62b2a75303.macho",
      "sample_size_bytes": 723072,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-27 03:29:14",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 35,
        "total_engines": 63,
        "detection_ratio": "35/63",
        "suggested_threat_label": "trojan.stealer/amos",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 19
          }
        ],
        "names": [
          "ujnyyodzjazt2491",
          "ujnyyodzjazt2491.exe",
          "fd0cd32edfe9b4f68dcc2fddb8f27c6102e9a9c8b90c5def07ac8e62b2a75303.macho",
          "ldf3qqow.exe",
          "macho_fd0cd32edfe9.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "multi-arch",
          "self-signed",
          "checks-vm",
          "os-credentials",
          "browser-creds",
          "self-delete",
          "password-dialog",
          "arm",
          "checks-cpu-name",
          "macho",
          "64bits"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Win32/Malgent",
          "SentinelOne": "Static AI - Malicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bg",
          "Sophos": "OSX/InfoStl-GW",
          "ESET-NOD32": "OSX/PSW.Agent.GF trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/fd0cd32edfe9b4f68dcc2fddb8f27c6102e9a9c8b90c5def07ac8e62b2a75303"
      },
      "detected_at": "2026-10-08T06:28:54.784186+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "Macho_Trojan_CloudSync_Generic",
      "platform": "macos",
      "namespace": "macos_cloud_sync",
      "tags": [],
      "meta": {
        "description": "Generic detection for CloudSync ",
        "date": "2026-10-06",
        "family": "CloudSync",
        "platform": "macOS"
      },
      "matched_strings": [
        {
          "offset": "0x9b93",
          "identifier": "$sobf_code_x86",
          "data_preview": "41 6b c4 83 41 83 e4 1f"
        },
        {
          "offset": "0x33d90",
          "identifier": "$sobf_code_arm",
          "data_preview": "69 10 80 52 c9 7e 09 9b cb 12 40 92"
        },
        {
          "offset": "0x2634a",
          "identifier": "$ns3",
          "data_preview": "_ct_APP_PROCESS_DISGUISE_NAME"
        },
        {
          "offset": "0x270ae",
          "identifier": "$ns3",
          "data_preview": "_ct_APP_PROCESS_DISGUISE_NAME"
        },
        {
          "offset": "0x29219",
          "identifier": "$ns3",
          "data_preview": "_ct_APP_PROCESS_DISGUISE_NAME"
        },
        {
          "offset": "0x592f7",
          "identifier": "$ns3",
          "data_preview": "_ct_APP_PROCESS_DISGUISE_NAME"
        },
        {
          "offset": "0x59b06",
          "identifier": "$ns3",
          "data_preview": "_ct_APP_PROCESS_DISGUISE_NAME"
        },
        {
          "offset": "0x5b6e1",
          "identifier": "$ns3",
          "data_preview": "_ct_APP_PROCESS_DISGUISE_NAME"
        },
        {
          "offset": "0x2623d",
          "identifier": "$ns4",
          "data_preview": "_ct_APP_INSTALL_DIR"
        },
        {
          "offset": "0x2701a",
          "identifier": "$ns4",
          "data_preview": "_ct_APP_INSTALL_DIR"
        },
        {
          "offset": "0x2910c",
          "identifier": "$ns4",
          "data_preview": "_ct_APP_INSTALL_DIR"
        },
        {
          "offset": "0x591ea",
          "identifier": "$ns4",
          "data_preview": "_ct_APP_INSTALL_DIR"
        },
        {
          "offset": "0x59a72",
          "identifier": "$ns4",
          "data_preview": "_ct_APP_INSTALL_DIR"
        },
        {
          "offset": "0x5b5d4",
          "identifier": "$ns4",
          "data_preview": "_ct_APP_INSTALL_DIR"
        },
        {
          "offset": "0x2620d",
          "identifier": "$ns5",
          "data_preview": "_ct_APP_OPS_URL"
        }
      ],
      "sample_sha256": "3220acfe8afe73c9beec11714cb95e324c56fe3386c5109fcd4cb5ba4873c3a5",
      "sample_md5": "b5779dfe16f84ecf7b60198ee65e1475",
      "sample_name": "3220acfe8afe73c9beec11714cb95e324c56fe3386c5109fcd4cb5ba4873c3a5.macho",
      "sample_size_bytes": 381320,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-25 20:07:47",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "macho"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 30,
        "total_engines": 63,
        "detection_ratio": "30/63",
        "suggested_threat_label": "trojan.cldsync/ravartar",
        "popular_threat_category": [
          {
            "count": 17,
            "value": "trojan"
          }
        ],
        "names": [
          "f44nl.exe",
          "0ceok5.exe",
          "c6ips.exe",
          "3220acfe8afe73c9beec11714cb95e324c56fe3386c5109fcd4cb5ba4873c3a5.macho",
          "wt1rlwd.exe"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "arm",
          "64bits",
          "multi-arch",
          "self-signed"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Trojan:Win32/Ravartar!rfn",
          "Sophos": "OSX/CldSync-A",
          "ESET-NOD32": "OSX/Agent.IK trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/3220acfe8afe73c9beec11714cb95e324c56fe3386c5109fcd4cb5ba4873c3a5"
      },
      "detected_at": "2026-10-08T06:28:54.784186+00:00",
      "last_seen_at": "2026-10-12T12:01:07.294646+00:00"
    },
    {
      "rule_name": "MALW_macOS_MacSync_Stealer_Universal",
      "platform": "macos",
      "namespace": "macos_MALW_macOS_MacSync_Stealer",
      "tags": [],
      "meta": {
        "description": "Universal multi-architecture detection for macOS MacSync Stealer (Intel x86_64 & Apple Silicon ARM64 / Universal Fat Binaries)",
        "date": "2026-08-31",
        "family": "MacSync",
        "threat_type": "Infostealer / Stager / Exfiltrator",
        "platform": "macOS (x86_64 & ARM64)"
      },
      "matched_strings": [
        {
          "offset": "0x833",
          "identifier": "$xor_archive",
          "data_preview": "/tmp/osalogging.zip"
        },
        {
          "offset": "0x7a2",
          "identifier": "$xor_osascript",
          "data_preview": "osascript"
        },
        {
          "offset": "0x7e4",
          "identifier": "$xor_osascript",
          "data_preview": "osascript"
        },
        {
          "offset": "0x761",
          "identifier": "$xor_curl",
          "data_preview": "curl -k -s"
        },
        {
          "offset": "0x7ac",
          "identifier": "$xor_curl",
          "data_preview": "curl -k -s"
        },
        {
          "offset": "0x788",
          "identifier": "$xor_dynamic",
          "data_preview": "/dynamic?txd="
        },
        {
          "offset": "0x7d2",
          "identifier": "$xor_dynamic",
          "data_preview": "/dynamic?txd="
        },
        {
          "offset": "0x20ce",
          "identifier": "$imp_freopen",
          "data_preview": "_freopen"
        },
        {
          "offset": "0x22b1",
          "identifier": "$imp_freopen",
          "data_preview": "_freopen"
        },
        {
          "offset": "0x20d7",
          "identifier": "$imp_setsid",
          "data_preview": "_setsid"
        },
        {
          "offset": "0x22ba",
          "identifier": "$imp_setsid",
          "data_preview": "_setsid"
        },
        {
          "offset": "0x20e9",
          "identifier": "$imp_system",
          "data_preview": "_system"
        },
        {
          "offset": "0x22cc",
          "identifier": "$imp_system",
          "data_preview": "_system"
        },
        {
          "offset": "0x20c8",
          "identifier": "$imp_fork",
          "data_preview": "_fork"
        },
        {
          "offset": "0x22ab",
          "identifier": "$imp_fork",
          "data_preview": "_fork"
        }
      ],
      "sample_sha256": "f80ff072316e2d62490df743cbd5363bfb6ec5459409cc162d0602f7a1c607bb",
      "sample_md5": "d79abf51b21fa607f2c463c309c144da",
      "sample_name": "f80ff072316e2d62490df743cbd5363bfb6ec5459409cc162d0602f7a1c607bb.macho",
      "sample_size_bytes": 8936,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-04-15 11:21:18",
        "file_type": "macho",
        "signature": "MacSync",
        "tags": [
          "machO",
          "MacSync",
          "MacSync-Stealer"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 32,
        "total_engines": 62,
        "detection_ratio": "32/62",
        "suggested_threat_label": "trojan.stealer/coins",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 12
          },
          {
            "value": "downloader",
            "count": 10
          }
        ],
        "names": [
          "localfile~.x64",
          "f80ff072316e2d62490df743cbd5363bfb6ec5459409cc162d0602f7a1c607bb.macho",
          "_f80ff072316e2d62490df743cbd5363bfb6ec5459409cc162d0602f7a1c607bb"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "64bits"
        ],
        "reputation": -59,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Stealer!AMTB",
          "SentinelOne": "Static AI - Suspicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Coins.b",
          "Sophos": "OSX/Dldr-XS",
          "ESET-NOD32": "OSX/PSW.Agent.EK trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/f80ff072316e2d62490df743cbd5363bfb6ec5459409cc162d0602f7a1c607bb"
      },
      "detected_at": "2026-10-08T06:28:54.784186+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "MALW_macOS_MacSync_Stealer_Universal",
      "platform": "macos",
      "namespace": "macos_MALW_macOS_MacSync_Stealer",
      "tags": [],
      "meta": {
        "description": "Universal multi-architecture detection for macOS MacSync Stealer (Intel x86_64 & Apple Silicon ARM64 / Universal Fat Binaries)",
        "date": "2026-08-31",
        "family": "MacSync",
        "threat_type": "Infostealer / Stager / Exfiltrator",
        "platform": "macOS (x86_64 & ARM64)"
      },
      "matched_strings": [
        {
          "offset": "0x1833",
          "identifier": "$xor_archive",
          "data_preview": "/tmp/osalogging.zip"
        },
        {
          "offset": "0x4826",
          "identifier": "$xor_archive",
          "data_preview": "/tmp/osalogging.zip"
        },
        {
          "offset": "0x17a2",
          "identifier": "$xor_osascript",
          "data_preview": "osascript"
        },
        {
          "offset": "0x17e4",
          "identifier": "$xor_osascript",
          "data_preview": "osascript"
        },
        {
          "offset": "0x4795",
          "identifier": "$xor_osascript",
          "data_preview": "osascript"
        },
        {
          "offset": "0x47d7",
          "identifier": "$xor_osascript",
          "data_preview": "osascript"
        },
        {
          "offset": "0x1761",
          "identifier": "$xor_curl",
          "data_preview": "curl -k -s"
        },
        {
          "offset": "0x17ac",
          "identifier": "$xor_curl",
          "data_preview": "curl -k -s"
        },
        {
          "offset": "0x4754",
          "identifier": "$xor_curl",
          "data_preview": "curl -k -s"
        },
        {
          "offset": "0x479f",
          "identifier": "$xor_curl",
          "data_preview": "curl -k -s"
        },
        {
          "offset": "0x1788",
          "identifier": "$xor_dynamic",
          "data_preview": "/dynamic?txd="
        },
        {
          "offset": "0x17d2",
          "identifier": "$xor_dynamic",
          "data_preview": "/dynamic?txd="
        },
        {
          "offset": "0x477b",
          "identifier": "$xor_dynamic",
          "data_preview": "/dynamic?txd="
        },
        {
          "offset": "0x47c5",
          "identifier": "$xor_dynamic",
          "data_preview": "/dynamic?txd="
        },
        {
          "offset": "0x30ce",
          "identifier": "$imp_freopen",
          "data_preview": "_freopen"
        }
      ],
      "sample_sha256": "f5471a00bb6cdaf01e44311c04de2e66c6f92ccc4b8e42bbb1bcb4e48f86ef3e",
      "sample_md5": "18c5bcbae0dc94147a15838fe8b4279c",
      "sample_name": "f5471a00bb6cdaf01e44311c04de2e66c6f92ccc4b8e42bbb1bcb4e48f86ef3e.macho",
      "sample_size_bytes": 50320,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-04-15 11:21:11",
        "file_type": "macho",
        "signature": "MacSync",
        "tags": [
          "machO",
          "MacSync",
          "MacSync-Stealer"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 33,
        "total_engines": 62,
        "detection_ratio": "33/62",
        "suggested_threat_label": "trojan.stealer/coins",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 19
          },
          {
            "value": "downloader",
            "count": 3
          }
        ],
        "names": [
          "f5471a00bb6cdaf01e44311c04de2e66c6f92ccc4b8e42bbb1bcb4e48f86ef3e.macho",
          "_f5471a00bb6cdaf01e44311c04de2e66c6f92ccc4b8e42bbb1bcb4e48f86ef3e",
          ".rc",
          "f83ef21e923d845e321bc9f0fff0427c65b9f2d13181bbd3b18318f6f1dccdf7"
        ],
        "type_description": "Mach-O",
        "tags": [
          "multi-arch",
          "64bits",
          "macho",
          "arm",
          "self-signed"
        ],
        "reputation": -59,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Stealer!AMTB",
          "SentinelOne": "Static AI - Malicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Coins.b",
          "Sophos": "OSX/Dldr-XS",
          "ESET-NOD32": "OSX/PSW.Agent.EK trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/f5471a00bb6cdaf01e44311c04de2e66c6f92ccc4b8e42bbb1bcb4e48f86ef3e"
      },
      "detected_at": "2026-10-08T06:28:54.784186+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "platform": "macos",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [
        {
          "offset": "0x54ffa",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x55017",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5508f",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadec9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadee6",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadef9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5500c",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0xadedb",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0x55632",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0xae44a",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0x99418",
          "identifier": "$op_arm64_dec",
          "data_preview": "4b 09 40 b3 6b 01 40 39 cc 02 0a 8b 8d 41 40 39 ab 01 0b 4a 8b 41 00 39 29 05 c9 93"
        },
        {
          "offset": "0x5b7ac",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x9948c",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99e80",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99f14",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        }
      ],
      "sample_sha256": "9135f4d24e45365b9680df64f6d0f51dba3a4ff7b740ca1cff3bc6b9998c474c",
      "sample_md5": "42bc18e69fed0270ad331caac75a896f",
      "sample_name": "9135f4d24e45365b9680df64f6d0f51dba3a4ff7b740ca1cff3bc6b9998c474c.macho",
      "sample_size_bytes": 723072,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-09 00:00:46",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "macho"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 31,
        "total_engines": 58,
        "detection_ratio": "31/58",
        "suggested_threat_label": "trojan.stealer/amos",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 19
          }
        ],
        "names": [
          "9135f4d24e45365b9680df64f6d0f51dba3a4ff7b740ca1cff3bc6b9998c474c.macho",
          "9nkzrkca.exe",
          "5i42segizmrmxlrq"
        ],
        "type_description": "Mach-O",
        "tags": [
          "checks-cpu-name",
          "arm",
          "self-signed",
          "macho",
          "self-delete",
          "password-dialog",
          "multi-arch",
          "64bits"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/AmosStealer.DB!MTB",
          "SentinelOne": "Static AI - Malicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bg",
          "Sophos": "OSX/InfoStl-GW",
          "ESET-NOD32": "OSX/PSW.Agent.GF trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/9135f4d24e45365b9680df64f6d0f51dba3a4ff7b740ca1cff3bc6b9998c474c"
      },
      "detected_at": "2026-10-09T09:35:31.947442+00:00",
      "last_seen_at": "2026-10-19T02:52:22.004609+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0xec9c8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0xd38c0",
          "identifier": "$chacha20_const",
          "data_preview": "expand 32-byte k"
        },
        {
          "offset": "0xd38d0",
          "identifier": "$chacha20_const",
          "data_preview": "expand 32-byte k"
        },
        {
          "offset": "0xec8e0",
          "identifier": "$chacha20_const",
          "data_preview": "expand 32-byte k"
        },
        {
          "offset": "0x1c7580",
          "identifier": "$chacha20_const",
          "data_preview": "expand 32-byte k"
        }
      ],
      "sample_sha256": "ddb7afd3e2d53100759643bb3b94b5cf011840d518d5553f33ae5c780af784e6",
      "sample_md5": "9a4c2d13b7fa04aaa55c701d15a0c357",
      "sample_name": "ddb7afd3e2d53100759643bb3b94b5cf011840d518d5553f33ae5c780af784e6.macho",
      "sample_size_bytes": 1927680,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-12 08:44:21",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "macho"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 21,
        "total_engines": 63,
        "detection_ratio": "21/63",
        "suggested_threat_label": "trojan.imnw/multiverze",
        "popular_threat_category": [
          {
            "count": 13,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "37bn2xxx.exe",
          "ddb7afd3e2d53100759643bb3b94b5cf011840d518d5553f33ae5c780af784e6.macho",
          "buuw9.exe",
          "0G7Xcm07FD8I"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "multi-arch",
          "64bits",
          "arm",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Backdoor.OSX.Agent.gen",
          "ESET-NOD32": "OSX/PSW.Agent.IY trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/ddb7afd3e2d53100759643bb3b94b5cf011840d518d5553f33ae5c780af784e6"
      },
      "detected_at": "2026-10-12T12:01:07.294646+00:00",
      "last_seen_at": "2026-10-19T21:33:01.399119+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x63b68",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x1481c0",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "c3b8375f092798ac851bfacdb94310ccabfebcbe106f6e7324764a0e4fd4ea57",
      "sample_md5": "f92f6f4b8dcd2e239dd4d262bfb25d65",
      "sample_name": "c3b8375f092798ac851bfacdb94310ccabfebcbe106f6e7324764a0e4fd4ea57.macho",
      "sample_size_bytes": 1857184,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-16 08:33:34",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 26,
        "total_engines": 63,
        "detection_ratio": "26/63",
        "suggested_threat_label": "trojan.amos/class",
        "popular_threat_category": [
          {
            "count": 19,
            "value": "trojan"
          }
        ],
        "names": [
          "5p9hip9lk.exe",
          "c3b8375f092798ac851bfacdb94310ccabfebcbe106f6e7324764a0e4fd4ea57.macho",
          "nfszn.exe",
          "macho_c3b8375f0927.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "multi-arch",
          "64bits",
          "self-signed",
          "macho"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/c3b8375f092798ac851bfacdb94310ccabfebcbe106f6e7324764a0e4fd4ea57"
      },
      "detected_at": "2026-10-16T09:33:37.569300+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x81198",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x1775e8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "faf572c1c989ca17101d5003bceb8b4796e709b93bf014f642b2a2c4b7b77fb4",
      "sample_md5": "63e5f42471c73f6ecd23a5caa82211ad",
      "sample_name": "faf572c1c989ca17101d5003bceb8b4796e709b93bf014f642b2a2c4b7b77fb4.macho",
      "sample_size_bytes": 2004080,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-16 07:36:09",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 27,
        "total_engines": 63,
        "detection_ratio": "27/63",
        "suggested_threat_label": "trojan.amos/class",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 20
          }
        ],
        "names": [
          "vloei91.exe",
          "faf572c1c989ca17101d5003bceb8b4796e709b93bf014f642b2a2c4b7b77fb4.macho",
          "u38sycfi.exe",
          "macho_faf572c1c989.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "multi-arch",
          "64bits",
          "self-signed",
          "macho",
          "arm"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/faf572c1c989ca17101d5003bceb8b4796e709b93bf014f642b2a2c4b7b77fb4"
      },
      "detected_at": "2026-10-16T09:33:37.569300+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x80068",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x173e2c",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "1e8ed19e771e7a9378daf3b3652802143345db8ea4196e560e54f28176ef958a",
      "sample_md5": "ed4a6db0e93b62fbb2a65d7b35e2eb87",
      "sample_name": "1e8ed19e771e7a9378daf3b3652802143345db8ea4196e560e54f28176ef958a.macho",
      "sample_size_bytes": 2003632,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-16 00:45:10",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 26,
        "total_engines": 63,
        "detection_ratio": "26/63",
        "suggested_threat_label": "trojan.amos/class",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 19
          }
        ],
        "names": [
          "4tjket27w.exe",
          "1e8ed19e771e7a9378daf3b3652802143345db8ea4196e560e54f28176ef958a.macho",
          "ekjj3p.exe",
          "macho_1e8ed19e771e.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "64bits",
          "self-signed",
          "arm",
          "multi-arch"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.C!ml",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/1e8ed19e771e7a9378daf3b3652802143345db8ea4196e560e54f28176ef958a"
      },
      "detected_at": "2026-10-16T09:33:37.569300+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x603f8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x13b7e8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "e42b8c35db5ab7169327b9185c3e05db4a156e8922b985da61bcbd6223df8aea",
      "sample_md5": "2324461d27387a0b7563be0b8cec055d",
      "sample_name": "e42b8c35db5ab7169327b9185c3e05db4a156e8922b985da61bcbd6223df8aea.macho",
      "sample_size_bytes": 1808272,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-16 00:34:53",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 26,
        "total_engines": 63,
        "detection_ratio": "26/63",
        "suggested_threat_label": "trojan.amos/class",
        "popular_threat_category": [
          {
            "count": 19,
            "value": "trojan"
          }
        ],
        "names": [
          "sxnfoais.exe",
          "e42b8c35db5ab7169327b9185c3e05db4a156e8922b985da61bcbd6223df8aea.macho",
          "nmli7d4.exe",
          "macho_e42b8c35db5a.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "64bits",
          "macho",
          "multi-arch",
          "self-signed"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.C!ml",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/e42b8c35db5ab7169327b9185c3e05db4a156e8922b985da61bcbd6223df8aea"
      },
      "detected_at": "2026-10-16T09:33:37.569300+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0xec8f8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0xd3900",
          "identifier": "$chacha20_const",
          "data_preview": "expand 32-byte k"
        },
        {
          "offset": "0xd3910",
          "identifier": "$chacha20_const",
          "data_preview": "expand 32-byte k"
        },
        {
          "offset": "0xec810",
          "identifier": "$chacha20_const",
          "data_preview": "expand 32-byte k"
        },
        {
          "offset": "0x1cb580",
          "identifier": "$chacha20_const",
          "data_preview": "expand 32-byte k"
        }
      ],
      "sample_sha256": "5b2531253b7fd1a18516dd937ad2e0ca3093b3b2f058b1a173fc65b037b37493",
      "sample_md5": "c9815743bddc0c9621cafe88c0b9d415",
      "sample_name": "5b2531253b7fd1a18516dd937ad2e0ca3093b3b2f058b1a173fc65b037b37493.macho",
      "sample_size_bytes": 1945088,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-13 18:40:15",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "AmnesiaStealer",
          "ClickFix",
          "lunomac-com",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 8,
        "total_engines": 58,
        "detection_ratio": "8/58",
        "suggested_threat_label": "trojan.gajl/multiverze",
        "popular_threat_category": [
          {
            "count": 8,
            "value": "trojan"
          }
        ],
        "names": [
          "5b2531253b7fd1a18516dd937ad2e0ca3093b3b2f058b1a173fc65b037b37493.macho",
          "macho_5b2531253b7f.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "multi-arch",
          "os-credentials",
          "macho",
          "self-signed",
          "64bits"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Backdoor.OSX.Agent.bt",
          "ESET-NOD32": "OSX/PSW.Agent.IY trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/5b2531253b7fd1a18516dd937ad2e0ca3093b3b2f058b1a173fc65b037b37493"
      },
      "detected_at": "2026-10-16T09:42:46.011654+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "platform": "macos",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [
        {
          "offset": "0x54ffa",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x55017",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5508f",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadec9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadee6",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadef9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5500c",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0xadedb",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0x55632",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0xae44a",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0x99418",
          "identifier": "$op_arm64_dec",
          "data_preview": "4b 09 40 b3 6b 01 40 39 cc 02 0a 8b 8d 41 40 39 ab 01 0b 4a 8b 41 00 39 29 05 c9 93"
        },
        {
          "offset": "0x5b7ac",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x9948c",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99e80",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99f14",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        }
      ],
      "sample_sha256": "4799b1f41221745e4e3e902526b9635e697b64c5c07a344b59fe1a6ddc018c34",
      "sample_md5": "ccd7e6c5470caeb40eb3979567f1da63",
      "sample_name": "4799b1f41221745e4e3e902526b9635e697b64c5c07a344b59fe1a6ddc018c34.macho",
      "sample_size_bytes": 723072,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-12 17:44:26",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Mach-O",
          "machO",
          "macOS",
          "stealer"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 35,
        "total_engines": 63,
        "detection_ratio": "35/63",
        "suggested_threat_label": "trojan.stealer/amos",
        "popular_threat_category": [
          {
            "count": 20,
            "value": "trojan"
          }
        ],
        "names": [
          "4799b1f41221745e4e3e902526b9635e697b64c5c07a344b59fe1a6ddc018c34.macho",
          "Tucoyodel",
          "146.103.101.229_sample.bin",
          "qqvnh36.exe"
        ],
        "type_description": "Mach-O",
        "tags": [
          "multi-arch",
          "64bits",
          "macho",
          "service-scan",
          "self-signed",
          "arm"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/AmosStealer.DB!MTB",
          "SentinelOne": "Static AI - Malicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bg",
          "Sophos": "OSX/InfoStl-GW",
          "ESET-NOD32": "OSX/PSW.Agent.GF trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/4799b1f41221745e4e3e902526b9635e697b64c5c07a344b59fe1a6ddc018c34"
      },
      "detected_at": "2026-10-16T09:42:46.011654+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "Macho_Trojan_CloudSync_1006YR",
      "platform": "macos",
      "namespace": "macos_stealer",
      "tags": [],
      "meta": {
        "silent": 1,
        "author": "Chandra Kant Bauri",
        "description": "Generic detection for CloudSync ",
        "date": "2026-10-06",
        "family": "CloudSync",
        "platform": "macOS"
      },
      "matched_strings": [
        {
          "offset": "0x2e8f0",
          "identifier": "$sobf_sbox",
          "data_preview": "d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51"
        },
        {
          "offset": "0x63b30",
          "identifier": "$sobf_sbox",
          "data_preview": "d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51"
        },
        {
          "offset": "0xbbbe0",
          "identifier": "$sobf_sbox",
          "data_preview": "d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51"
        },
        {
          "offset": "0x12ca58",
          "identifier": "$sobf_sbox",
          "data_preview": "d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51"
        },
        {
          "offset": "0x161c98",
          "identifier": "$sobf_sbox",
          "data_preview": "d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51"
        },
        {
          "offset": "0x1b9d48",
          "identifier": "$sobf_sbox",
          "data_preview": "d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51"
        },
        {
          "offset": "0x2097f",
          "identifier": "$sobf_code_x86",
          "data_preview": "41 6b c4 83 41 83 e4 1f"
        },
        {
          "offset": "0x46c0f",
          "identifier": "$sobf_code_x86",
          "data_preview": "41 6b c4 83 41 83 e4 1f"
        },
        {
          "offset": "0x144d77",
          "identifier": "$sobf_code_x86",
          "data_preview": "41 6b c4 83 41 83 e4 1f"
        },
        {
          "offset": "0xa01bc",
          "identifier": "$sobf_code_arm",
          "data_preview": "69 10 80 52 c9 7e 09 9b cb 12 40 92"
        },
        {
          "offset": "0x11f674",
          "identifier": "$sobf_code_arm",
          "data_preview": "69 10 80 52 c9 7e 09 9b cb 12 40 92"
        },
        {
          "offset": "0x19e324",
          "identifier": "$sobf_code_arm",
          "data_preview": "69 10 80 52 c9 7e 09 9b cb 12 40 92"
        },
        {
          "offset": "0x6e72a",
          "identifier": "$ns1",
          "data_preview": "cloudsync_impl"
        },
        {
          "offset": "0x6e767",
          "identifier": "$ns1",
          "data_preview": "cloudsync_impl"
        },
        {
          "offset": "0x6e7a3",
          "identifier": "$ns1",
          "data_preview": "cloudsync_impl"
        }
      ],
      "sample_sha256": "cc54d90920a73cc5e176664f61c6f601c95d693e431e79ae1148cb91e83c9235",
      "sample_md5": "b1f53a08784f2eb9ffb39ac77e1f4f51",
      "sample_name": "cc54d90920a73cc5e176664f61c6f601c95d693e431e79ae1148cb91e83c9235.macho",
      "sample_size_bytes": 2119088,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-30 10:36:44",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "macho"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 29,
        "total_engines": 62,
        "detection_ratio": "29/62",
        "suggested_threat_label": "trojan.cldsync/abtrojan",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 17
          },
          {
            "value": "hacktool",
            "count": 1
          }
        ],
        "names": [
          "cc54d90920a73cc5e176664f61c6f601c95d693e431e79ae1148cb91e83c9235.macho",
          "11sfiq2zy.exe",
          "issrjw643.exe",
          "app_installer"
        ],
        "type_description": "Mach-O",
        "tags": [
          "multi-arch",
          "macho",
          "64bits",
          "dropper",
          "arm",
          "self-signed"
        ],
        "reputation": -2,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Backdoor.OSX.Agent.bs",
          "Sophos": "OSX/CldSync-A",
          "ESET-NOD32": "OSX/PSW.Agent.KO trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/cc54d90920a73cc5e176664f61c6f601c95d693e431e79ae1148cb91e83c9235"
      },
      "detected_at": "2026-10-16T09:42:46.011654+00:00"
    },
    {
      "rule_name": "Macho_Trojan_CloudSync_1006YR",
      "platform": "macos",
      "namespace": "macos_stealer",
      "tags": [],
      "meta": {
        "silent": 1,
        "author": "Chandra Kant Bauri",
        "description": "Generic detection for CloudSync ",
        "date": "2026-10-06",
        "family": "CloudSync",
        "platform": "macOS"
      },
      "matched_strings": [
        {
          "offset": "0x2db10",
          "identifier": "$sobf_sbox",
          "data_preview": "d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51"
        },
        {
          "offset": "0x62db0",
          "identifier": "$sobf_sbox",
          "data_preview": "d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51"
        },
        {
          "offset": "0xbae50",
          "identifier": "$sobf_sbox",
          "data_preview": "d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51"
        },
        {
          "offset": "0x12cc38",
          "identifier": "$sobf_sbox",
          "data_preview": "d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51"
        },
        {
          "offset": "0x161ed8",
          "identifier": "$sobf_sbox",
          "data_preview": "d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51"
        },
        {
          "offset": "0x1b9f78",
          "identifier": "$sobf_sbox",
          "data_preview": "d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51"
        },
        {
          "offset": "0x20f6f",
          "identifier": "$sobf_code_x86",
          "data_preview": "41 6b c4 83 41 83 e4 1f"
        },
        {
          "offset": "0x45e8f",
          "identifier": "$sobf_code_x86",
          "data_preview": "41 6b c4 83 41 83 e4 1f"
        },
        {
          "offset": "0x144fb7",
          "identifier": "$sobf_code_x86",
          "data_preview": "41 6b c4 83 41 83 e4 1f"
        },
        {
          "offset": "0x9f42c",
          "identifier": "$sobf_code_arm",
          "data_preview": "69 10 80 52 c9 7e 09 9b cb 12 40 92"
        },
        {
          "offset": "0x1209d8",
          "identifier": "$sobf_code_arm",
          "data_preview": "69 10 80 52 c9 7e 09 9b cb 12 40 92"
        },
        {
          "offset": "0x19e554",
          "identifier": "$sobf_code_arm",
          "data_preview": "69 10 80 52 c9 7e 09 9b cb 12 40 92"
        },
        {
          "offset": "0x6d99a",
          "identifier": "$ns1",
          "data_preview": "cloudsync_impl"
        },
        {
          "offset": "0x6d9d7",
          "identifier": "$ns1",
          "data_preview": "cloudsync_impl"
        },
        {
          "offset": "0x6da13",
          "identifier": "$ns1",
          "data_preview": "cloudsync_impl"
        }
      ],
      "sample_sha256": "524a7bcc8edcadc6f4381459f79769e1ec534aa78f66e5c38a6678bd55cf2572",
      "sample_md5": "0ea400ad00f00428dbf178ca9488c332",
      "sample_name": "524a7bcc8edcadc6f4381459f79769e1ec534aa78f66e5c38a6678bd55cf2572.macho",
      "sample_size_bytes": 2119024,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-09-30 10:36:14",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "macho"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 29,
        "total_engines": 62,
        "detection_ratio": "29/62",
        "suggested_threat_label": "trojan.cldsync/abtrojan",
        "popular_threat_category": [
          {
            "count": 18,
            "value": "trojan"
          }
        ],
        "names": [
          "524a7bcc8edcadc6f4381459f79769e1ec534aa78f66e5c38a6678bd55cf2572.macho",
          "ihrf2.exe",
          "9x6bbuhe6.exe",
          "app_installer"
        ],
        "type_description": "Mach-O",
        "tags": [
          "multi-arch",
          "self-delete",
          "macho",
          "arm",
          "dropper",
          "password-dialog",
          "64bits",
          "service-scan",
          "self-signed"
        ],
        "reputation": -1,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Backdoor.OSX.Agent.bs",
          "Sophos": "OSX/CldSync-A",
          "ESET-NOD32": "OSX/PSW.Agent.KO trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/524a7bcc8edcadc6f4381459f79769e1ec534aa78f66e5c38a6678bd55cf2572"
      },
      "detected_at": "2026-10-16T09:42:46.011654+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x645d8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x13c620",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "81e34b0ec6928234d0a24f9b1634d1e2201fe0fca38bf048229d750ba35f64ca",
      "sample_md5": "f7ef4c1829b0f60ab48c5dcb551b3a2c",
      "sample_name": "81e34b0ec6928234d0a24f9b1634d1e2201fe0fca38bf048229d750ba35f64ca.macho",
      "sample_size_bytes": 1758160,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-18 19:25:19",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 26,
        "total_engines": 63,
        "detection_ratio": "26/63",
        "suggested_threat_label": "trojan.amos/class",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 18
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "kjsg79.exe",
          "81e34b0ec6928234d0a24f9b1634d1e2201fe0fca38bf048229d750ba35f64ca.macho",
          "i9lxc.exe",
          "macho_81e34b0ec692.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "self-signed",
          "64bits",
          "multi-arch",
          "arm",
          "macho"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/81e34b0ec6928234d0a24f9b1634d1e2201fe0fca38bf048229d750ba35f64ca"
      },
      "detected_at": "2026-10-18T21:15:48.044327+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "platform": "macos",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [
        {
          "offset": "0x54ffa",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x55017",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5508f",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadec9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadee6",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadef9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5500c",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0xadedb",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0x55632",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0xae44a",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0x99418",
          "identifier": "$op_arm64_dec",
          "data_preview": "4b 09 40 b3 6b 01 40 39 cc 02 0a 8b 8d 41 40 39 ab 01 0b 4a 8b 41 00 39 29 05 c9 93"
        },
        {
          "offset": "0x5b7ac",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x9948c",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99e80",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99f14",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        }
      ],
      "sample_sha256": "e395c5343703a570d12620c81b9593ea6117d2f57c95bd8247704d9dbd256ce6",
      "sample_md5": "8940fc0ec2243756dd25e5a144e96591",
      "sample_name": "e395c5343703a570d12620c81b9593ea6117d2f57c95bd8247704d9dbd256ce6.macho",
      "sample_size_bytes": 723072,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-18 17:55:22",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 34,
        "total_engines": 62,
        "detection_ratio": "34/62",
        "suggested_threat_label": "trojan.stealer/amos",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 19
          }
        ],
        "names": [
          "e395c5343703a570d12620c81b9593ea6117d2f57c95bd8247704d9dbd256ce6.macho",
          "192.162.199.249_sample.bin",
          "0mug7gt9c94l6fn3",
          "ikohtarys.exe",
          "macho_e395c5343703.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "checks-vm",
          "os-credentials",
          "64bits",
          "multi-arch",
          "checks-cpu-name",
          "macho",
          "self-delete",
          "browser-creds",
          "arm",
          "password-dialog",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/AmosStealer.DB!MTB",
          "SentinelOne": "Static AI - Malicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bg",
          "Sophos": "OSX/InfoStl-GW",
          "ESET-NOD32": "OSX/PSW.Agent.GF trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/e395c5343703a570d12620c81b9593ea6117d2f57c95bd8247704d9dbd256ce6"
      },
      "detected_at": "2026-10-18T21:15:48.044327+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x6a288",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x14f0e0",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "85fce9826974549c2dd4c92a3207cf2543e10676ad2dfad7c8ea429f616cdf21",
      "sample_md5": "954b11a1b80b84c2c5cf88d5f0739ab3",
      "sample_name": "85fce9826974549c2dd4c92a3207cf2543e10676ad2dfad7c8ea429f616cdf21.macho",
      "sample_size_bytes": 1857152,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-18 15:26:33",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 25,
        "total_engines": 63,
        "detection_ratio": "25/63",
        "suggested_threat_label": "trojan.multiverze/abpws",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 16
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "lb1iin.exe",
          "85fce9826974549c2dd4c92a3207cf2543e10676ad2dfad7c8ea429f616cdf21.macho",
          "ce16mvcb.exe",
          "macho_85fce9826974.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "multi-arch",
          "self-signed",
          "macho",
          "64bits",
          "arm"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/85fce9826974549c2dd4c92a3207cf2543e10676ad2dfad7c8ea429f616cdf21"
      },
      "detected_at": "2026-10-18T21:15:48.044327+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "platform": "macos",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [
        {
          "offset": "0x5b5cf",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5b5ec",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5b664",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xbe49e",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xbe4bb",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xbe4ce",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5b5e1",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0xbe4b0",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0x5bc2d",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0xbea45",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0xa746c",
          "identifier": "$op_arm64_dec",
          "data_preview": "4b 09 40 b3 6b 01 40 39 cc 02 0a 8b 8d 41 40 39 ab 01 0b 4a 8b 41 00 39 29 05 c9 93"
        }
      ],
      "sample_sha256": "89a25311145ada1664428064bc5b4ae16ec3e322b1399f3d4e753de8aba3ea06",
      "sample_md5": "0f3d9a4643825505892cd370a58014c5",
      "sample_name": "89a25311145ada1664428064bc5b4ae16ec3e322b1399f3d4e753de8aba3ea06.macho",
      "sample_size_bytes": 790128,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-18 06:37:57",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "macho"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 30,
        "total_engines": 63,
        "detection_ratio": "30/63",
        "suggested_threat_label": "trojan.stealer/amos",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 19
          }
        ],
        "names": [
          "cf7jcx5ttx7uw21f",
          "89a25311145ada1664428064bc5b4ae16ec3e322b1399f3d4e753de8aba3ea06.macho",
          "eaag6g.exe",
          "192.162.199.249_sample.bin",
          "macho_89a25311145a.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "os-credentials",
          "self-delete",
          "password-dialog",
          "multi-arch",
          "64bits",
          "browser-creds",
          "arm",
          "checks-cpu-name",
          "self-signed",
          "checks-vm",
          "macho"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/AmosStealer.DB!MTB",
          "SentinelOne": "Static AI - Suspicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bg",
          "ESET-NOD32": "OSX/PSW.Agent.GF trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/89a25311145ada1664428064bc5b4ae16ec3e322b1399f3d4e753de8aba3ea06"
      },
      "detected_at": "2026-10-18T21:15:48.044327+00:00",
      "last_seen_at": "2026-10-20T18:52:09.961170+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x71388",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x15959c",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "6c118d4bd1a56f56756b78134474c2a5becd3f138803d3297155691a427f6524",
      "sample_md5": "9ec7c7bc599d26a7b63428eba0af0d2c",
      "sample_name": "6c118d4bd1a56f56756b78134474c2a5becd3f138803d3297155691a427f6524.macho",
      "sample_size_bytes": 1905440,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-18 00:50:40",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 27,
        "total_engines": 63,
        "detection_ratio": "27/63",
        "suggested_threat_label": "trojan.egairtigado/abtrojan",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 16
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "sgrznw.exe",
          "6c118d4bd1a56f56756b78134474c2a5becd3f138803d3297155691a427f6524.macho",
          "zv0vwq5w3.exe",
          "macho_6c118d4bd1a5.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "macho",
          "multi-arch",
          "self-signed",
          "arm"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Trojan:Win32/Egairtigado!rfn",
          "Kaspersky": "UDS:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/6c118d4bd1a56f56756b78134474c2a5becd3f138803d3297155691a427f6524"
      },
      "detected_at": "2026-10-18T21:15:48.044327+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x866e8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x187d58",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "813bb6f2bc378364b4a0ed1405fe6ccd34a1510c4c94fe98f5908e6514999c1a",
      "sample_md5": "b3481c07a846afc398fec764d8ea3254",
      "sample_name": "813bb6f2bc378364b4a0ed1405fe6ccd34a1510c4c94fe98f5908e6514999c1a.macho",
      "sample_size_bytes": 2086688,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-18 00:42:03",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 25,
        "total_engines": 63,
        "detection_ratio": "25/63",
        "suggested_threat_label": "trojan.amos/class",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 15
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "l0nmm3bau.exe",
          "813bb6f2bc378364b4a0ed1405fe6ccd34a1510c4c94fe98f5908e6514999c1a.macho",
          "uc0ju.exe",
          "macho_813bb6f2bc37.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "self-signed",
          "64bits",
          "arm",
          "multi-arch"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "UDS:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/813bb6f2bc378364b4a0ed1405fe6ccd34a1510c4c94fe98f5908e6514999c1a"
      },
      "detected_at": "2026-10-18T21:15:48.044327+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x90bc8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x18b178",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "aa2fe64a8b365f79ba99c5cae660602063d6b555b3dd2e40d05f5293ca2c2a96",
      "sample_md5": "4fc57fbac7a8ddae835f2a1e3aaa6f71",
      "sample_name": "aa2fe64a8b365f79ba99c5cae660602063d6b555b3dd2e40d05f5293ca2c2a96.macho",
      "sample_size_bytes": 2086064,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-18 00:38:14",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 25,
        "total_engines": 63,
        "detection_ratio": "25/63",
        "suggested_threat_label": "trojan.amos/class",
        "popular_threat_category": [
          {
            "count": 16,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "3vhdrtd.exe",
          "aa2fe64a8b365f79ba99c5cae660602063d6b555b3dd2e40d05f5293ca2c2a96.macho",
          "r5uv6.exe",
          "macho_aa2fe64a8b36.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "multi-arch",
          "64bits",
          "self-signed",
          "arm"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "UDS:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/aa2fe64a8b365f79ba99c5cae660602063d6b555b3dd2e40d05f5293ca2c2a96"
      },
      "detected_at": "2026-10-18T21:15:48.044327+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x64828",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x146608",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "f2c7af231a3dc1a9291a2421d2b67e3c6ed829073fdcbd7aeec3c33a933d2f6e",
      "sample_md5": "d023d47b2f589cfcbb6489b3fec54a20",
      "sample_name": "f2c7af231a3dc1a9291a2421d2b67e3c6ed829073fdcbd7aeec3c33a933d2f6e.macho",
      "sample_size_bytes": 1824160,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-18 00:34:28",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 25,
        "total_engines": 63,
        "detection_ratio": "25/63",
        "suggested_threat_label": "trojan.amos/egairtigado",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 16
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "apnb93vb.exe",
          "f2c7af231a3dc1a9291a2421d2b67e3c6ed829073fdcbd7aeec3c33a933d2f6e.macho",
          "p2qjai1k.exe",
          "rdgsgykkd.exe",
          "macho_f2c7af231a3d.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "arm",
          "multi-arch",
          "64bits",
          "self-signed"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Trojan:Win32/Egairtigado!rfn",
          "Kaspersky": "UDS:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/f2c7af231a3dc1a9291a2421d2b67e3c6ed829073fdcbd7aeec3c33a933d2f6e"
      },
      "detected_at": "2026-10-18T21:15:48.044327+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x674c8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x146bac",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "d64921058e03078b75565d5aeea126e75698f39be3c6387d17c5d9fa8536d0ac",
      "sample_md5": "1201d3f0dcdbc694d6cdc5709fc6913a",
      "sample_name": "d64921058e03078b75565d5aeea126e75698f39be3c6387d17c5d9fa8536d0ac.macho",
      "sample_size_bytes": 1807920,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-18 00:32:08",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 24,
        "total_engines": 63,
        "detection_ratio": "24/63",
        "suggested_threat_label": "trojan.egairtigado/amos",
        "popular_threat_category": [
          {
            "count": 15,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "ff3znjn.exe",
          "d64921058e03078b75565d5aeea126e75698f39be3c6387d17c5d9fa8536d0ac.macho",
          "7zaa78z70.exe",
          "macho_d64921058e03.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "self-signed",
          "multi-arch",
          "macho",
          "64bits",
          "arm"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Trojan:Win32/Egairtigado!rfn",
          "Kaspersky": "UDS:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/d64921058e03078b75565d5aeea126e75698f39be3c6387d17c5d9fa8536d0ac"
      },
      "detected_at": "2026-10-18T21:15:48.044327+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x6da48",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x14f068",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "e6490a700b965a6dcf264eb1e8291217d9e52f167470d70bc24806697fabeeaa",
      "sample_md5": "b5f69f7dda8147ade669bc404f610f77",
      "sample_name": "e6490a700b965a6dcf264eb1e8291217d9e52f167470d70bc24806697fabeeaa.macho",
      "sample_size_bytes": 1856288,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-18 00:28:31",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 25,
        "total_engines": 63,
        "detection_ratio": "25/63",
        "suggested_threat_label": "trojan.multiverze/amos",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 16
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "3ef1f.exe",
          "e6490a700b965a6dcf264eb1e8291217d9e52f167470d70bc24806697fabeeaa.macho",
          "95oso0rj.exe",
          "42gro2stz.exe",
          "macho_e6490a700b96.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "multi-arch",
          "macho",
          "arm",
          "self-signed",
          "64bits"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "UDS:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/e6490a700b965a6dcf264eb1e8291217d9e52f167470d70bc24806697fabeeaa"
      },
      "detected_at": "2026-10-18T21:15:48.044327+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x764d8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x1677ec",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "efc0f30e9b1c8e4b1479006ecdcc95d5d4fa0627af8b294a6babe57da17b58d3",
      "sample_md5": "35889a421f52606c0e7fe0deb874c567",
      "sample_name": "efc0f30e9b1c8e4b1479006ecdcc95d5d4fa0627af8b294a6babe57da17b58d3.macho",
      "sample_size_bytes": 1971168,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-17 10:26:00",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 28,
        "total_engines": 63,
        "detection_ratio": "28/63",
        "suggested_threat_label": "trojan.egairtigado/abtrojan",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 18
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "5y3gn.exe",
          "efc0f30e9b1c8e4b1479006ecdcc95d5d4fa0627af8b294a6babe57da17b58d3.macho",
          "hwummhk.exe",
          "macho_efc0f30e9b1c.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "multi-arch",
          "64bits",
          "self-signed",
          "macho",
          "arm"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Trojan:Win32/Egairtigado!rfn",
          "Kaspersky": "UDS:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/efc0f30e9b1c8e4b1479006ecdcc95d5d4fa0627af8b294a6babe57da17b58d3"
      },
      "detected_at": "2026-10-18T21:15:48.044327+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x5e288",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x140ce8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "322a9bdadc796f2b2a7459b949ff367ed3258e9a8eefb1af161b557418ce845d",
      "sample_md5": "063d431494f6334fcb4ff7bed85cc4f4",
      "sample_name": "322a9bdadc796f2b2a7459b949ff367ed3258e9a8eefb1af161b557418ce845d.macho",
      "sample_size_bytes": 1840576,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-17 00:38:39",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 29,
        "total_engines": 62,
        "detection_ratio": "29/62",
        "suggested_threat_label": "trojan.egairtigado/amos",
        "popular_threat_category": [
          {
            "count": 20,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "srzo6.exe",
          "322a9bdadc796f2b2a7459b949ff367ed3258e9a8eefb1af161b557418ce845d.macho",
          "58hse75.exe",
          "macho_322a9bdadc79.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "self-signed",
          "multi-arch",
          "macho",
          "64bits"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Trojan:Win32/Egairtigado!rfn",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/322a9bdadc796f2b2a7459b949ff367ed3258e9a8eefb1af161b557418ce845d"
      },
      "detected_at": "2026-10-18T21:15:48.044327+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x5f1e8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x137888",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "51ad0fe8782d9756f1fc647bfd19e649b1b3e55e8b641a295062c935c1939bd8",
      "sample_md5": "b2c79175abeac23f568643b24aea5938",
      "sample_name": "51ad0fe8782d9756f1fc647bfd19e649b1b3e55e8b641a295062c935c1939bd8.macho",
      "sample_size_bytes": 1758272,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-17 00:32:55",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 24,
        "total_engines": 63,
        "detection_ratio": "24/63",
        "suggested_threat_label": "trojan.class/deulm0",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 16
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "29k1a.exe",
          "51ad0fe8782d9756f1fc647bfd19e649b1b3e55e8b641a295062c935c1939bd8.macho",
          "fb5j7qv0d.exe",
          "macho_51ad0fe8782d.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "self-signed",
          "macho",
          "multi-arch",
          "arm"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.C!ml",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/51ad0fe8782d9756f1fc647bfd19e649b1b3e55e8b641a295062c935c1939bd8"
      },
      "detected_at": "2026-10-18T21:15:48.044327+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x68f18",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x1460ac",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "ecf0f6b181632fb335c800bcc77cccc5584bc15b5ac594dc68019f05081c3d5d",
      "sample_md5": "d05c4e8e90385e4a6b026c6fd19977be",
      "sample_name": "ecf0f6b181632fb335c800bcc77cccc5584bc15b5ac594dc68019f05081c3d5d.macho",
      "sample_size_bytes": 1774688,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-17 00:29:29",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 27,
        "total_engines": 63,
        "detection_ratio": "27/63",
        "suggested_threat_label": "trojan.egairtigado/abtrojan",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 18
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "zpw8xjdxv.exe",
          "ecf0f6b181632fb335c800bcc77cccc5584bc15b5ac594dc68019f05081c3d5d.macho",
          "woulzm8.exe",
          "macho_ecf0f6b18163.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "self-signed",
          "macho",
          "multi-arch",
          "arm",
          "64bits"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Trojan:Win32/Egairtigado!rfn",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/ecf0f6b181632fb335c800bcc77cccc5584bc15b5ac594dc68019f05081c3d5d"
      },
      "detected_at": "2026-10-18T21:15:48.044327+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x6bbf8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x14535c",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "3bf9ac9cb26ecffd2ab26bb14c81c110b53fe31c196cc774291ad4af804023c3",
      "sample_md5": "2c75f5fe56280172fc4c3e0a1c5745a1",
      "sample_name": "3bf9ac9cb26ecffd2ab26bb14c81c110b53fe31c196cc774291ad4af804023c3.macho",
      "sample_size_bytes": 1791616,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-17 00:26:55",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 24,
        "total_engines": 63,
        "detection_ratio": "24/63",
        "suggested_threat_label": "trojan.egairtigado/abrisk",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 14
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "vgsh6af2.exe",
          "3bf9ac9cb26ecffd2ab26bb14c81c110b53fe31c196cc774291ad4af804023c3.macho",
          "9zx26m.exe",
          "macho_3bf9ac9cb26e.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "macho",
          "self-signed",
          "64bits",
          "multi-arch"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Trojan:Win32/Egairtigado!rfn",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/3bf9ac9cb26ecffd2ab26bb14c81c110b53fe31c196cc774291ad4af804023c3"
      },
      "detected_at": "2026-10-18T21:15:48.044327+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "platform": "macos",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [
        {
          "offset": "0x54ffa",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x55017",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5508f",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadec9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadee6",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0xadef9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x5500c",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0xadedb",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0x55632",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0xae44a",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0x99418",
          "identifier": "$op_arm64_dec",
          "data_preview": "4b 09 40 b3 6b 01 40 39 cc 02 0a 8b 8d 41 40 39 ab 01 0b 4a 8b 41 00 39 29 05 c9 93"
        },
        {
          "offset": "0x5b7ac",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x9948c",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99e80",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x99f14",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        }
      ],
      "sample_sha256": "104a6e4b1da8f7b42bdaf887b82f2c12348c6b1ffe52d1de2d964b6329492ad7",
      "sample_md5": "b3d0c55af9a3b6fbca4e92b995709aa3",
      "sample_name": "104a6e4b1da8f7b42bdaf887b82f2c12348c6b1ffe52d1de2d964b6329492ad7.macho",
      "sample_size_bytes": 723072,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-16 20:17:35",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "macho"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 35,
        "total_engines": 63,
        "detection_ratio": "35/63",
        "suggested_threat_label": "trojan.stealer/amos",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 20
          }
        ],
        "names": [
          "hbspbloprxh3iu2h",
          "104a6e4b1da8f7b42bdaf887b82f2c12348c6b1ffe52d1de2d964b6329492ad7.macho",
          "192.162.199.249_sample.bin",
          "az7c9.exe"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "64bits",
          "multi-arch",
          "self-signed",
          "macho",
          "self-delete",
          "checks-cpu-name",
          "password-dialog",
          "browser-creds",
          "os-credentials",
          "checks-vm",
          "service-scan"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/AmosStealer.DB!MTB",
          "SentinelOne": "Static AI - Malicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bg",
          "Sophos": "OSX/InfoStl-GW",
          "ESET-NOD32": "OSX/PSW.Agent.GF trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/104a6e4b1da8f7b42bdaf887b82f2c12348c6b1ffe52d1de2d964b6329492ad7"
      },
      "detected_at": "2026-10-18T21:15:48.044327+00:00",
      "last_seen_at": "2026-10-20T18:52:09.961170+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x5dcc8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x1353b0",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "cefb465886bc813ac91e9ad5b1835eefe9828f251b58eb0da012ee4022ff6d98",
      "sample_md5": "8e249a77ba41050b18c9e4b3f69e1390",
      "sample_name": "cefb465886bc813ac91e9ad5b1835eefe9828f251b58eb0da012ee4022ff6d98.macho",
      "sample_size_bytes": 1758512,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-16 16:26:28",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 23,
        "total_engines": 61,
        "detection_ratio": "23/61",
        "suggested_threat_label": "trojan.class/macho",
        "popular_threat_category": [
          {
            "count": 17,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "t9n0t6i.exe",
          "qd808gddw.exe",
          "cefb465886bc813ac91e9ad5b1835eefe9828f251b58eb0da012ee4022ff6d98.macho",
          "macho_cefb465886bc.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "self-signed",
          "arm",
          "multi-arch",
          "macho"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/cefb465886bc813ac91e9ad5b1835eefe9828f251b58eb0da012ee4022ff6d98"
      },
      "detected_at": "2026-10-18T21:15:48.044327+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "Macho_Trojan_CloudSync_1007YR",
      "platform": "macos",
      "namespace": "macos_stealer",
      "tags": [],
      "meta": {
        "silent": 1,
        "author": "Chandra Kant Bauri",
        "description": "Detects CloudSync trojanized DMG disk image containers",
        "date": "2026-10-06",
        "family": "CloudSync",
        "platform": "macOS"
      },
      "matched_strings": [
        {
          "offset": "0x1eed16",
          "identifier": "$koly",
          "data_preview": "koly"
        },
        {
          "offset": "0x1ec574",
          "identifier": "$xml",
          "data_preview": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        },
        {
          "offset": "0x1ec59b",
          "identifier": "$plist",
          "data_preview": "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\""
        },
        {
          "offset": "0x1ec6bf",
          "identifier": "$part",
          "data_preview": "whole disk (unknown partition : 0)"
        },
        {
          "offset": "0x1ee1de",
          "identifier": "$part",
          "data_preview": "whole disk (unknown partition : 0)"
        },
        {
          "offset": "0x1ec70e",
          "identifier": "$mish_hdr",
          "data_preview": "bWlzaAAAAAEAAAAAAAAAAAAAAAAAANg"
        },
        {
          "offset": "0x1ec778",
          "identifier": "$crc_part",
          "data_preview": "PbEzG"
        }
      ],
      "sample_sha256": "faf2eea05f3c9f1c4ef8f6be339f5459a38f95cfd9d512bc24e2803230e5c7bf",
      "sample_md5": "0b572c56189c562cd4250cbfe0662be1",
      "sample_name": "zoom.dmg",
      "sample_size_bytes": 2027286,
      "source_feed": "Local File",
      "detected_at": "2026-10-19T02:32:11.677388+00:00",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 20,
        "total_engines": 58,
        "detection_ratio": "20/58",
        "suggested_threat_label": "trojan.multiverze/abtrojan",
        "popular_threat_category": [
          {
            "count": 16,
            "value": "trojan"
          }
        ],
        "names": [
          "Zoom.dmg"
        ],
        "type_description": "Macintosh Disk Image",
        "tags": [
          "self-signed",
          "password-dialog",
          "dmg",
          "self-delete"
        ],
        "reputation": -1,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "UDS:Trojan-PSW.OSX.Agent.gen",
          "Sophos": "OSX/CldSync-A",
          "ESET-NOD32": "OSX/PSW.Agent.KO trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/faf2eea05f3c9f1c4ef8f6be339f5459a38f95cfd9d512bc24e2803230e5c7bf"
      }
    },
    {
      "rule_name": "Macho_Trojan_CloudSync_DMG",
      "platform": "macos",
      "namespace": "macos_cloud_sync",
      "tags": [],
      "meta": {
        "description": "Detects CloudSync trojanized DMG disk image containers",
        "date": "2026-10-06",
        "family": "CloudSync",
        "platform": "macOS"
      },
      "matched_strings": [
        {
          "offset": "0x1eed16",
          "identifier": "$koly",
          "data_preview": "koly"
        },
        {
          "offset": "0x1ec574",
          "identifier": "$xml",
          "data_preview": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        },
        {
          "offset": "0x1ec59b",
          "identifier": "$plist",
          "data_preview": "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\""
        },
        {
          "offset": "0x1ec6bf",
          "identifier": "$part",
          "data_preview": "whole disk (unknown partition : 0)"
        },
        {
          "offset": "0x1ee1de",
          "identifier": "$part",
          "data_preview": "whole disk (unknown partition : 0)"
        },
        {
          "offset": "0x1ec70e",
          "identifier": "$mish_hdr",
          "data_preview": "bWlzaAAAAAEAAAAAAAAAAAAAAAAAANg"
        },
        {
          "offset": "0x1ec778",
          "identifier": "$crc_part",
          "data_preview": "PbEzG"
        }
      ],
      "sample_sha256": "faf2eea05f3c9f1c4ef8f6be339f5459a38f95cfd9d512bc24e2803230e5c7bf",
      "sample_md5": "0b572c56189c562cd4250cbfe0662be1",
      "sample_name": "zoom.dmg",
      "sample_size_bytes": 2027286,
      "source_feed": "Local File",
      "detected_at": "2026-10-19T02:32:11.677388+00:00",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 20,
        "total_engines": 58,
        "detection_ratio": "20/58",
        "suggested_threat_label": "trojan.multiverze/abtrojan",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 16
          }
        ],
        "names": [
          "Zoom.dmg"
        ],
        "type_description": "Macintosh Disk Image",
        "tags": [
          "self-signed",
          "password-dialog",
          "dmg",
          "self-delete"
        ],
        "reputation": -1,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "UDS:Trojan-PSW.OSX.Agent.gen",
          "Sophos": "OSX/CldSync-A",
          "ESET-NOD32": "OSX/PSW.Agent.KO trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/faf2eea05f3c9f1c4ef8f6be339f5459a38f95cfd9d512bc24e2803230e5c7bf"
      }
    },
    {
      "rule_name": "Macho_hVNCRat_generic",
      "platform": "macos",
      "namespace": "macos_stealer",
      "tags": [],
      "meta": {
        "author": "Chandra Kant Bauri",
        "description": "Detects generic macOS HVNC (Hidden VNC) browser hijacking implant",
        "date": "2026-10-14",
        "malware_family": "macOS.hvnc"
      },
      "matched_strings": [
        {
          "offset": "0x2a604",
          "identifier": "$js_find",
          "data_preview": "window.__hvncFind"
        },
        {
          "offset": "0x2a62c",
          "identifier": "$js_find",
          "data_preview": "window.__hvncFind"
        },
        {
          "offset": "0x2a645",
          "identifier": "$js_find",
          "data_preview": "window.__hvncFind"
        },
        {
          "offset": "0x605cc",
          "identifier": "$js_find",
          "data_preview": "window.__hvncFind"
        },
        {
          "offset": "0x605f4",
          "identifier": "$js_find",
          "data_preview": "window.__hvncFind"
        },
        {
          "offset": "0x6060d",
          "identifier": "$js_find",
          "data_preview": "window.__hvncFind"
        },
        {
          "offset": "0x2a4c0",
          "identifier": "$js_copy",
          "data_preview": "window.__hvncCopySel"
        },
        {
          "offset": "0x60488",
          "identifier": "$js_copy",
          "data_preview": "window.__hvncCopySel"
        },
        {
          "offset": "0x2a385",
          "identifier": "$js_zoom",
          "data_preview": "window.__hvncZoomSet"
        },
        {
          "offset": "0x6034d",
          "identifier": "$js_zoom",
          "data_preview": "window.__hvncZoomSet"
        },
        {
          "offset": "0x2a2d4",
          "identifier": "$css_find",
          "data_preview": "::highlight(hvnc-find)"
        },
        {
          "offset": "0x6029c",
          "identifier": "$css_find",
          "data_preview": "::highlight(hvnc-find)"
        },
        {
          "offset": "0x2c2c8",
          "identifier": "$sqlite_bak",
          "data_preview": ".backup '$T.hvncbak'"
        },
        {
          "offset": "0x6228f",
          "identifier": "$sqlite_bak",
          "data_preview": ".backup '$T.hvncbak'"
        },
        {
          "offset": "0x27f09",
          "identifier": "$pkill_clone",
          "data_preview": "/usr/bin/pkill -f 'hvnc_clone_'"
        }
      ],
      "sample_sha256": "5681c400f0ed8431b3950e92864e52cffb0bf93a359edffb49e423ad5e8ef0b8",
      "sample_md5": "540a0c1858da1e38cd4b64db1fefa6e0",
      "sample_name": "5681c400f0ed8431b3950e92864e52cffb0bf93a359edffb49e423ad5e8ef0b8",
      "sample_size_bytes": 469200,
      "source_feed": "Local File",
      "detected_at": "2026-10-19T02:32:11.677388+00:00",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 4,
        "total_engines": 63,
        "detection_ratio": "4/63",
        "suggested_threat_label": "trojan.horse/stealer",
        "popular_threat_category": [
          {
            "count": 3,
            "value": "trojan"
          }
        ],
        "names": [
          "agent",
          "wohnung"
        ],
        "type_description": "Mach-O",
        "tags": [
          "service-scan",
          "long-sleeps",
          "arm",
          "malware",
          "multi-arch",
          "64bits",
          "macho"
        ],
        "reputation": -3,
        "key_engine_detections": {},
        "vt_permalink": "https://www.virustotal.com/gui/file/5681c400f0ed8431b3950e92864e52cffb0bf93a359edffb49e423ad5e8ef0b8"
      }
    },
    {
      "rule_name": "Macho_hVNCRat_campaign",
      "platform": "macos",
      "namespace": "macos_stealer",
      "tags": [],
      "meta": {
        "author": "Chandra Kant Bauri",
        "description": "Detects specific campaign build of macOS HVNC implant",
        "date": "2026-10-14",
        "malware_family": "macOS.HVNC",
        "sample_hash": "5681c400f0ed8431b3950e92864e52cffb0bf93a359edffb49e423ad5e8ef0b8"
      },
      "matched_strings": [
        {
          "offset": "0x2f95e",
          "identifier": "$c2",
          "data_preview": "agent.torrentsbyjimboslimfit.xyz"
        },
        {
          "offset": "0x6896e",
          "identifier": "$c2",
          "data_preview": "agent.torrentsbyjimboslimfit.xyz"
        },
        {
          "offset": "0x2fa70",
          "identifier": "$tag",
          "data_preview": "HVNC_MAC_TAG:8panel"
        },
        {
          "offset": "0x68a78",
          "identifier": "$tag",
          "data_preview": "HVNC_MAC_TAG:8panel"
        },
        {
          "offset": "0x27e86",
          "identifier": "$psk",
          "data_preview": "hvnc-remote-default-psk"
        },
        {
          "offset": "0x5de52",
          "identifier": "$psk",
          "data_preview": "hvnc-remote-default-psk"
        },
        {
          "offset": "0x36134",
          "identifier": "$id",
          "data_preview": "hvnc_agent_macos_universal"
        },
        {
          "offset": "0x3687b",
          "identifier": "$id",
          "data_preview": "hvnc_agent_macos_universal"
        },
        {
          "offset": "0x72084",
          "identifier": "$id",
          "data_preview": "hvnc_agent_macos_universal"
        },
        {
          "offset": "0x7286b",
          "identifier": "$id",
          "data_preview": "hvnc_agent_macos_universal"
        }
      ],
      "sample_sha256": "5681c400f0ed8431b3950e92864e52cffb0bf93a359edffb49e423ad5e8ef0b8",
      "sample_md5": "540a0c1858da1e38cd4b64db1fefa6e0",
      "sample_name": "5681c400f0ed8431b3950e92864e52cffb0bf93a359edffb49e423ad5e8ef0b8",
      "sample_size_bytes": 469200,
      "source_feed": "Local File",
      "detected_at": "2026-10-19T02:32:11.677388+00:00",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 4,
        "total_engines": 63,
        "detection_ratio": "4/63",
        "suggested_threat_label": "trojan.horse/stealer",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 3
          }
        ],
        "names": [
          "agent",
          "wohnung"
        ],
        "type_description": "Mach-O",
        "tags": [
          "service-scan",
          "long-sleeps",
          "arm",
          "malware",
          "multi-arch",
          "64bits",
          "macho"
        ],
        "reputation": -3,
        "key_engine_detections": {},
        "vt_permalink": "https://www.virustotal.com/gui/file/5681c400f0ed8431b3950e92864e52cffb0bf93a359edffb49e423ad5e8ef0b8"
      }
    },
    {
      "rule_name": "Macho_hVNCRat_shelldropper",
      "platform": "macos",
      "namespace": "macos_stealer",
      "tags": [],
      "meta": {
        "author": "Chandra Kant Bauri",
        "description": "Detects shell dropper script for macOS HVNC agent",
        "date": "2026-10-14",
        "malware_family": "macOS.HVNC",
        "sample_hash": "dce578f5af994c77785b96087e4fd4d8124482eab896dceb175a26342a84e31b"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$sh",
          "data_preview": "#!/bin/"
        },
        {
          "offset": "0x26",
          "identifier": "$c2",
          "data_preview": "txrouteuifbfewfubewfbhgrabbing.xyz"
        },
        {
          "offset": "0x75",
          "identifier": "$c2",
          "data_preview": "txrouteuifbfewfubewfbhgrabbing.xyz"
        },
        {
          "offset": "0x104",
          "identifier": "$uri",
          "data_preview": "/wohnung/agent"
        },
        {
          "offset": "0x2fc",
          "identifier": "$dest",
          "data_preview": "Downloads/wohnung"
        },
        {
          "offset": "0x485",
          "identifier": "$dest",
          "data_preview": "Downloads/wohnung"
        },
        {
          "offset": "0x8b6",
          "identifier": "$dest",
          "data_preview": "Downloads/wohnung"
        },
        {
          "offset": "0x331",
          "identifier": "$plist",
          "data_preview": "com.system.updater.plist"
        },
        {
          "offset": "0x210",
          "identifier": "$check_magic",
          "data_preview": "cafebabe|cffaedfe"
        }
      ],
      "sample_sha256": "dce578f5af994c77785b96087e4fd4d8124482eab896dceb175a26342a84e31b",
      "sample_md5": "cdba0eea25ca357b0be56fc0695803d6",
      "sample_name": "dce578f5af994c77785b96087e4fd4d8124482eab896dceb175a26342a84e31b",
      "sample_size_bytes": 2331,
      "source_feed": "Local File",
      "detected_at": "2026-10-19T02:32:11.677388+00:00",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 5,
        "total_engines": 58,
        "detection_ratio": "5/58",
        "suggested_threat_label": "trojan.horse/qgil",
        "popular_threat_category": [
          {
            "count": 5,
            "value": "trojan"
          }
        ],
        "names": [
          "wohnung"
        ],
        "type_description": "Shell script",
        "tags": [
          "long-sleeps",
          "shell",
          "detect-debug-environment",
          "persistence"
        ],
        "reputation": -2,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/dce578f5af994c77785b96087e4fd4d8124482eab896dceb175a26342a84e31b"
      }
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "platform": "macos",
      "namespace": "macos_OSX_Stealer_AMOS_Generic",
      "tags": [],
      "meta": {
        "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
        "date": "2026-08-20",
        "sample": "5277bb0dd553d54d81dbd8a12d4634f9",
        "malware_family": "Atomic Stealer / AMOS",
        "os": "macos",
        "silent": 1
      },
      "matched_strings": [
        {
          "offset": "0x55ec9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x55ee6",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x55ef9",
          "identifier": "$sym_1",
          "data_preview": "build_info_t"
        },
        {
          "offset": "0x55edb",
          "identifier": "$sym_2",
          "data_preview": "serialized_build_info_t"
        },
        {
          "offset": "0x5644a",
          "identifier": "$sym_3",
          "data_preview": "_g_serialized_build_info"
        },
        {
          "offset": "0x41418",
          "identifier": "$op_arm64_dec",
          "data_preview": "4b 09 40 b3 6b 01 40 39 cc 02 0a 8b 8d 41 40 39 ab 01 0b 4a 8b 41 00 39 29 05 c9 93"
        },
        {
          "offset": "0x37ac",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x4148c",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x41e80",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x41f14",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x41fa8",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x42034",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x420c8",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x4215c",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        },
        {
          "offset": "0x421e8",
          "identifier": "$op_key_load_1",
          "data_preview": "48 64 8b 52 e8 73 be 72"
        }
      ],
      "sample_sha256": "592d93f5899fb3245b962e9388e503efa085729cc41e1404feaf5ab04aeded45",
      "sample_md5": "5277bb0dd553d54d81dbd8a12d4634f9",
      "sample_name": "amos-ARM64",
      "sample_size_bytes": 362624,
      "source_feed": "Local File",
      "detected_at": "2026-10-19T02:32:11.677388+00:00",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 32,
        "total_engines": 63,
        "detection_ratio": "32/63",
        "suggested_threat_label": "trojan.stealer/amos",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 19
          }
        ],
        "names": [
          "localfile~.arm64"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "macho",
          "self-signed",
          "arm",
          "password-dialog",
          "self-delete",
          "checks-cpu-name"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/AmosStealer.DB!MTB",
          "SentinelOne": "Static AI - Malicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.bg",
          "Sophos": "OSX/InfoStl-GW",
          "ESET-NOD32": "OSX/PSW.Agent.GF trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/592d93f5899fb3245b962e9388e503efa085729cc41e1404feaf5ab04aeded45"
      }
    },
    {
      "rule_name": "MALW_macOS_MacSync_Stealer_Universal",
      "platform": "macos",
      "namespace": "macos_MALW_macOS_MacSync_Stealer",
      "tags": [],
      "meta": {
        "description": "Universal multi-architecture detection for macOS MacSync Stealer (Intel x86_64 & Apple Silicon ARM64 / Universal Fat Binaries)",
        "date": "2026-08-31",
        "family": "MacSync",
        "threat_type": "Infostealer / Stager / Exfiltrator",
        "platform": "macOS (x86_64 & ARM64)"
      },
      "matched_strings": [
        {
          "offset": "0x81f",
          "identifier": "$xor_archive",
          "data_preview": "/tmp/osalogging.zip"
        },
        {
          "offset": "0x78e",
          "identifier": "$xor_osascript",
          "data_preview": "osascript"
        },
        {
          "offset": "0x7d0",
          "identifier": "$xor_osascript",
          "data_preview": "osascript"
        },
        {
          "offset": "0x74d",
          "identifier": "$xor_curl",
          "data_preview": "curl -k -s"
        },
        {
          "offset": "0x798",
          "identifier": "$xor_curl",
          "data_preview": "curl -k -s"
        },
        {
          "offset": "0x774",
          "identifier": "$xor_dynamic",
          "data_preview": "/dynamic?txd="
        },
        {
          "offset": "0x7be",
          "identifier": "$xor_dynamic",
          "data_preview": "/dynamic?txd="
        },
        {
          "offset": "0x80ce",
          "identifier": "$imp_freopen",
          "data_preview": "_freopen"
        },
        {
          "offset": "0x82b1",
          "identifier": "$imp_freopen",
          "data_preview": "_freopen"
        },
        {
          "offset": "0x80d7",
          "identifier": "$imp_setsid",
          "data_preview": "_setsid"
        },
        {
          "offset": "0x82ba",
          "identifier": "$imp_setsid",
          "data_preview": "_setsid"
        },
        {
          "offset": "0x80e9",
          "identifier": "$imp_system",
          "data_preview": "_system"
        },
        {
          "offset": "0x82cc",
          "identifier": "$imp_system",
          "data_preview": "_system"
        },
        {
          "offset": "0x80c8",
          "identifier": "$imp_fork",
          "data_preview": "_fork"
        },
        {
          "offset": "0x82ab",
          "identifier": "$imp_fork",
          "data_preview": "_fork"
        }
      ],
      "sample_sha256": "fa65230781d2d3afc4152f23e3c4c91a91978d67dda2519d6eeb42476d41dc5a",
      "sample_md5": "87aa640b3e03128a5358b60e17b48d2a",
      "sample_name": "fa65230781d2d3afc4152f23e3c4c91a91978d67dda2519d6eeb42476d41dc5a",
      "sample_size_bytes": 33936,
      "source_feed": "Local File",
      "detected_at": "2026-10-19T02:32:11.677388+00:00",
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 26,
        "total_engines": 63,
        "detection_ratio": "26/63",
        "suggested_threat_label": "trojan.stealer/coins",
        "popular_threat_category": [
          {
            "count": 12,
            "value": "trojan"
          },
          {
            "count": 3,
            "value": "downloader"
          }
        ],
        "names": [
          "localfile~.arm64"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "macho",
          "self-signed",
          "arm"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Stealer!AMTB",
          "SentinelOne": "Static AI - Suspicious Mach-O",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Coins.b",
          "Sophos": "OSX/Dldr-XS",
          "ESET-NOD32": "OSX/PSW.Agent.EK trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/fa65230781d2d3afc4152f23e3c4c91a91978d67dda2519d6eeb42476d41dc5a"
      }
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x71628",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x152188",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "40dc77a48faae52f4ab7e2fbac202427947ffd48fc4e3dc6ed9f9b4403dc590c",
      "sample_md5": "a635c28c24aa6e3e73fad857e3347659",
      "sample_name": "40dc77a48faae52f4ab7e2fbac202427947ffd48fc4e3dc6ed9f9b4403dc590c.macho",
      "sample_size_bytes": 1808400,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-19 01:46:31",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 22,
        "total_engines": 62,
        "detection_ratio": "22/62",
        "suggested_threat_label": "trojan.amos/class",
        "popular_threat_category": [
          {
            "count": 15,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "6zsnd4t.exe",
          "40dc77a48faae52f4ab7e2fbac202427947ffd48fc4e3dc6ed9f9b4403dc590c.macho",
          "76vzy4un.exe",
          "macho_40dc77a48faa.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "self-signed",
          "arm",
          "multi-arch",
          "64bits"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/40dc77a48faae52f4ab7e2fbac202427947ffd48fc4e3dc6ed9f9b4403dc590c"
      },
      "detected_at": "2026-10-19T02:52:22.004609+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x68338",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x144ef0",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "0119e2bc2281379155fe73917dc347f31501873867e7d8174b71c8cdbf0e5c8f",
      "sample_md5": "e13cb75e45b5ddea87ac24bbd7866c94",
      "sample_name": "0119e2bc2281379155fe73917dc347f31501873867e7d8174b71c8cdbf0e5c8f.macho",
      "sample_size_bytes": 1774432,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-19 00:09:42",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 23,
        "total_engines": 63,
        "detection_ratio": "23/63",
        "suggested_threat_label": "trojan.amos/class",
        "popular_threat_category": [
          {
            "count": 16,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "sfu2bk.exe",
          "0119e2bc2281379155fe73917dc347f31501873867e7d8174b71c8cdbf0e5c8f.macho",
          "vg0fru8.exe",
          "macho_0119e2bc2281.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "macho",
          "arm",
          "multi-arch",
          "self-signed"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/0119e2bc2281379155fe73917dc347f31501873867e7d8174b71c8cdbf0e5c8f"
      },
      "detected_at": "2026-10-19T02:52:22.004609+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x79308",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x168b08",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "ff9c8f57fa3ec4c935c343bc636dee3253e6b6e4dbbd0d64e7898f0c7f7c5598",
      "sample_md5": "e2592299ed996606a84f8e51ef06e215",
      "sample_name": "ff9c8f57fa3ec4c935c343bc636dee3253e6b6e4dbbd0d64e7898f0c7f7c5598.macho",
      "sample_size_bytes": 1953888,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-19 00:04:52",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 24,
        "total_engines": 63,
        "detection_ratio": "24/63",
        "suggested_threat_label": "trojan.amos/cbg41x",
        "popular_threat_category": [
          {
            "count": 16,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "n7nvxs.exe",
          "ff9c8f57fa3ec4c935c343bc636dee3253e6b6e4dbbd0d64e7898f0c7f7c5598.macho",
          "vl54do.exe",
          "macho_ff9c8f57fa3e.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "macho",
          "64bits",
          "multi-arch",
          "self-signed"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/ff9c8f57fa3ec4c935c343bc636dee3253e6b6e4dbbd0d64e7898f0c7f7c5598"
      },
      "detected_at": "2026-10-19T02:52:22.004609+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x76958",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x164990",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "b5d4aba0fe4004e851756d0329f0c165db2c1667c7c73516e0f1537c9afd3298",
      "sample_md5": "685da7c3ebba4f06f024aad8881e85e4",
      "sample_name": "b5d4aba0fe4004e851756d0329f0c165db2c1667c7c73516e0f1537c9afd3298.macho",
      "sample_size_bytes": 1922560,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-18 23:28:21",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 21,
        "total_engines": 55,
        "detection_ratio": "21/55",
        "suggested_threat_label": "trojan.class/dplw",
        "popular_threat_category": [
          {
            "count": 15,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "b5d4aba0fe4004e851756d0329f0c165db2c1667c7c73516e0f1537c9afd3298.macho",
          ".z5vb5uou",
          "bbwj17w.exe",
          "macho_b5d4aba0fe40.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "self-signed",
          "macho",
          "multi-arch",
          "64bits"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/b5d4aba0fe4004e851756d0329f0c165db2c1667c7c73516e0f1537c9afd3298"
      },
      "detected_at": "2026-10-19T02:52:22.004609+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_64_le",
          "data_preview": "cf fa ed fe"
        },
        {
          "offset": "0x8abe8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x8a8a0",
          "identifier": "$chacha20_const",
          "data_preview": "expand 32-byte k"
        }
      ],
      "sample_sha256": "a436ac961ce25a0072fbafb8c1937a94b8c900e3ac512a5aa32ecf4610f2260e",
      "sample_md5": "79bee24265d649117acbc9fa54b90211",
      "sample_name": "a436ac961ce25a0072fbafb8c1937a94b8c900e3ac512a5aa32ecf4610f2260e.macho",
      "sample_size_bytes": 668480,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-19 21:09:58",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "0xf00dbeef",
          "Coruna",
          "DarkSword",
          "GHOSTBLADE",
          "iOS",
          "macho"
        ]
      },
      "vt_enrichment": {
        "vt_status": "not_found",
        "reason": "Sample not seen on VirusTotal yet"
      },
      "detected_at": "2026-10-19T21:33:01.399119+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_64_le",
          "data_preview": "cf fa ed fe"
        },
        {
          "offset": "0x50f68",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x50c60",
          "identifier": "$chacha20_const",
          "data_preview": "expand 32-byte k"
        }
      ],
      "sample_sha256": "b0a7077b5d5baa1fb2d31115fbf226bac47f54c9aa499de343385cab6712f79c",
      "sample_md5": "e17a86c3264e5d7ccf532884db4fae51",
      "sample_name": "b0a7077b5d5baa1fb2d31115fbf226bac47f54c9aa499de343385cab6712f79c.macho",
      "sample_size_bytes": 420896,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-19 21:09:46",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "0xf00dbeef",
          "Coruna",
          "DarkSword",
          "GHOSTBLADE",
          "iOS",
          "macho"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 11,
        "total_engines": 63,
        "detection_ratio": "11/63",
        "suggested_threat_label": "trojan.",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 9
          }
        ],
        "names": [
          "9sngg73v9.exe",
          "b0a7077b5d5baa1fb2d31115fbf226bac47f54c9aa499de343385cab6712f79c.macho"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "self-signed",
          "64bits",
          "ios",
          "lib",
          "macho"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/b0a7077b5d5baa1fb2d31115fbf226bac47f54c9aa499de343385cab6712f79c"
      },
      "detected_at": "2026-10-19T21:33:01.399119+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x63eb8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x13bce8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "cf28f44cfec7384cd572f5457a2d7e4a09fd72f7a29264393961fa4493b29c19",
      "sample_md5": "d99b4e5cb729662e7c2b9a9b34227241",
      "sample_name": "cf28f44cfec7384cd572f5457a2d7e4a09fd72f7a29264393961fa4493b29c19.macho",
      "sample_size_bytes": 1758656,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-19 16:22:16",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 26,
        "total_engines": 63,
        "detection_ratio": "26/63",
        "suggested_threat_label": "trojan.abtrojan/amos",
        "popular_threat_category": [
          {
            "count": 17,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "woipy1.exe",
          "cf28f44cfec7384cd572f5457a2d7e4a09fd72f7a29264393961fa4493b29c19.macho",
          "crfn2o.exe",
          "macho_cf28f44cfec7.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "self-signed",
          "macho",
          "arm",
          "64bits",
          "multi-arch"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/cf28f44cfec7384cd572f5457a2d7e4a09fd72f7a29264393961fa4493b29c19"
      },
      "detected_at": "2026-10-19T21:33:01.399119+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x6caa8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x151150",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "47258dad12e7bbb34a8421c79e98a10f62adc6d613fa8d94c30599fffbb040f8",
      "sample_md5": "d43ef492e1e09715c83f1c6cb9cef50b",
      "sample_name": "47258dad12e7bbb34a8421c79e98a10f62adc6d613fa8d94c30599fffbb040f8.macho",
      "sample_size_bytes": 1873696,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-19 15:49:42",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 19,
        "total_engines": 62,
        "detection_ratio": "19/62",
        "suggested_threat_label": "trojan.amos/bnhl",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 13
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "e6mmb.exe",
          "47258dad12e7bbb34a8421c79e98a10f62adc6d613fa8d94c30599fffbb040f8.macho",
          "cbkv4.exe",
          "macho_47258dad12e7.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "multi-arch",
          "arm",
          "self-signed",
          "macho"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Kaspersky": "UDS:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/47258dad12e7bbb34a8421c79e98a10f62adc6d613fa8d94c30599fffbb040f8"
      },
      "detected_at": "2026-10-19T21:33:01.399119+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x6fd18",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x161c18",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "08e7c04e22c51313e5095f2db39e11fcc59adf56a63481ae92d8730e2788edc7",
      "sample_md5": "72cab11554eeb0f9dc3a3cfe912bfdde",
      "sample_name": "08e7c04e22c51313e5095f2db39e11fcc59adf56a63481ae92d8730e2788edc7.macho",
      "sample_size_bytes": 1938912,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-19 13:25:02",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 18,
        "total_engines": 62,
        "detection_ratio": "18/62",
        "suggested_threat_label": "trojan.amos/class",
        "popular_threat_category": [
          {
            "count": 11,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "tsm6e.exe",
          "08e7c04e22c51313e5095f2db39e11fcc59adf56a63481ae92d8730e2788edc7.macho",
          ".hk3ug2dm",
          "brznb9xd.exe",
          "macho_08e7c04e22c5.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "arm",
          "macho",
          "multi-arch",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "PUA:Win32/Puwaders.C!ml",
          "Kaspersky": "UDS:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KV trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/08e7c04e22c51313e5095f2db39e11fcc59adf56a63481ae92d8730e2788edc7"
      },
      "detected_at": "2026-10-19T21:33:01.399119+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x67a28",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x144e94",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "225f89ad501a71af48f405b6c61309a6c0f041ad8add6625e75274c536954f1f",
      "sample_md5": "14b94a9e23588f8ff09afdf863ed137c",
      "sample_name": "225f89ad501a71af48f405b6c61309a6c0f041ad8add6625e75274c536954f1f.macho",
      "sample_size_bytes": 1792064,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-19 09:44:57",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "loader",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 21,
        "total_engines": 63,
        "detection_ratio": "21/63",
        "suggested_threat_label": "trojan.amos/class",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 14
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "2q54olpqg.exe",
          "225f89ad501a71af48f405b6c61309a6c0f041ad8add6625e75274c536954f1f.macho",
          "pf9pknzw8.exe",
          "macho_225f89ad501a.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "self-signed",
          "macho",
          "arm",
          "multi-arch"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.C!ml",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/225f89ad501a71af48f405b6c61309a6c0f041ad8add6625e75274c536954f1f"
      },
      "detected_at": "2026-10-19T21:33:01.399119+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x5ba78",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x132808",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "ab5b9b53b603bc5bc8abb0eb0aab014d82d20b603b40fdc69642b5b907fcea43",
      "sample_md5": "0075c3ce073439c4df399b0860dea785",
      "sample_name": "ab5b9b53b603bc5bc8abb0eb0aab014d82d20b603b40fdc69642b5b907fcea43.macho",
      "sample_size_bytes": 1725184,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-19 09:35:24",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "loader",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 21,
        "total_engines": 63,
        "detection_ratio": "21/63",
        "suggested_threat_label": "trojan.amos/class",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 14
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "l0a7o.exe",
          "ab5b9b53b603bc5bc8abb0eb0aab014d82d20b603b40fdc69642b5b907fcea43.macho",
          "k55oryj.exe",
          "macho_ab5b9b53b603.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "multi-arch",
          "arm",
          "64bits",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/ab5b9b53b603bc5bc8abb0eb0aab014d82d20b603b40fdc69642b5b907fcea43"
      },
      "detected_at": "2026-10-19T21:33:01.399119+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "OSX_Foxveil_AMOS_Stage4_Generic",
      "platform": "macos",
      "namespace": "macos_stealer",
      "tags": [],
      "meta": {
        "description": "Generic detection for Foxveil macOS Loader (AMOS / Atomic macOS Stealer Stage 4) utilizing PBKDF2 key stretching, ChaCha20-Poly1305 payload encryption, LCG stack-string decryption, and memory zeroing wipers",
        "date": "2026-09-16",
        "reference": "https://bazaar.abuse.ch/sample/841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb/",
        "malware_family": "Foxveil / AMOS (Atomic macOS Stealer)",
        "threat_type": "Dropper / Loader / InfoStealer"
      },
      "matched_strings": [
        {
          "offset": "0x1f5adc",
          "identifier": "$id_pattern",
          "data_preview": "setup-555549445f14d851c0d138df80c8a8be4f09fd96"
        },
        {
          "offset": "0x3f8aec",
          "identifier": "$id_pattern",
          "data_preview": "setup-555549445f14d851c0d138df80c8a8be4f09fd96"
        },
        {
          "offset": "0x20400c",
          "identifier": "$hmac_consts_arm64",
          "data_preview": "c0 e6 01 4f aa 23 03 d1 81 e7 02 4f"
        },
        {
          "offset": "0x1f5120",
          "identifier": "$sym_chkstk",
          "data_preview": "____chkstk_darwin"
        },
        {
          "offset": "0x1f584b",
          "identifier": "$sym_chkstk",
          "data_preview": "____chkstk_darwin"
        }
      ],
      "sample_sha256": "8e9dd132e044d2d44ef09c4bcce1ab64f089100a7c6414c9b8d0c95c57cabcd0",
      "sample_md5": "083ccc0d4fe17c01a58098d5d402bdd6",
      "sample_name": "8e9dd132e044d2d44ef09c4bcce1ab64f089100a7c6414c9b8d0c95c57cabcd0.macho",
      "sample_size_bytes": 4186528,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-05-24 07:17:34",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "ClickFix",
          "machO",
          "macOS",
          "OSX"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 32,
        "total_engines": 63,
        "detection_ratio": "32/63",
        "suggested_threat_label": "trojan.amos/infostl",
        "popular_threat_category": [
          {
            "count": 18,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "8e9dd132e044d2d44ef09c4bcce1ab64f089100a7c6414c9b8d0c95c57cabcd0.macho",
          "_8e9dd132e044d2d44ef09c4bcce1ab64f089100a7c6414c9b8d0c95c57cabcd0",
          "update"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "64bits",
          "multi-arch",
          "arm",
          "signed",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "Sophos": "OSX/InfoStl-HA",
          "ESET-NOD32": "OSX/PSW.Agent.IG trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/8e9dd132e044d2d44ef09c4bcce1ab64f089100a7c6414c9b8d0c95c57cabcd0"
      },
      "detected_at": "2026-10-19T21:33:01.399119+00:00",
      "last_seen_at": "2026-10-20T18:52:09.961170+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x5e618",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x136a10",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "bc0bde5dd5ca313436bc7119c5f603d9f4fb99dcbb09b2eaa5fd7ccda2c33794",
      "sample_md5": "72a18c68a470e598362c5e1c8bee1163",
      "sample_name": "bc0bde5dd5ca313436bc7119c5f603d9f4fb99dcbb09b2eaa5fd7ccda2c33794.macho",
      "sample_size_bytes": 1774768,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-20 06:22:08",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 23,
        "total_engines": 63,
        "detection_ratio": "23/63",
        "suggested_threat_label": "trojan.amos/class",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 15
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "bc0bde5dd5ca313436bc7119c5f603d9f4fb99dcbb09b2eaa5fd7ccda2c33794.macho",
          "7erx2shd5.exe",
          "macho_bc0bde5dd5ca.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "64bits",
          "multi-arch",
          "self-signed",
          "arm"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/bc0bde5dd5ca313436bc7119c5f603d9f4fb99dcbb09b2eaa5fd7ccda2c33794"
      },
      "detected_at": "2026-10-20T08:26:32.598064+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x6e338",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x14c390",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "9d0c0819b915625b6c7bc2898cb5f1248df6ab941ce86447c059c4d6de5e0002",
      "sample_md5": "3d7b6af2acd15e52747f1fd068f7dc22",
      "sample_name": "9d0c0819b915625b6c7bc2898cb5f1248df6ab941ce86447c059c4d6de5e0002.macho",
      "sample_size_bytes": 1791744,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-20 04:51:47",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 24,
        "total_engines": 63,
        "detection_ratio": "24/63",
        "suggested_threat_label": "trojan.amos/infostl",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 14
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "9d0c0819b915625b6c7bc2898cb5f1248df6ab941ce86447c059c4d6de5e0002.macho",
          "3fwmu08f.exe",
          "macho_9d0c0819b915.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "multi-arch",
          "self-signed",
          "64bits",
          "arm",
          "macho"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "Sophos": "OSX/InfoStl-IP",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/9d0c0819b915625b6c7bc2898cb5f1248df6ab941ce86447c059c4d6de5e0002"
      },
      "detected_at": "2026-10-20T08:26:32.598064+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x77618",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x165bb8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "1b317f7c91282bc41153d12a28a41a883eeb655c245e76f8c3142a8cc8458bb4",
      "sample_md5": "9e0a8bad8a3694f5abdb816b5227ddae",
      "sample_name": "1b317f7c91282bc41153d12a28a41a883eeb655c245e76f8c3142a8cc8458bb4.macho",
      "sample_size_bytes": 1922800,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-20 04:51:21",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 24,
        "total_engines": 63,
        "detection_ratio": "24/63",
        "suggested_threat_label": "trojan.amos/infostl",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 14
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "1b317f7c91282bc41153d12a28a41a883eeb655c245e76f8c3142a8cc8458bb4.macho",
          "hseqb2y.exe",
          "macho_1b317f7c9128.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "arm",
          "multi-arch",
          "macho",
          "self-signed"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "Sophos": "OSX/InfoStl-IP",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/1b317f7c91282bc41153d12a28a41a883eeb655c245e76f8c3142a8cc8458bb4"
      },
      "detected_at": "2026-10-20T08:26:32.598064+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x67158",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x14f7f8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "863ea1012d1379896cba11f581f4a8e8c86143297f5cdf4c432a8d652a717107",
      "sample_md5": "98ff3b141ccf61fc6c6c2dd3fa999687",
      "sample_name": "863ea1012d1379896cba11f581f4a8e8c86143297f5cdf4c432a8d652a717107.macho",
      "sample_size_bytes": 1889472,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-20 01:41:23",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 19,
        "total_engines": 62,
        "detection_ratio": "19/62",
        "suggested_threat_label": "trojan.amos/class",
        "popular_threat_category": [
          {
            "count": 13,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "863ea1012d1379896cba11f581f4a8e8c86143297f5cdf4c432a8d652a717107.macho",
          "jtlh682x.exe",
          "2y5r1.exe",
          "sl3lpebel.exe",
          "macho_863ea1012d13.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "64bits",
          "multi-arch",
          "macho",
          "self-signed"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.C!ml",
          "Kaspersky": "UDS:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/863ea1012d1379896cba11f581f4a8e8c86143297f5cdf4c432a8d652a717107"
      },
      "detected_at": "2026-10-20T08:26:32.598064+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x748c8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x151268",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "ac4484f6139484fd0099d9fa54d6feebb91c26418f4e7aed9eba6185da58b7d4",
      "sample_md5": "fa5f9c4518e840a3068ee494ee81a57d",
      "sample_name": "ac4484f6139484fd0099d9fa54d6feebb91c26418f4e7aed9eba6185da58b7d4.macho",
      "sample_size_bytes": 1823856,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-20 01:15:46",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "ClickFix",
          "Foxveil",
          "loader",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 15,
        "total_engines": 60,
        "detection_ratio": "15/60",
        "suggested_threat_label": "trojan.amos/class",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 11
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "ac4484f6139484fd0099d9fa54d6feebb91c26418f4e7aed9eba6185da58b7d4.macho",
          "it3luqa.exe",
          "macho_ac4484f61394.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "arm",
          "multi-arch",
          "64bits",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Kaspersky": "UDS:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/ac4484f6139484fd0099d9fa54d6feebb91c26418f4e7aed9eba6185da58b7d4"
      },
      "detected_at": "2026-10-20T08:26:32.598064+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x67108",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x14f6d8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "706c3b12e8be63504ef14663eb7084a2d14587419166918f2fe32cfe55d78ee8",
      "sample_md5": "c02228664f0a5020b5312356efc52be0",
      "sample_name": "706c3b12e8be63504ef14663eb7084a2d14587419166918f2fe32cfe55d78ee8.macho",
      "sample_size_bytes": 1889984,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-20 01:08:30",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "loader",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 17,
        "total_engines": 60,
        "detection_ratio": "17/60",
        "suggested_threat_label": "trojan.amos/class",
        "popular_threat_category": [
          {
            "count": 11,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "706c3b12e8be63504ef14663eb7084a2d14587419166918f2fe32cfe55d78ee8.macho",
          "33vknr.exe",
          "d4adugrw0.exe",
          "dijn12z.exe",
          "macho_706c3b12e8be.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "self-signed",
          "64bits",
          "arm",
          "multi-arch"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Kaspersky": "UDS:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/706c3b12e8be63504ef14663eb7084a2d14587419166918f2fe32cfe55d78ee8"
      },
      "detected_at": "2026-10-20T08:26:32.598064+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x6dbf8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x15ac20",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "f59d0a5f63972619bb2c5184cecbe7d4fc59d5e291ede27ba13acbe49dab839b",
      "sample_md5": "1921647f5e5b4eb1fd0abd4db5c5c2c4",
      "sample_name": "f59d0a5f63972619bb2c5184cecbe7d4fc59d5e291ede27ba13acbe49dab839b.macho",
      "sample_size_bytes": 1922448,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-20 01:05:54",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "loader",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 18,
        "total_engines": 63,
        "detection_ratio": "18/63",
        "suggested_threat_label": "trojan.amos/class",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 11
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "f59d0a5f63972619bb2c5184cecbe7d4fc59d5e291ede27ba13acbe49dab839b.macho",
          "gfii3.exe",
          "macho_f59d0a5f6397.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "multi-arch",
          "self-signed",
          "macho",
          "64bits"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Phonzy.B!ml",
          "Kaspersky": "UDS:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/f59d0a5f63972619bb2c5184cecbe7d4fc59d5e291ede27ba13acbe49dab839b"
      },
      "detected_at": "2026-10-20T08:26:32.598064+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x5b5b8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x135fc8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "407902441438f0f73a0ce5f5b89f50f9b6fcf7551a6179617fa21efac1cd524f",
      "sample_md5": "a1f5c2963675b9b24a1b505e62d199f1",
      "sample_name": "407902441438f0f73a0ce5f5b89f50f9b6fcf7551a6179617fa21efac1cd524f.macho",
      "sample_size_bytes": 1774880,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-20 01:02:03",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "loader",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 25,
        "total_engines": 63,
        "detection_ratio": "25/63",
        "suggested_threat_label": "trojan.abtrojan/amos",
        "popular_threat_category": [
          {
            "count": 15,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "407902441438f0f73a0ce5f5b89f50f9b6fcf7551a6179617fa21efac1cd524f.macho",
          "krnbyk1vl.exe",
          "macho_407902441438.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "64bits",
          "multi-arch",
          "arm",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/407902441438f0f73a0ce5f5b89f50f9b6fcf7551a6179617fa21efac1cd524f"
      },
      "detected_at": "2026-10-20T08:26:32.598064+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x7dcf8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x165420",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "2d6f829d87773207cabc9360f8aae81adcf838829be00b0b6040fb7ebccf393e",
      "sample_md5": "784f388fb5f3cdac2396d695ec71f3f0",
      "sample_name": "2d6f829d87773207cabc9360f8aae81adcf838829be00b0b6040fb7ebccf393e.macho",
      "sample_size_bytes": 1890016,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-20 00:59:32",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "loader",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 26,
        "total_engines": 63,
        "detection_ratio": "26/63",
        "suggested_threat_label": "trojan.amos/infostl",
        "popular_threat_category": [
          {
            "count": 14,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "2d6f829d87773207cabc9360f8aae81adcf838829be00b0b6040fb7ebccf393e.macho",
          "y49pfx.exe",
          "macho_2d6f829d8777.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "multi-arch",
          "arm",
          "64bits",
          "self-signed",
          "macho"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "Sophos": "OSX/InfoStl-IP",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/2d6f829d87773207cabc9360f8aae81adcf838829be00b0b6040fb7ebccf393e"
      },
      "detected_at": "2026-10-20T08:26:32.598064+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x672c8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x13ca88",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "2f4b6d386a70eea4d5aaa951b8a9095095410cef0963b4a769aa9cc4b7e356a0",
      "sample_md5": "ef9aac625fb96c6c5dfa9d9c5436c303",
      "sample_name": "2f4b6d386a70eea4d5aaa951b8a9095095410cef0963b4a769aa9cc4b7e356a0.macho",
      "sample_size_bytes": 1758672,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-20 00:56:42",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "loader",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 19,
        "total_engines": 62,
        "detection_ratio": "19/62",
        "suggested_threat_label": "trojan.amos/class",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 12
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "2f4b6d386a70eea4d5aaa951b8a9095095410cef0963b4a769aa9cc4b7e356a0.macho",
          "xe2q9udb.exe",
          "macho_2f4b6d386a70.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "multi-arch",
          "arm",
          "macho",
          "self-signed"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Kaspersky": "UDS:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/2f4b6d386a70eea4d5aaa951b8a9095095410cef0963b4a769aa9cc4b7e356a0"
      },
      "detected_at": "2026-10-20T08:26:32.598064+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x608f8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x133ed0",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "1e7cc2bd060683795a7bfa0ee3610e6b896c71ad20677b65ccde4278594911f9",
      "sample_md5": "9ba266b4a8265a4011510aaad2c35d61",
      "sample_name": "1e7cc2bd060683795a7bfa0ee3610e6b896c71ad20677b65ccde4278594911f9.macho",
      "sample_size_bytes": 1741888,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-19 22:24:43",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 25,
        "total_engines": 62,
        "detection_ratio": "25/62",
        "suggested_threat_label": "trojan.abtrojan/adlsb4",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 16
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "n9autrs.exe",
          "1e7cc2bd060683795a7bfa0ee3610e6b896c71ad20677b65ccde4278594911f9.macho",
          "g0dhgv.exe",
          "macho_1e7cc2bd0606.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "arm",
          "multi-arch",
          "64bits",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Kaspersky": "HEUR:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/1e7cc2bd060683795a7bfa0ee3610e6b896c71ad20677b65ccde4278594911f9"
      },
      "detected_at": "2026-10-20T08:26:32.598064+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x7a578",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x17602c",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "2ff0a9594923b8896910fd338b4a899649bb89bca20ace4d00b9fada9da93441",
      "sample_md5": "b64078a1e045f8cadb0e24bf28a55eb1",
      "sample_name": "2ff0a9594923b8896910fd338b4a899649bb89bca20ace4d00b9fada9da93441.macho",
      "sample_size_bytes": 2020304,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-20 17:27:17",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 22,
        "total_engines": 63,
        "detection_ratio": "22/63",
        "suggested_threat_label": "trojan.infostl/amos",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 12
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "2ff0a9594923b8896910fd338b4a899649bb89bca20ace4d00b9fada9da93441.macho",
          ".hy0tpp",
          "18ws0su.exe",
          "macho_2ff0a9594923.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "self-signed",
          "arm",
          "multi-arch",
          "macho",
          "64bits"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Kaspersky": "UDS:Trojan-PSW.OSX.Amos.gen",
          "Sophos": "OSX/InfoStl-IP",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/2ff0a9594923b8896910fd338b4a899649bb89bca20ace4d00b9fada9da93441"
      },
      "detected_at": "2026-10-20T18:52:09.961170+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x7caf8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x17fd78",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "89ab3b9e84198d8bb8d207964ee8cc02d75da3d6bdbd9cf1ccf34f9500272053",
      "sample_md5": "faa6e6767f7545b56152e8fc34a8ce36",
      "sample_name": "89ab3b9e84198d8bb8d207964ee8cc02d75da3d6bdbd9cf1ccf34f9500272053.macho",
      "sample_size_bytes": 2086512,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-20 12:24:18",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 10,
        "total_engines": 63,
        "detection_ratio": "10/63",
        "suggested_threat_label": "trojan.amos/najl",
        "popular_threat_category": [
          {
            "count": 5,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "89ab3b9e84198d8bb8d207964ee8cc02d75da3d6bdbd9cf1ccf34f9500272053.macho",
          "fi8s5bht.exe",
          "macho_89ab3b9e8419.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "macho",
          "self-signed",
          "arm",
          "multi-arch"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Kaspersky": "UDS:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/89ab3b9e84198d8bb8d207964ee8cc02d75da3d6bdbd9cf1ccf34f9500272053"
      },
      "detected_at": "2026-10-20T18:52:09.961170+00:00",
      "last_seen_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x8b768",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x188498",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "ccdc4d7aa75140392ae4d6296c229cb456617f64b6509be93f61ca91412d9af6",
      "sample_md5": "f579f16f5022433759e7b4b87bb48e7a",
      "sample_name": "ccdc4d7aa75140392ae4d6296c229cb456617f64b6509be93f61ca91412d9af6.macho",
      "sample_size_bytes": 2086336,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-22 07:17:50",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "ClickFix",
          "Foxveil",
          "loader",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 8,
        "total_engines": 63,
        "detection_ratio": "8/63",
        "suggested_threat_label": "trojan.lcnw",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 4
          }
        ],
        "names": [
          "ccdc4d7aa75140392ae4d6296c229cb456617f64b6509be93f61ca91412d9af6.macho",
          "gvxapk.exe",
          "macho_ccdc4d7aa751.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "64bits",
          "multi-arch",
          "arm",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/ccdc4d7aa75140392ae4d6296c229cb456617f64b6509be93f61ca91412d9af6"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x79238",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x16fd28",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "1b9ebec7a73d0a7c135f71904fef98602fa5ff49d137bb145608da207541c15b",
      "sample_md5": "a2dd43b96e8b490e604fb13d12b6847a",
      "sample_name": "1b9ebec7a73d0a7c135f71904fef98602fa5ff49d137bb145608da207541c15b.macho",
      "sample_size_bytes": 1988048,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-22 02:58:48",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 14,
        "total_engines": 63,
        "detection_ratio": "14/63",
        "suggested_threat_label": "trojan.infostealer/infostl",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 6
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "u316hon7f.exe",
          "macho_1b9ebec7a73d.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "multi-arch",
          "macho",
          "self-signed",
          "64bits"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Infostealer.MK!MTB",
          "Sophos": "OSX/InfoStl-IP",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/1b9ebec7a73d0a7c135f71904fef98602fa5ff49d137bb145608da207541c15b"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x6c518",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x14d338",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "c81b8c0775f0fa25cfe09cab180e88426340cd1e171c033cd70145294504fefd",
      "sample_md5": "99751c3133aea87f02e527a5c05b438a",
      "sample_name": "c81b8c0775f0fa25cfe09cab180e88426340cd1e171c033cd70145294504fefd.macho",
      "sample_size_bytes": 1824368,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-22 01:23:12",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 13,
        "total_engines": 63,
        "detection_ratio": "13/63",
        "suggested_threat_label": "trojan.infostealer/abtrojan",
        "popular_threat_category": [
          {
            "count": 5,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "xz1dpea.exe",
          "macho_c81b8c0775f0.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "64bits",
          "arm",
          "self-signed",
          "multi-arch"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Infostealer.MK!MTB",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/c81b8c0775f0fa25cfe09cab180e88426340cd1e171c033cd70145294504fefd"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x72398",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x14855c",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "66bb0add8962b6b2cf5bb3358e6777a421b54968674d838d7ccd2d3a6da555a0",
      "sample_md5": "86571315d4df1fc270c79d45985c7b6f",
      "sample_name": "66bb0add8962b6b2cf5bb3358e6777a421b54968674d838d7ccd2d3a6da555a0.macho",
      "sample_size_bytes": 1775072,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-22 00:57:52",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "ClickFix",
          "Foxveil",
          "loader",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 12,
        "total_engines": 63,
        "detection_ratio": "12/63",
        "suggested_threat_label": "trojan.sgil",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 5
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "esg1otxqs.exe",
          "macho_66bb0add8962.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "arm",
          "64bits",
          "self-signed",
          "multi-arch"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.C!ml",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/66bb0add8962b6b2cf5bb3358e6777a421b54968674d838d7ccd2d3a6da555a0"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x8e6f8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x18f81c",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "44306aa41505302c109d90a5c85c68541b98bf783cb47af912a55b4d5a3dcc99",
      "sample_md5": "f78d4d23e46f87ac679226d72d2b01f8",
      "sample_name": "44306aa41505302c109d90a5c85c68541b98bf783cb47af912a55b4d5a3dcc99.macho",
      "sample_size_bytes": 2069648,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-22 00:52:25",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "ClickFix",
          "Foxveil",
          "loader",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 8,
        "total_engines": 60,
        "detection_ratio": "8/60",
        "suggested_threat_label": "trojan.",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 3
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "3gr6elgn.exe",
          "macho_44306aa41505.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "64bits",
          "service-scan",
          "multi-arch",
          "macho",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/44306aa41505302c109d90a5c85c68541b98bf783cb47af912a55b4d5a3dcc99"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x88d98",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x18895c",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "b626c19713c716a0bc5a49d801300eaade449cec525012a35a6477295b6729a4",
      "sample_md5": "8748ded672c1c6c0522a105babba1e63",
      "sample_name": "b626c19713c716a0bc5a49d801300eaade449cec525012a35a6477295b6729a4.macho",
      "sample_size_bytes": 2086256,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-22 00:49:29",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "ClickFix",
          "Foxveil",
          "loader",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 12,
        "total_engines": 63,
        "detection_ratio": "12/63",
        "suggested_threat_label": "trojan.infostl",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 4
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "owdka.exe",
          "macho_b626c19713c7.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "multi-arch",
          "self-signed",
          "macho",
          "64bits",
          "arm"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.C!ml",
          "Sophos": "OSX/InfoStl-IP",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/b626c19713c716a0bc5a49d801300eaade449cec525012a35a6477295b6729a4"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x6e088",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x14689c",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "9edd2a4e7ce79550637ab4dd1dec171087dcf7313547e0935d64725101140a9b",
      "sample_md5": "8f2d4da3b0b570558b9df34b82359571",
      "sample_name": "9edd2a4e7ce79550637ab4dd1dec171087dcf7313547e0935d64725101140a9b.macho",
      "sample_size_bytes": 1758960,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-22 00:45:36",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "ClickFix",
          "Foxveil",
          "loader",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 10,
        "total_engines": 63,
        "detection_ratio": "10/63",
        "suggested_threat_label": "trojan.tnkl",
        "popular_threat_category": [
          {
            "count": 5,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "1i5yh90y.exe",
          "macho_9edd2a4e7ce7.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "macho",
          "arm",
          "multi-arch",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.C!ml",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/9edd2a4e7ce79550637ab4dd1dec171087dcf7313547e0935d64725101140a9b"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x5f628",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x136a28",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "aeea0651716d990d527a48473e7b54cd56849aee87b8916294c8f2ae81831617",
      "sample_md5": "31167b77df99f65225bfe2a8c7e8c41b",
      "sample_name": "aeea0651716d990d527a48473e7b54cd56849aee87b8916294c8f2ae81831617.macho",
      "sample_size_bytes": 1741248,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-22 00:41:49",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "ClickFix",
          "Foxveil",
          "loader",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 11,
        "total_engines": 63,
        "detection_ratio": "11/63",
        "suggested_threat_label": "trojan.vimw",
        "popular_threat_category": [
          {
            "count": 5,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "4xecr.exe",
          "macho_aeea0651716d.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "64bits",
          "arm",
          "self-signed",
          "multi-arch"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/aeea0651716d990d527a48473e7b54cd56849aee87b8916294c8f2ae81831617"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x78338",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x169f18",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "932761c3c90d8db72e53b5e2cbf5f86eee95e15be50e0a4dab91d6e16b33cbd8",
      "sample_md5": "fc94684bfce74110e7f40ce13e1ef6af",
      "sample_name": "932761c3c90d8db72e53b5e2cbf5f86eee95e15be50e0a4dab91d6e16b33cbd8.macho",
      "sample_size_bytes": 1971680,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-22 00:36:54",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "ClickFix",
          "Foxveil",
          "loader",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 15,
        "total_engines": 63,
        "detection_ratio": "15/63",
        "suggested_threat_label": "trojan.infostl/abapplication",
        "popular_threat_category": [
          {
            "count": 5,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "mws9g204w.exe",
          ".cid9mtl.$$"
        ],
        "type_description": "Mach-O",
        "tags": [
          "self-signed",
          "64bits",
          "multi-arch",
          "macho",
          "arm"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Sophos": "OSX/InfoStl-IP",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/932761c3c90d8db72e53b5e2cbf5f86eee95e15be50e0a4dab91d6e16b33cbd8"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x88498",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x1814ac",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "94521a0d9d77513864171e00075b46b5bededbd849efe056687d8494353815d4",
      "sample_md5": "98e393cf07ff6a280e03a46e60e186d2",
      "sample_name": "94521a0d9d77513864171e00075b46b5bededbd849efe056687d8494353815d4.macho",
      "sample_size_bytes": 2053664,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-22 00:34:43",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "ClickFix",
          "Foxveil",
          "loader",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 13,
        "total_engines": 62,
        "detection_ratio": "13/62",
        "suggested_threat_label": "trojan.infostl/ekjl",
        "popular_threat_category": [
          {
            "count": 5,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "5za9iv7l.exe",
          "macho_94521a0d9d77.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "self-signed",
          "multi-arch",
          "64bits",
          "arm",
          "macho"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.C!ml",
          "Sophos": "OSX/InfoStl-IP",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/94521a0d9d77513864171e00075b46b5bededbd849efe056687d8494353815d4"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x8df68",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x1875a8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "805a8575437df0241e4f24d3c3d377e7dbcb42924ad9e41664bd0bc7dc26ed9d",
      "sample_md5": "f3e681b1e114800a54db03ba9243a36f",
      "sample_name": "805a8575437df0241e4f24d3c3d377e7dbcb42924ad9e41664bd0bc7dc26ed9d.macho",
      "sample_size_bytes": 2070144,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-22 00:31:49",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "ClickFix",
          "Foxveil",
          "loader",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 9,
        "total_engines": 63,
        "detection_ratio": "9/63",
        "suggested_threat_label": "trojan.eajl",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 4
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "0gdsd.exe",
          "macho_805a8575437d.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "arm",
          "self-signed",
          "macho",
          "multi-arch"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/805a8575437df0241e4f24d3c3d377e7dbcb42924ad9e41664bd0bc7dc26ed9d"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x7bd78",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x17aa30",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "a4f89e85ca176c7fccd50335b80e9cb31887297c3e8abb879e35636ae7c6cd68",
      "sample_md5": "923096efc0834232da638e0e3b3765d2",
      "sample_name": "a4f89e85ca176c7fccd50335b80e9cb31887297c3e8abb879e35636ae7c6cd68.macho",
      "sample_size_bytes": 2053600,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-22 00:23:57",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 12,
        "total_engines": 60,
        "detection_ratio": "12/60",
        "suggested_threat_label": "trojan.infostl/gflw",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 4
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "lvuojl.exe",
          "macho_a4f89e85ca17.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "self-signed",
          "macho",
          "64bits",
          "multi-arch"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Sophos": "OSX/InfoStl-IP",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/a4f89e85ca176c7fccd50335b80e9cb31887297c3e8abb879e35636ae7c6cd68"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x64e88",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x1455a8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "bfaba22e0b58c2f5ab977de4322563fdeb3f5a90a573175181f34d4830a7fc97",
      "sample_md5": "766440502968cc9c4174d49efd9c5dcf",
      "sample_name": "bfaba22e0b58c2f5ab977de4322563fdeb3f5a90a573175181f34d4830a7fc97.macho",
      "sample_size_bytes": 1807536,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-22 00:23:06",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 10,
        "total_engines": 61,
        "detection_ratio": "10/61",
        "suggested_threat_label": "trojan.ssmw",
        "popular_threat_category": [
          {
            "count": 5,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "4he6gq.exe",
          "macho_bfaba22e0b58.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "macho",
          "multi-arch",
          "self-signed",
          "64bits"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/bfaba22e0b58c2f5ab977de4322563fdeb3f5a90a573175181f34d4830a7fc97"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0xed9d8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0xd48e0",
          "identifier": "$chacha20_const",
          "data_preview": "expand 32-byte k"
        },
        {
          "offset": "0xd48f0",
          "identifier": "$chacha20_const",
          "data_preview": "expand 32-byte k"
        },
        {
          "offset": "0xed8f0",
          "identifier": "$chacha20_const",
          "data_preview": "expand 32-byte k"
        },
        {
          "offset": "0x1c7580",
          "identifier": "$chacha20_const",
          "data_preview": "expand 32-byte k"
        }
      ],
      "sample_sha256": "d47d4a39e80e5c8c233aa4ecfe28d42f89f688a96421ad68baaf4bd5a4c81b31",
      "sample_md5": "edf9dc78213bb0d98d721f9eb55330a2",
      "sample_name": "d47d4a39e80e5c8c233aa4ecfe28d42f89f688a96421ad68baaf4bd5a4c81b31.macho",
      "sample_size_bytes": 1927616,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-21 19:22:59",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "ClickFix",
          "dropped-by-errtraffic",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 14,
        "total_engines": 63,
        "detection_ratio": "14/63",
        "suggested_threat_label": "trojan.mmdhlt/uimw",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 9
          }
        ],
        "names": [
          "q24nc.exe",
          "a1cy8hit.exe"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "64bits",
          "macho",
          "os-credentials",
          "self-signed",
          "multi-arch"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Kaspersky": "HEUR:Backdoor.OSX.Agent.bt",
          "ESET-NOD32": "OSX/PSW.Agent.IY trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/d47d4a39e80e5c8c233aa4ecfe28d42f89f688a96421ad68baaf4bd5a4c81b31"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0xfb698",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0xe2540",
          "identifier": "$chacha20_const",
          "data_preview": "expand 32-byte k"
        },
        {
          "offset": "0xe2550",
          "identifier": "$chacha20_const",
          "data_preview": "expand 32-byte k"
        },
        {
          "offset": "0xfb5b0",
          "identifier": "$chacha20_const",
          "data_preview": "expand 32-byte k"
        },
        {
          "offset": "0x1e7180",
          "identifier": "$chacha20_const",
          "data_preview": "expand 32-byte k"
        }
      ],
      "sample_sha256": "621ed067e8214758b584df19b7f9726559d32af16267e6217f878d0b96378a29",
      "sample_md5": "6445defffb42cc06ea71c8fe763fe2d5",
      "sample_name": "621ed067e8214758b584df19b7f9726559d32af16267e6217f878d0b96378a29.macho",
      "sample_size_bytes": 2060944,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-21 18:12:13",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "ClickFix",
          "dropped-by-errtraffic",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 7,
        "total_engines": 59,
        "detection_ratio": "7/59",
        "suggested_threat_label": "trojan.ogil",
        "popular_threat_category": [
          {
            "count": 7,
            "value": "trojan"
          }
        ],
        "names": [
          "49uvir.exe"
        ],
        "type_description": "Mach-O",
        "tags": [
          "multi-arch",
          "macho",
          "64bits",
          "arm",
          "os-credentials",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Kaspersky": "HEUR:Backdoor.OSX.Agent.bt",
          "ESET-NOD32": "OSX/PSW.Agent.IY trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/621ed067e8214758b584df19b7f9726559d32af16267e6217f878d0b96378a29"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x7b5f8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x166f10",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "c6dcafd1aaa7cdbf84e2cc6f1f6b3e6cc6a7c1b74ab995003a5d6f828cdf1268",
      "sample_md5": "da0384cb490b2e8f900e24db60f5bfba",
      "sample_name": "c6dcafd1aaa7cdbf84e2cc6f1f6b3e6cc6a7c1b74ab995003a5d6f828cdf1268.macho",
      "sample_size_bytes": 1905712,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-21 14:04:07",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "loader",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 20,
        "total_engines": 63,
        "detection_ratio": "20/63",
        "suggested_threat_label": "trojan.infostl/abapplication",
        "popular_threat_category": [
          {
            "count": 9,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "t3hk9.exe",
          "macho_c6dcafd1aaa7.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "self-signed",
          "multi-arch",
          "64bits",
          "macho"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Sophos": "OSX/InfoStl-IP",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/c6dcafd1aaa7cdbf84e2cc6f1f6b3e6cc6a7c1b74ab995003a5d6f828cdf1268"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x82cf8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x1838a8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "30b4ae5036e76367f9d1165253dc81d4c7ae9fdced72c95cb4ecffc1f6aefcfd",
      "sample_md5": "5d6a9189fff6a91641ec52871ebc883c",
      "sample_name": "30b4ae5036e76367f9d1165253dc81d4c7ae9fdced72c95cb4ecffc1f6aefcfd.macho",
      "sample_size_bytes": 2085664,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-21 13:30:21",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 18,
        "total_engines": 63,
        "detection_ratio": "18/63",
        "suggested_threat_label": "trojan.infostl/class",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 10
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "vtudje4.exe",
          "macho_30b4ae5036e7.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "multi-arch",
          "macho",
          "64bits",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Sophos": "OSX/InfoStl-IP",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/30b4ae5036e76367f9d1165253dc81d4c7ae9fdced72c95cb4ecffc1f6aefcfd"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0xfb698",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0xe2540",
          "identifier": "$chacha20_const",
          "data_preview": "expand 32-byte k"
        },
        {
          "offset": "0xe2550",
          "identifier": "$chacha20_const",
          "data_preview": "expand 32-byte k"
        },
        {
          "offset": "0xfb5b0",
          "identifier": "$chacha20_const",
          "data_preview": "expand 32-byte k"
        },
        {
          "offset": "0x1e7180",
          "identifier": "$chacha20_const",
          "data_preview": "expand 32-byte k"
        }
      ],
      "sample_sha256": "7a3e4f6ac3d726df49bad8f9a1c00bd75a57341238a1be9dac90be5b50b3385c",
      "sample_md5": "16202a62f7de1b413380fc6ab06ed7ad",
      "sample_name": "7a3e4f6ac3d726df49bad8f9a1c00bd75a57341238a1be9dac90be5b50b3385c.macho",
      "sample_size_bytes": 2060944,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-21 12:11:48",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "ClickFix",
          "dropped-by-errtraffic",
          "ErrTraffic",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 10,
        "total_engines": 63,
        "detection_ratio": "10/63",
        "suggested_threat_label": "trojan.abbackdoor/siuj",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 5
          }
        ],
        "names": [
          "0yghm8.exe"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "multi-arch",
          "64bits",
          "self-signed",
          "arm",
          "os-credentials"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Kaspersky": "HEUR:Backdoor.OSX.Agent.bt",
          "ESET-NOD32": "OSX/PSW.Agent.IY trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/7a3e4f6ac3d726df49bad8f9a1c00bd75a57341238a1be9dac90be5b50b3385c"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x803b8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x16fbd8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "1d6102cbdf119cd3655d9beb30698a97ab69d996f2a1b913c0bd95b32076d2ac",
      "sample_md5": "ce4decbfd9327bc6cd070f747bcaf23b",
      "sample_name": "1d6102cbdf119cd3655d9beb30698a97ab69d996f2a1b913c0bd95b32076d2ac.macho",
      "sample_size_bytes": 1971696,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-21 11:29:26",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 18,
        "total_engines": 63,
        "detection_ratio": "18/63",
        "suggested_threat_label": "trojan.infostl/abpws",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 6
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          ".qm5lh",
          "53um8y.exe",
          "macho_1d6102cbdf11.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "multi-arch",
          "64bits",
          "self-signed",
          "macho"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Program:Script/Wacapew.A!ml",
          "Sophos": "OSX/InfoStl-IP",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/1d6102cbdf119cd3655d9beb30698a97ab69d996f2a1b913c0bd95b32076d2ac"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x73278",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x165190",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "461f5d168c724db1094e76955ce5ebe15ea611d7d0b497c5f06ffb0baffa10c8",
      "sample_md5": "45de872f98e59054bb066be9675b90e7",
      "sample_name": "461f5d168c724db1094e76955ce5ebe15ea611d7d0b497c5f06ffb0baffa10c8.macho",
      "sample_size_bytes": 1954464,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-21 10:23:21",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 23,
        "total_engines": 62,
        "detection_ratio": "23/62",
        "suggested_threat_label": "trojan.infostl/abtrojan",
        "popular_threat_category": [
          {
            "count": 13,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "ff13o2.exe",
          "macho_461f5d168c72.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "macho",
          "64bits",
          "self-signed",
          "multi-arch"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:MacOS/Multiverze!rfn",
          "Sophos": "OSX/InfoStl-IP",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/461f5d168c724db1094e76955ce5ebe15ea611d7d0b497c5f06ffb0baffa10c8"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x74188",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x15a5bc",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "68b736e2aa1c565c1748fcb17a5e44bbf1727714047fbf50e8c9c9d6844fe6ea",
      "sample_md5": "ad2b4aa030707fc73e68aeda390210ed",
      "sample_name": "68b736e2aa1c565c1748fcb17a5e44bbf1727714047fbf50e8c9c9d6844fe6ea.macho",
      "sample_size_bytes": 1856160,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-21 05:49:13",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 21,
        "total_engines": 63,
        "detection_ratio": "21/63",
        "suggested_threat_label": "trojan.infostl/amos",
        "popular_threat_category": [
          {
            "count": 13,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "atwlfuokk.exe",
          "macho_68b736e2aa1c.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "self-signed",
          "64bits",
          "arm",
          "multi-arch"
        ],
        "reputation": -11,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Sophos": "OSX/InfoStl-IP",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/68b736e2aa1c565c1748fcb17a5e44bbf1727714047fbf50e8c9c9d6844fe6ea"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x5d428",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x137ff0",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "6e7dcc1716e5a94f937f66f0796d10280abe40a11f13d2a258784468de71c478",
      "sample_md5": "cdfdd768a2a0dac1a10c34b3d9825290",
      "sample_name": "6e7dcc1716e5a94f937f66f0796d10280abe40a11f13d2a258784468de71c478.macho",
      "sample_size_bytes": 1790960,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-21 00:35:26",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 15,
        "total_engines": 63,
        "detection_ratio": "15/63",
        "suggested_threat_label": "trojan.amos/fkjl",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 8
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "i0wi3.exe",
          "macho_6e7dcc1716e5.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "macho",
          "multi-arch",
          "arm",
          "64bits",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Kaspersky": "UDS:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/6e7dcc1716e5a94f937f66f0796d10280abe40a11f13d2a258784468de71c478"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x70bf8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x14b818",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "8a2daf154b45503f88abb0f9f77ba79ad4044f235f03c2a1ff5604bc9ef1c227",
      "sample_md5": "72d3d15841f06ec1551dd841b8eb74cd",
      "sample_name": "8a2daf154b45503f88abb0f9f77ba79ad4044f235f03c2a1ff5604bc9ef1c227.macho",
      "sample_size_bytes": 1807824,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-21 00:33:59",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 15,
        "total_engines": 63,
        "detection_ratio": "15/63",
        "suggested_threat_label": "trojan.amos/gb0tgg",
        "popular_threat_category": [
          {
            "count": 8,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "cefgvwb7.exe",
          "macho_8a2daf154b45.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "macho",
          "multi-arch",
          "arm",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Kaspersky": "UDS:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/8a2daf154b45503f88abb0f9f77ba79ad4044f235f03c2a1ff5604bc9ef1c227"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x89eb8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x182d08",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "4892ea6ae970b1c57b505e511ace698878b29666e0da59867b712ea83db1563b",
      "sample_md5": "7198523f1e52e9d3164e698e47d386ff",
      "sample_name": "4892ea6ae970b1c57b505e511ace698878b29666e0da59867b712ea83db1563b.macho",
      "sample_size_bytes": 2020720,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-21 00:30:25",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 17,
        "total_engines": 62,
        "detection_ratio": "17/62",
        "suggested_threat_label": "trojan.amos/abtrojan",
        "popular_threat_category": [
          {
            "count": 9,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "ys3h5pl.exe",
          "macho_4892ea6ae970.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "arm",
          "macho",
          "64bits",
          "self-signed",
          "multi-arch"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Kaspersky": "UDS:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/4892ea6ae970b1c57b505e511ace698878b29666e0da59867b712ea83db1563b"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x659f8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x141de8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "09b5143a55acbb87423681f6c70a1bbed0034289a7448becc5d3adab51fddb77",
      "sample_md5": "ad6bc5bcdf0418600f2fb6ffda299b09",
      "sample_name": "09b5143a55acbb87423681f6c70a1bbed0034289a7448becc5d3adab51fddb77.macho",
      "sample_size_bytes": 1807712,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-21 00:25:22",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 17,
        "total_engines": 63,
        "detection_ratio": "17/63",
        "suggested_threat_label": "trojan.amos/abpws",
        "popular_threat_category": [
          {
            "count": 8,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "7x9zn.exe",
          "macho_09b5143a55ac.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "64bits",
          "multi-arch",
          "self-signed",
          "macho",
          "arm"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Kaspersky": "UDS:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/09b5143a55acbb87423681f6c70a1bbed0034289a7448becc5d3adab51fddb77"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x780f8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x15ae90",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "0ef806bb25a7206b2a7ab4c936ac6aa540c4777574068d51ec3d65c9e1fb67c4",
      "sample_md5": "af5636897d1c5fd328504bc137087f04",
      "sample_name": "0ef806bb25a7206b2a7ab4c936ac6aa540c4777574068d51ec3d65c9e1fb67c4.macho",
      "sample_size_bytes": 1856912,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-21 00:11:18",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 17,
        "total_engines": 63,
        "detection_ratio": "17/63",
        "suggested_threat_label": "trojan.amos/abtrojan",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 8
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "ycwdlqg.exe",
          "macho_0ef806bb25a7.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "self-signed",
          "64bits",
          "multi-arch",
          "arm",
          "macho"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Kaspersky": "UDS:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/0ef806bb25a7206b2a7ab4c936ac6aa540c4777574068d51ec3d65c9e1fb67c4"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x68478",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x144d3c",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "66a39ad4e53d93de95c3db38822fb265dcc8835328d591edaf3bbbe5098f391f",
      "sample_md5": "146a1bd3fe055ea18383e271d587bf9a",
      "sample_name": "66a39ad4e53d93de95c3db38822fb265dcc8835328d591edaf3bbbe5098f391f.macho",
      "sample_size_bytes": 1790864,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-21 00:07:59",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Loader",
          "Mach-O",
          "machO",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 18,
        "total_engines": 63,
        "detection_ratio": "18/63",
        "suggested_threat_label": "trojan.amos/abtrojan",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 9
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "aidkjf.exe",
          "macho_66a39ad4e53d.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "multi-arch",
          "self-signed",
          "64bits",
          "macho",
          "arm"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Kaspersky": "UDS:Trojan-PSW.OSX.Amos.gen",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/66a39ad4e53d93de95c3db38822fb265dcc8835328d591edaf3bbbe5098f391f"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00",
      "last_seen_at": "2026-10-22T19:15:34.846800+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x78db8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x16801c",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "13b4b87da6046356804ccfa023d66b9809371027b00f62fb4e4812dca34a1571",
      "sample_md5": "9687b1e3773e8fe96e1f27d8fc21d798",
      "sample_name": "13b4b87da6046356804ccfa023d66b9809371027b00f62fb4e4812dca34a1571.macho",
      "sample_size_bytes": 1938224,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-20 22:39:44",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 22,
        "total_engines": 63,
        "detection_ratio": "22/63",
        "suggested_threat_label": "trojan.infostl/amos",
        "popular_threat_category": [
          {
            "count": 13,
            "value": "trojan"
          },
          {
            "count": 1,
            "value": "pua"
          }
        ],
        "names": [
          "13b4b87da6046356804ccfa023d66b9809371027b00f62fb4e4812dca34a1571.macho",
          "op8t7.exe",
          "macho_13b4b87da604.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "self-signed",
          "64bits",
          "macho",
          "multi-arch",
          "arm"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "Kaspersky": "UDS:Trojan-PSW.OSX.Amos.gen",
          "Sophos": "OSX/InfoStl-IP",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/13b4b87da6046356804ccfa023d66b9809371027b00f62fb4e4812dca34a1571"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x597b8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x12815c",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "2e5bb8cc0558dfed95e93207bdcc39dfd3ed21851d7ba1e8d56dee83088c5e66",
      "sample_md5": "c8d2b6a9e7952f049c2ef40f21f61525",
      "sample_name": "2e5bb8cc0558dfed95e93207bdcc39dfd3ed21851d7ba1e8d56dee83088c5e66.macho",
      "sample_size_bytes": 1676208,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-20 18:40:26",
        "file_type": "macho",
        "signature": "AMOS",
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "success",
        "positives": 15,
        "total_engines": 52,
        "detection_ratio": "15/52",
        "suggested_threat_label": "trojan.class/togkpj",
        "popular_threat_category": [
          {
            "value": "trojan",
            "count": 10
          },
          {
            "value": "pua",
            "count": 1
          }
        ],
        "names": [
          "2e5bb8cc0558dfed95e93207bdcc39dfd3ed21851d7ba1e8d56dee83088c5e66.macho",
          "ewydar0ca.exe",
          "macho_2e5bb8cc0558.bin"
        ],
        "type_description": "Mach-O",
        "tags": [
          "multi-arch",
          "arm",
          "macho",
          "64bits",
          "self-signed"
        ],
        "reputation": 0,
        "key_engine_detections": {
          "Microsoft": "Trojan:Script/Wacatac.B!ml",
          "ESET-NOD32": "OSX/PSW.Agent.KU trojan"
        },
        "vt_permalink": "https://www.virustotal.com/gui/file/2e5bb8cc0558dfed95e93207bdcc39dfd3ed21851d7ba1e8d56dee83088c5e66"
      },
      "detected_at": "2026-10-22T15:06:28.931817+00:00"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "namespace": "macos_macOS_ClickFix_AppleScript",
      "tags": [],
      "meta": {
        "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
        "date": "2026-08-31",
        "sample_sha256": "05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72",
        "threat_type": "Dropper / Infostealer Loader",
        "platform": "macOS",
        "confidence": "High"
      },
      "matched_strings": [
        {
          "offset": "0x0",
          "identifier": "$macho_fat_be",
          "data_preview": "ca fe ba be"
        },
        {
          "offset": "0x6f1a8",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        },
        {
          "offset": "0x14e708",
          "identifier": "$sbox",
          "data_preview": "be 85 31 24 c3 7d 0c 55 74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1 c1 69 9b e4 86 47 be ef"
        }
      ],
      "sample_sha256": "0ad481c6994048519dc317896755c1e8f6fec92e458aeaf4fa5cfa09a5126270",
      "sample_md5": "903d4e0c1ff81b07599893234116257a",
      "sample_name": "0ad481c6994048519dc317896755c1e8f6fec92e458aeaf4fa5cfa09a5126270.macho",
      "sample_size_bytes": 1806624,
      "source_feed": "MalwareBazaar",
      "mb_metadata": {
        "first_seen": "2026-10-22 17:23:41",
        "file_type": "macho",
        "signature": null,
        "tags": [
          "AMOS",
          "ClickFix",
          "Foxveil",
          "Mach-O",
          "macho",
          "macOS"
        ]
      },
      "vt_enrichment": {
        "vt_status": "not_found",
        "reason": "Sample not seen on VirusTotal yet"
      },
      "detected_at": "2026-10-22T19:15:34.846800+00:00"
    }
  ],
  "rules": [
    {
      "rule_name": "MALW_macOS_MacSync_Stealer_Universal",
      "platform": "macos",
      "file_path": "yara-rules/macos/MALW_macOS_MacSync_Stealer.yar",
      "description": "Universal multi-architecture detection for macOS MacSync Stealer (Intel x86_64 & Apple Silicon ARM64 / Universal Fat Binaries)",
      "malware_family": "MacSync",
      "author": "Unknown",
      "date": "2026-08-31",
      "severity": "Medium",
      "tags": [],
      "strings_count": 17,
      "total_hits": 7,
      "source_code": "rule MALW_macOS_MacSync_Stealer_Universal {\n    meta:\n        description = \"Universal multi-architecture detection for macOS MacSync Stealer (Intel x86_64 & Apple Silicon ARM64 / Universal Fat Binaries)\"\n        date = \"2026-08-31\"\n        family = \"MacSync\"\n        threat_type = \"Infostealer / Stager / Exfiltrator\"\n        platform = \"macOS (x86_64 & ARM64)\"\n\n    strings:\n        // XOR Modifier: Scans all 256 keys: 0x00 - 0xFF across Intel & ARM)\n        $xor_httpcode   = \"/tmp/.httpcode\" xor\n        $xor_archive    = \"/tmp/osalogging.zip\" xor\n        $xor_osascript  = \"osascript\" xor\n        $xor_curl       = \"curl -k -s\" xor\n        $xor_dd_slice   = \"dd if=\" xor\n        $xor_chunk_fmt  = \"chunk_index=\" xor\n        $xor_dynamic    = \"/dynamic?txd=\" xor\n        $xor_gate       = \"/gate?buildtxd=\" xor\n        $xor_agent      = \"CFNetwork/Darwin\" xor\n\n        // Unencrypted Format String Tokens & Compiler Artifacts\n        $fmt_sess_id    = \"%ld-%08x\" ascii wide\n        $str_obf_class  = \"ObfuscatedString\" ascii\n\n        // Multi-Architecture C++ Decryption Engine Machine Code\n        // x86_64: movsx eax, byte [reg+reg] ; xor eax, <KEY> ; mov byte [reg+reg], dl/al\n        $op_xor_x86_64  = { 0F BE ?? ?? 35 ?? 00 00 00 88 }\n\n        // POSIX Daemonization & Stream Manipulation System Imports (Identical across dyld on Intel & ARM64)\n        $imp_freopen    = \"_freopen\" ascii\n        $imp_setsid     = \"_setsid\" ascii\n        $imp_stat       = \"_stat$INODE64\" ascii\n        $imp_system     = \"_system\" ascii\n        $imp_fork       = \"_fork\" ascii\n\n    condition:\n        // Mach-O Magic Checks: Thin 64-bit/32-bit (Intel & ARM64) OR Universal Fat Binaries (FAT_MAGIC 0xCAFEBABE / FAT_MAGIC_64 0xCAFEBABF)\n        (\n            uint32(0) == 0xFEEDFACF or uint32(0) == 0xCFFAEDFE or  // Thin Mach-O 64-bit (x86_64 & ARM64)\n            uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or  // Thin Mach-O 32-bit (Legacy x86/ARM)\n            uint32(0) == 0xCAFEBABE or uint32(0) == 0xBEBAFECA or  // Universal Fat Binary (32-bit offsets)\n            uint32(0) == 0xCAFEBABF or uint32(0) == 0xBFBAFECA     // Universal Fat Binary 64-bit\n        ) and\n        filesize < 15MB and\n        (\n            // Primary Detection: Matches any 3 core behavioral strings regardless of XOR key (0x00-0xFF on Intel & ARM)\n            (3 of ($xor_*)) or\n\n            // Stripped Variant Detection: XOR loop opcodes + daemonization API imports\n            ($op_xor_x86_64 and $imp_freopen and ($imp_setsid or $imp_fork or $imp_stat)) or\n\n            // Universal Pipeline Detection: osascript pipe / dd slice + dyld execution APIs (Intel & ARM64)\n            (2 of ($xor_osascript, $xor_dd_slice, $xor_curl, $xor_gate) and $imp_system and ($imp_freopen or $imp_stat)) or\n\n            // Unstripped Variant Detection: ObfuscatedString class template + any single behavioral token\n            ($str_obf_class and (1 of ($xor_*) or $fmt_sess_id))\n        )\n}"
    },
    {
      "rule_name": "OSX_Stealer_AMOS_Generic",
      "platform": "macos",
      "file_path": "yara-rules/macos/OSX_Stealer_AMOS_Generic.yar",
      "description": "Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants",
      "malware_family": "Atomic Stealer / AMOS",
      "author": "Unknown",
      "date": "2026-08-20",
      "severity": "Medium",
      "tags": [],
      "strings_count": 19,
      "total_hits": 38,
      "source_code": "rule OSX_Stealer_AMOS_Generic {\n    meta:\n        description = \"Detects Atomic macOS Stealer (AMOS) payloads, memory dumps, and unpacked variants\"\n        date = \"2026-08-20\"\n        sample = \"5277bb0dd553d54d81dbd8a12d4634f9\"\n        malware_family = \"Atomic Stealer / AMOS\"\n        os = \"macos\"\n        silent = 1\n\n    strings:\n        // Layer 1: C++ Symbols for serialized build config\n        $sym_1 = \"build_info_t\" ascii\n        $sym_2 = \"serialized_build_info_t\" ascii\n        $sym_3 = \"_g_serialized_build_info\" ascii\n\n        // Layer 2: AMOS Persistence & Artifact Names\n        $persist_1 = \"com.hlpr.agent\" ascii\n        $persist_2 = \".hlpr\" ascii\n        $persist_3 = \".agnt\" ascii\n\n        // Layer 3: AMOS C2 Endpoints and Upload Form Fields\n        $c2_api_1 = \"/api/reports/upload\" ascii\n        $c2_api_2 = \"/api/download/app-bundle\" ascii\n        $c2_api_3 = \"/api/agent/download\" ascii\n        $c2_field_1 = \"report_file=@\" ascii\n        $c2_field_2 = \"build_tag=\" ascii\n\n        // Layer 4: Characteristic AMOS Command Lines & TTP Sequences\n        $cmd_1 = \"SPSoftwareDataType SPHardwareDataType SPDisplaysDataType\" ascii\n        $cmd_2 = \"ditto -c -k --sequesterRsrc\" ascii\n        $cmd_3 = \"security find-generic-password\" ascii\n        $cmd_4 = \"dscl . -authonly\" ascii\n        $cmd_5 = \"com.apple.notificationcenterui doNotDisturb\" ascii\n\n        // Layer 5: Bytecode Signatures (ARM64)\n        // Rolling-ROR Decryption Loop: bfxil, ldrb, add, ldrb, eor, strb, ror x9, x9, #1\n        $op_arm64_dec = { 4b 09 40 b3 6b 01 40 39 [2-6] 8d 41 40 39 ab 01 0b 4a 8b 41 00 39 29 05 c9 93 }\n\n        // Stack-string 32-byte XOR key loader sequences:\n        // mov wX, #0x5b22 ; movk wX, #0xf39f, lsl #16 (0xf39f5b22)\n        $op_key_load_1 = { 4? 64 8b 52 e? 73 be 72 }\n        // mov wX, #0x60cd ; movk wX, #0x5929, lsl #16 (0x592960cd)\n        $op_key_load_2 = { a? 19 8c 52 2? 25 ab 72 }\n\n    condition:\n        // Mach-O 64-bit, 32-bit, or Universal/FAT binary headers\n        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or \n         uint32(0) == 0xbebafeca or uint32(0) == 0xcafebabe) and (\n            //Symbol indicators + at least one behavioral artifact\n            (2 of ($sym_*) and (1 of ($c2_*) or 1 of ($cmd_*) or 1 of ($persist_*) or $op_arm64_dec or 1 of ($op_key_load_*))) or\n            \n            // C2 endpoints + Recon / Persistence commands / Form fields\n            (1 of ($c2_api_*) and (1 of ($cmd_*) or 1 of ($persist_*) or 1 of ($c2_field_*))) or\n            \n            // Decryption loop + any AMOS artifact / symbol / key loader\n            ($op_arm64_dec and (1 of ($sym_*) or 1 of ($c2_*) or 1 of ($cmd_*) or 1 of ($persist_*) or 1 of ($op_key_load_*))) or\n            \n            // High density of stack string key loader opcodes (for stripped/packed variants)\n            (#op_key_load_1 > 3 and #op_key_load_2 > 3) or\n            \n            // High density of characteristic TTP commands\n            (3 of ($cmd_*) and 2 of ($persist_*))\n        )\n}"
    },
    {
      "rule_name": "Macho_Trojan_CloudSync_Generic",
      "platform": "macos",
      "file_path": "yara-rules/macos/cloud_sync.yar",
      "description": "Generic detection for CloudSync ",
      "malware_family": "CloudSync",
      "author": "Unknown",
      "date": "2026-10-06",
      "severity": "Medium",
      "tags": [],
      "strings_count": 21,
      "total_hits": 3,
      "source_code": "rule Macho_Trojan_CloudSync_Generic {\n    meta:\n        description = \"Generic detection for CloudSync \"\n        date = \"2026-10-06\"\n        family = \"CloudSync\"\n        platform = \"macOS\"\n\n    strings:\n\n        // Invariant 32-byte substitution table (resides in __TEXT,__const, survives full symbol stripping)\n        $sobf_sbox = { d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51 }\n\n        // x86_64 machine code sequence for sobf::reveal (imull $-0x7d, %r12d, %eax; andl $0x1f, %r12d)\n        $sobf_code_x86 = { 41 6b c4 83 41 83 e4 1f }\n\n        // ARM64 machine code sequence for sobf::reveal (mov w9, #0x83; mul x9, x22, x9; and x11, x22, #0x1f)\n        $sobf_code_arm = { 69 10 80 52 c9 7e 09 9b cb 12 40 92 }\n\n\n        $ns1 = \"cloudsync_impl\" ascii\n        $ns2 = \"CSURLInsecureDelegate\" ascii\n        $ns3 = \"_ct_APP_PROCESS_DISGUISE_NAME\" ascii\n        $ns4 = \"_ct_APP_INSTALL_DIR\" ascii\n        $ns5 = \"_ct_APP_OPS_URL\" ascii\n        $ns6 = \"_ct_APP_AUTH_JSON_NAME\" ascii\n        $ns7 = \"_ct_APP_PACKAGE_DAEMON_BIN\" ascii\n        $ns8 = \"_ct_APP_TMP_SPAWN_S_PREFIX\" ascii\n        $ns9 = \"cloudsyncd\" ascii\n\n        $ui1 = \"AuthDialog\" ascii\n        $ui2 = \"showPasswordDialog\" ascii\n        $ui3 = \"renderCompositeAuthIcon\" ascii\n        $ui4 = \"ModernStatusWindow\" ascii\n        $ui5 = \"AlertButtonHandler\" ascii\n\n        // -------------------------------------------------------------------------\n        // 4. Stage 2 Backdoor Crypto & TLS Evasion Artifacts\n        // -------------------------------------------------------------------------\n        $c1 = \"chacha20poly1305\" ascii\n        $c2 = \"chacha20_stream\" ascii\n        $c3 = \"SecTrustSetExceptions\" ascii\n        $c4 = \"SecTrustCopyExceptions\" ascii\n\n    condition:\n        // Mach-O Magic Header: 64-bit, 32-bit, Universal/Fat binary (Little/Big Endian)\n        (\n            uint32(0) == 0xfeedfacf or \n            uint32(0) == 0xcafebabe or \n            uint32(0) == 0xbebafeca or \n            uint32(0) == 0xfeedface or \n            uint32(0) == 0xcffaedfe\n        ) and\n        filesize < 25MB and\n        (\n            // High-entropy compile-time obfuscator signatures (matches stripped & unstripped variants)\n            $sobf_sbox or\n            $sobf_code_x86 or\n            $sobf_code_arm or\n\n            // Symbol-based detection requiring 3+ specific internal namespace markers\n            (3 of ($ns*)) or\n\n            // Phishing dropper detection: fake password dialog combined with namespace/malware strings\n            (2 of ($ui*) and (1 of ($ns*) or $c3)) or\n\n            // Backdoor C2 delegate detection: custom insecure delegate combined with trust override & crypto\n            ($ns2 and ($c3 or $c4) and (1 of ($c1, $c2) or 1 of ($ns*)))\n        )\n}"
    },
    {
      "rule_name": "Macho_Trojan_CloudSync_DMG",
      "platform": "macos",
      "file_path": "yara-rules/macos/cloud_sync.yar",
      "description": "Detects CloudSync trojanized DMG disk image containers",
      "malware_family": "CloudSync",
      "author": "Unknown",
      "date": "2026-10-06",
      "severity": "Medium",
      "tags": [],
      "strings_count": 6,
      "total_hits": 1,
      "source_code": "rule Macho_Trojan_CloudSync_DMG {\n    meta:\n        description = \"Detects CloudSync trojanized DMG disk image containers\"\n        date = \"2026-10-06\"\n        family = \"CloudSync\"\n        platform = \"macOS\"\n\n    strings:\n        $koly = \"koly\"\n        $xml = \"<?xml version=\\\"1.0\\\" encoding=\\\"UTF-8\\\"?>\" ascii\n        $plist = \"<!DOCTYPE plist PUBLIC \\\"-//Apple//DTD PLIST 1.0//EN\\\"\" ascii\n        $part = \"whole disk (unknown partition : 0)\" ascii\n        $mish_hdr = \"bWlzaAAAAAEAAAAAAAAAAAAAAAAAANg\" ascii\n        $crc_part = \"PbEzG\" ascii // Base64 encoding of partition CRC 0x3DB13318\n\n    condition:\n        $koly at (filesize - 512) and\n        filesize > 1MB and filesize < 100MB and\n        $xml in (filesize-100000..filesize) and\n        $plist in (filesize-100000..filesize) and\n        $part and\n        ($mish_hdr or $crc_part)\n}"
    },
    {
      "rule_name": "macOS_ClickFix_AppleScript_Dropper",
      "platform": "macos",
      "file_path": "yara-rules/macos/macOS_ClickFix_AppleScript.yar",
      "description": "Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader",
      "malware_family": "Generic",
      "author": "Unknown",
      "date": "2026-08-31",
      "severity": "Medium",
      "tags": [],
      "strings_count": 16,
      "total_hits": 113,
      "source_code": "rule macOS_ClickFix_AppleScript_Dropper {\n    meta:\n        description    = \"Detects macOS ClickFix ChaCha20/AppleScript dropper and payload loader\"\n        date           = \"2026-08-31\"\n        sample_sha256  = \"05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72\"\n        threat_type    = \"Dropper / Infostealer Loader\"\n        platform       = \"macOS\"\n        confidence     = \"High\"\n\n    strings:\n        // Mach-O Magic Header Identification\n        $macho_fat_be  = { CA FE BA BE }\n        $macho_fat_le  = { BE BA FE CA }\n        $macho_64_be   = { FE ED FA CF }\n        $macho_64_le   = { CF FA ED FE }\n\n        // S-Box / Key Table (256-byte static table header)\n        $sbox = {\n            BE 85 31 24 C3 7D 0C 55 74 5D BE 72 FE B1 DE 80\n            A7 06 DC 9B 74 F1 9B C1 C1 69 9B E4 86 47 BE EF\n        }\n\n        // PBKDF2 / Key Derivation Salt (32 bytes)\n        $pbkdf2_salt = {\n            B1 CD FF 97 CC 3E B0 8F 2B 4A 53 89 4E CD 52 15\n            1A E5 AD 86 89 EA 99 45 06 F9 70 26 F0 34 6A BE\n        }\n\n        // HKDF Salt Constant\n        $hkdf_salt = {\n            85 CD 9E 60 B3 7D E0 B7 33 F7 36 D0 66 DC 49 1A\n            54 94 A7 E8 63 1F 03 24 BF 3E 08 2F CC D5 06 5D\n        }\n\n        // Hardcoded SHA-256 verification hashes for decrypted payloads\n        $payload_hash1 = {\n            9E 0B 82 E1 6D 94 C4 8F BF C7 12 00 4D B9 95 BE\n            A8 23 E8 97 7A C7 A9 4C D7 C3 A4 F2 FE 08 05 07\n        }\n        $payload_hash2 = {\n            7D B4 3F F8 79 96 2B 55 70 44 2C 2A E5 D2 1F D4\n            F6 D8 7D C0 CF DD E7 28 94 39 B4 71 8B 2B EE B9\n        }\n\n        // Multi-chunk encrypted payload length table (0x3ef6, 0x410f, 0x3ba4, 0x40f4, 0x3f79)\n        $chunk_lengths = {\n            F6 3E 00 00 00 00 00 00 0F 41 00 00 00 00 00 00\n            A4 3B 00 00 00 00 00 00 F4 40 00 00 00 00 00 00\n            79 3F 00 00 00 00 00 00\n        }\n\n        // Obfuscated XOR (0x1D) Anti-Analysis / VM Artifact Strings\n        $xor_hw_model   = \"uj3pryxq\"                // \"hw.model\" ^ 0x1d\n        $xor_model_id   = \"Pryxq=Tyxsit{txo\\x27=\"   // \"Model Identifier: \" ^ 0x1d\n        $xor_cpu_brand  = \"syBniotszvxos3urnihhty9\" // \"machdep.cpu.brand_string\" ^ 0x1d\n        $xor_vm_uuid    = \"zf4dtjrdmf\"              // VM UUID prefix ^ 0x1d\n\n        // Dropper Build / Component Identifier\n        $setup_id = \"setup-d192a316d9094048ce8251c66418fa61a3f2d45c\"\n\n        // ChaCha20 constant\n        $chacha20_const = \"expand 32-byte k\"\n\n    condition:\n        // Ensure valid Mach-O file format and size bounds\n        ($macho_fat_be at 0 or $macho_fat_le at 0 or $macho_64_be at 0 or $macho_64_le at 0) and\n        filesize < 2MB and\n        (\n            $sbox or\n            $setup_id or\n            $chunk_lengths or\n            ($pbkdf2_salt and ($payload_hash1 or $payload_hash2)) or\n            2 of ($xor_hw_model, $xor_model_id, $xor_cpu_brand, $xor_vm_uuid) or\n            ($chacha20_const and ($pbkdf2_salt or $hkdf_salt or $payload_hash1 or $payload_hash2))\n        )\n}"
    },
    {
      "rule_name": "APT_macOS_RustBucket_Behavioral_Indicators",
      "platform": "macos",
      "file_path": "yara-rules/macos/rust_bucket.yar",
      "description": "Broad hunting rule for macOS RustBucket/Lazarus loaders and drop-and-execute variants",
      "malware_family": "RustBucket",
      "author": "Unknown",
      "date": "2026-09-18",
      "severity": "High",
      "tags": [],
      "strings_count": 12,
      "total_hits": 3,
      "source_code": "rule APT_macOS_RustBucket_Behavioral_Indicators {\n    meta:\n        description = \"Broad hunting rule for macOS RustBucket/Lazarus loaders and drop-and-execute variants\"\n        date = \"2026-09-18\"\n        severity = \"High\"\n        malware_family = \"RustBucket\"\n\n    strings:\n        // C2 User-Agent anomaly (Legacy IE on macOS)\n        $ua_anom_01 = \"msie 8.0; windows nt 5.1\" ascii nocase\n        $ua_anom_02 = \"trident/4.0\" ascii nocase\n\n        // Subprocess spawning via Cocoa NSTask APIs\n        $task_sel_01 = \"setLaunchPath:\" ascii\n        $task_sel_02 = \"launchAndReturnError:\" ascii\n        $task_sel_03 = \"setArguments:\" ascii\n\n        // File-handling & staging indicators\n        $file_01 = \"temporaryDirectory\" ascii\n        $file_02 = \"defaultManager\" ascii\n        $file_03 = \"appendingPathComponent\" ascii\n\n        // Anti-forensic wiping primitives\n        $wipe_01 = \"swift_stdlib_random\" ascii\n        $wipe_02 = \"_unlink\" ascii\n\n        // Swift-specific execution scaffolding\n        $swift_cmd = \"CommandLine\" ascii\n        $swift_sem = \"OS_dispatch_semaphore\" ascii\n\n    condition:\n        // Mach-O Magic Numbers: 64-bit LE/BE or FAT Universal\n        (\n            uint32(0) == 0xfeedfacf or \n            uint32(0) == 0xcffaedfe or \n            uint32(0) == 0xbebafeca\n        )\n        and\n        (\n            // Direct hit: Any variation of the legacy MSIE 8.0 User-Agent inside a macOS Mach-O\n            1 of ($ua_anom_*) or\n\n            // Behavioral composition: Temp path resolution + Process spawning + Anti-forensics\n            (\n                2 of ($task_sel_*) and\n                2 of ($file_*) and\n                1 of ($wipe_*) and\n                all of ($swift_*)\n            )\n        )\n}"
    },
    {
      "rule_name": "OSX_Foxveil_AMOS_Stage4_Generic",
      "platform": "macos",
      "file_path": "yara-rules/macos/stealer.yar",
      "description": "Generic detection for Foxveil macOS Loader (AMOS / Atomic macOS Stealer Stage 4) utilizing PBKDF2 key stretching, ChaCha20-Poly1305 payload encryption, LCG stack-string decryption, and memory zeroing wipers",
      "malware_family": "Foxveil / AMOS (Atomic macOS Stealer)",
      "author": "Unknown",
      "date": "2026-09-16",
      "severity": "Medium",
      "tags": [],
      "strings_count": 14,
      "total_hits": 18,
      "source_code": "rule OSX_Foxveil_AMOS_Stage4_Generic {\n    meta:\n        description = \"Generic detection for Foxveil macOS Loader (AMOS / Atomic macOS Stealer Stage 4) utilizing PBKDF2 key stretching, ChaCha20-Poly1305 payload encryption, LCG stack-string decryption, and memory zeroing wipers\"\n        date = \"2026-09-16\"\n        reference = \"https://bazaar.abuse.ch/sample/841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb/\"\n        malware_family = \"Foxveil / AMOS (Atomic macOS Stealer)\"\n        threat_type = \"Dropper / Loader / InfoStealer\"\n\n    strings:\n        // Generic ad-hoc signing identifier pattern for disguised fake setups/installers/helpers\n        $id_pattern = /(setup|install|installer|update|helper|patch|cleaner|daemon|task|agent|app)-[0-9a-f]{16,64}/ ascii nocase\n\n        // Constructor table reconstruction in __mod_init_func (x86_64)\n        $mod_init_x86 = { 8B ?? ?? 03 ?? ?? 89 ?? ?? 48 83 C0 04 48 ( 3D ?? ?? 00 00 | 83 F8 ?? ) 75 }\n\n        // Constructor table reconstruction in __mod_init_func (arm64)\n        $mod_init_arm64 = { ?? ?? 68 B8 ?? ?? 68 B8 ?? ?? 0? 0B ?? ?? 28 B8 08 11 00 91 1F ?? ?? F1 ?? ?? ?? 54 }\n\n        // Dynamic API resolution call: dlsym(RTLD_DEFAULT, str) in x86_64 (movq $-2, %rdi; callq _dlsym)\n        $dlsym_call_x86 = { 48 C7 C7 FE FF FF FF E8 ?? ?? 00 00 }\n\n        // Dynamic API resolution call: dlsym(RTLD_DEFAULT, str) in arm64 (mov x0, #-2; bl _dlsym)\n        $dlsym_call_arm64 = { 20 00 80 92 ?? ?? 00 94 }\n\n        // Linear Congruential Generator (LCG) PRNG constants for string decryption (A = 1103515245, C = 12345) in x86_64\n        $lcg_consts_x86 = { 6D 4E C6 41 [0-16] 39 30 00 00 }\n\n        // LCG instruction step in arm64: madd w8, w9, w8, w10 (occurs 200+ times)\n        $lcg_madd_arm64 = { 28 29 08 1B }\n\n        // LCG increment constant load in arm64: mov w9, #12345 (occurs 15+ times)\n        $lcg_const_arm64 = { 29 07 86 52 }\n\n        // Stack zeroing memory wiper loop after dynamic API resolution (x86_64)\n        $wiper_loop_x86 = { C6 84 ?? ?? ?? FF FF 00 48 FF (C0 | C8) [0-4] 75 }\n\n        // PBKDF2 vector XOR accumulation loop (x86_64)\n        $pbkdf2_accum_x86 = { 66 0F 6F 84 05 ?? ?? FF FF 66 0F EF 84 05 ?? ?? FF FF 66 0F 7F 84 05 ?? ?? FF FF 48 83 C0 10 48 83 F8 20 75 }\n\n        // High-iteration PBKDF2 key stretching loop bound check (x86_64: 65k to 131k iterations)\n        $key_stretch_x86 = { 41 81 FE ?? ?? 01 00 0F 85 }\n\n        // HMAC vector constant initialization on arm64 (ipad = 0x36 / 54, opad = 0x5c / 92)\n        $hmac_consts_arm64 = { C0 E6 01 4F [0-8] 81 E7 02 4F }\n\n        // Characteristic minimal dynamic symbol imports\n        $sym_dlsym = \"_dlsym\" ascii\n        $sym_chkstk = \"____chkstk_darwin\" ascii\n\n    condition:\n        // Mach-O binary format validation (Fat universal or standalone Mach-O 32/64)\n        (uint32(0) == 0xbebafeca or uint32(0) == 0xcafebabe or\n         uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe)\n        and filesize < 20MB\n        and (\n            // Condition 1: Fake installer identifier combined with any Foxveil loader engine artifact\n            ($id_pattern and 1 of ($mod_init_*, $lcg_*, $wiper_*, $pbkdf2_*, $hmac_*)) or\n\n            // Condition 2: Generic x86_64 Foxveil loader characteristics\n            (\n                $mod_init_x86 and\n                ($lcg_consts_x86 or $pbkdf2_accum_x86 or $key_stretch_x86) and\n                #wiper_loop_x86 >= 3 and\n                #dlsym_call_x86 >= 5\n            ) or\n\n            // Condition 3: Generic arm64 Foxveil loader characteristics\n            (\n                $mod_init_arm64 and\n                ($hmac_consts_arm64 or #lcg_const_arm64 >= 3) and\n                #lcg_madd_arm64 >= 10 and\n                #dlsym_call_arm64 >= 5\n            ) or\n\n            // Condition 4: Multi-architecture core engine match with minimal symbol indicators\n            (\n                all of ($sym_*) and\n                2 of ($mod_init_*, $lcg_consts_x86, $pbkdf2_accum_x86, $hmac_consts_arm64) and\n                (#dlsym_call_x86 >= 5 or #dlsym_call_arm64 >= 5)\n            )\n        )\n}"
    },
    {
      "rule_name": "Macho_Trojan_CloudSync_1006YR",
      "platform": "macos",
      "file_path": "yara-rules/macos/stealer.yar",
      "description": "Generic detection for CloudSync ",
      "malware_family": "CloudSync",
      "author": "Chandra Kant Bauri",
      "date": "2026-10-06",
      "severity": "Medium",
      "tags": [],
      "strings_count": 21,
      "total_hits": 2,
      "source_code": "rule Macho_Trojan_CloudSync_1006YR {\n    meta:\n        silent = 1\n        author = \"Chandra Kant Bauri\"\n        description = \"Generic detection for CloudSync \"\n        date = \"2026-10-06\"\n        family = \"CloudSync\"\n        platform = \"macOS\"\n\n    strings:\n\n        // Invariant 32-byte substitution table (resides in __TEXT,__const, survives full symbol stripping)\n        $sobf_sbox = { d7 19 bf 57 e6 5b a0 9d e1 ba cd b1 82 c9 91 18 ed af d5 18 fd 3a 4a 97 97 bc ad 22 1a db 81 51 }\n\n        // x86_64 machine code sequence for sobf::reveal (imull $-0x7d, %r12d, %eax; andl $0x1f, %r12d)\n        $sobf_code_x86 = { 41 6b c4 83 41 83 e4 1f }\n\n        // ARM64 machine code sequence for sobf::reveal (mov w9, #0x83; mul x9, x22, x9; and x11, x22, #0x1f)\n        $sobf_code_arm = { 69 10 80 52 c9 7e 09 9b cb 12 40 92 }\n\n\n        $ns1 = \"cloudsync_impl\" ascii\n        $ns2 = \"CSURLInsecureDelegate\" ascii\n        $ns3 = \"_ct_APP_PROCESS_DISGUISE_NAME\" ascii\n        $ns4 = \"_ct_APP_INSTALL_DIR\" ascii\n        $ns5 = \"_ct_APP_OPS_URL\" ascii\n        $ns6 = \"_ct_APP_AUTH_JSON_NAME\" ascii\n        $ns7 = \"_ct_APP_PACKAGE_DAEMON_BIN\" ascii\n        $ns8 = \"_ct_APP_TMP_SPAWN_S_PREFIX\" ascii\n        $ns9 = \"cloudsyncd\" ascii\n\n        $ui1 = \"AuthDialog\" ascii\n        $ui2 = \"showPasswordDialog\" ascii\n        $ui3 = \"renderCompositeAuthIcon\" ascii\n        $ui4 = \"ModernStatusWindow\" ascii\n        $ui5 = \"AlertButtonHandler\" ascii\n\n\n        // 4. Stage 2 Backdoor Crypto & TLS Evasion Artifacts\n\n        $c1 = \"chacha20poly1305\" ascii\n        $c2 = \"chacha20_stream\" ascii\n        $c3 = \"SecTrustSetExceptions\" ascii\n        $c4 = \"SecTrustCopyExceptions\" ascii\n\n    condition:\n        // Mach-O Magic Header: 64-bit, 32-bit, Universal/Fat binary (Little/Big Endian)\n        (\n            uint32(0) == 0xfeedfacf or \n            uint32(0) == 0xcafebabe or \n            uint32(0) == 0xbebafeca or \n            uint32(0) == 0xfeedface or \n            uint32(0) == 0xcffaedfe\n        ) and\n        filesize < 25MB and\n        (\n            // High-entropy compile-time obfuscator signatures (matches stripped & unstripped variants)\n            $sobf_sbox or\n            $sobf_code_x86 or\n            $sobf_code_arm or\n\n            // Symbol-based detection requiring 3+ specific internal namespace markers\n            (3 of ($ns*)) or\n\n            // Phishing dropper detection: fake password dialog combined with namespace/malware strings\n            (2 of ($ui*) and (1 of ($ns*) or $c3)) or\n\n            // Backdoor C2 delegate detection: custom insecure delegate combined with trust override & crypto\n            ($ns2 and ($c3 or $c4) and (1 of ($c1, $c2) or 1 of ($ns*)))\n        )\n}"
    },
    {
      "rule_name": "Macho_Trojan_CloudSync_1007YR",
      "platform": "macos",
      "file_path": "yara-rules/macos/stealer.yar",
      "description": "Detects CloudSync trojanized DMG disk image containers",
      "malware_family": "CloudSync",
      "author": "Chandra Kant Bauri",
      "date": "2026-10-06",
      "severity": "Medium",
      "tags": [],
      "strings_count": 6,
      "total_hits": 1,
      "source_code": "rule Macho_Trojan_CloudSync_1007YR {\n    meta:\n        silent = 1\n        author = \"Chandra Kant Bauri\"\n        description = \"Detects CloudSync trojanized DMG disk image containers\"\n        date = \"2026-10-06\"\n        family = \"CloudSync\"\n        platform = \"macOS\"\n\n    strings:\n        $koly = \"koly\"\n        $xml = \"<?xml version=\\\"1.0\\\" encoding=\\\"UTF-8\\\"?>\" ascii\n        $plist = \"<!DOCTYPE plist PUBLIC \\\"-//Apple//DTD PLIST 1.0//EN\\\"\" ascii\n        $part = \"whole disk (unknown partition : 0)\" ascii\n        $mish_hdr = \"bWlzaAAAAAEAAAAAAAAAAAAAAAAAANg\" ascii\n        $crc_part = \"PbEzG\" ascii // Base64 encoding of partition CRC 0x3DB13318\n\n    condition:\n        $koly at (filesize - 512) and\n        filesize > 1MB and filesize < 100MB and\n        $xml in (filesize-100000..filesize) and\n        $plist in (filesize-100000..filesize) and\n        $part and\n        ($mish_hdr or $crc_part)\n}"
    },
    {
      "rule_name": "Macho_hVNCRat_generic",
      "platform": "macos",
      "file_path": "yara-rules/macos/stealer.yar",
      "description": "Detects generic macOS HVNC (Hidden VNC) browser hijacking implant",
      "malware_family": "macOS.hvnc",
      "author": "Chandra Kant Bauri",
      "date": "2026-10-14",
      "severity": "Medium",
      "tags": [],
      "strings_count": 10,
      "total_hits": 1,
      "source_code": "rule Macho_hVNCRat_generic {\n    meta:\n        author = \"Chandra Kant Bauri\"\n        description = \"Detects generic macOS HVNC (Hidden VNC) browser hijacking implant\"\n        date = \"2026-10-14\"\n        malware_family = \"macOS.hvnc\"\n    strings:\n        // Unique custom JavaScript injected into victim browsers for covert interaction\n        $js_find = \"window.__hvncFind\" ascii\n        $js_copy = \"window.__hvncCopySel\" ascii\n        $js_zoom = \"window.__hvncZoomSet\" ascii\n        $css_find = \"::highlight(hvnc-find)\" ascii\n\n        // Unique SQLite shadow backup & APFS clone strings\n        $sqlite_bak = \".backup '$T.hvncbak'\" ascii\n        $pkill_clone = \"/usr/bin/pkill -f 'hvnc_clone_'\" ascii\n        $apfs_clone = \"chromium clone: APFS clonefile snapshot\" ascii\n\n        // Unique DevTools Protocol manipulation & crash prompt suppression\n        $cdp_bounds = \"{\\\"windowId\\\":%d,\\\"bounds\\\":{\\\"left\\\":-32000,\\\"top\\\":-32000}}\" ascii\n        $cdp_crash1 = \"s/\\\"exit_type\\\":\\\"Crashed\\\"/\\\"exit_type\\\":\\\"Normal\\\"/g\" ascii\n        $cdp_crash2 = \"browser.sessionstore.resume_from_crash\" ascii\n    condition:\n        // Enforce valid Mach-O binary (64-bit, 32-bit, or Fat/Universal)\n        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32(0) == 0xcafebabe or uint32(0) == 0xcffaedfe or uint32(0) == 0xbebafeca)\n        and (\n            2 of ($js_find, $js_copy, $js_zoom, $css_find) or\n            2 of ($sqlite_bak, $pkill_clone, $apfs_clone) or\n            ($cdp_bounds and 1 of ($cdp_crash1, $cdp_crash2)) or\n            (3 of them)\n        )\n}"
    },
    {
      "rule_name": "Macho_hVNCRat_campaign",
      "platform": "macos",
      "file_path": "yara-rules/macos/stealer.yar",
      "description": "Detects specific campaign build of macOS HVNC implant",
      "malware_family": "macOS.HVNC",
      "author": "Chandra Kant Bauri",
      "date": "2026-10-14",
      "severity": "Medium",
      "tags": [],
      "strings_count": 4,
      "total_hits": 1,
      "source_code": "rule Macho_hVNCRat_campaign {\n    meta:\n        author = \"Chandra Kant Bauri\"\n        description = \"Detects specific campaign build of macOS HVNC implant\"\n        date = \"2026-10-14\"\n        malware_family = \"macOS.HVNC\"\n        sample_hash = \"5681c400f0ed8431b3950e92864e52cffb0bf93a359edffb49e423ad5e8ef0b8\"\n    strings:\n        $c2 = \"agent.torrentsbyjimboslimfit.xyz\" ascii\n        $tag = \"HVNC_MAC_TAG:8panel\" ascii\n        $psk = \"hvnc-remote-default-psk\" ascii\n        $id = \"hvnc_agent_macos_universal\" ascii\n    condition:\n        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32(0) == 0xcafebabe or uint32(0) == 0xcffaedfe or uint32(0) == 0xbebafeca)\n        and 2 of ($c2, $tag, $psk, $id)\n}"
    },
    {
      "rule_name": "Macho_hVNCRat_shelldropper",
      "platform": "macos",
      "file_path": "yara-rules/macos/stealer.yar",
      "description": "Detects shell dropper script for macOS HVNC agent",
      "malware_family": "macOS.HVNC",
      "author": "Chandra Kant Bauri",
      "date": "2026-10-14",
      "severity": "Medium",
      "tags": [],
      "strings_count": 6,
      "total_hits": 1,
      "source_code": "rule Macho_hVNCRat_shelldropper {\n    meta:\n        author = \"Chandra Kant Bauri\"\n        description = \"Detects shell dropper script for macOS HVNC agent\"\n        date = \"2026-10-14\"\n        malware_family = \"macOS.HVNC\"\n        sample_hash = \"dce578f5af994c77785b96087e4fd4d8124482eab896dceb175a26342a84e31b\"\n    strings:\n        $sh = \"#!/bin/\" ascii\n        $c2 = \"txrouteuifbfewfubewfbhgrabbing.xyz\" ascii\n        $uri = \"/wohnung/agent\" ascii\n        $dest = \"Downloads/wohnung\" ascii\n        $plist = \"com.system.updater.plist\" ascii\n        $check_magic = \"cafebabe|cffaedfe\" ascii\n    condition:\n        $sh at 0\n        and (\n            $c2 or\n            (3 of ($uri, $dest, $plist, $check_magic))\n        )\n}"
    }
  ]
};

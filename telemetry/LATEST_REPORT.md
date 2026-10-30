# Yarafy Telemetry & Threat Hunting Report

**Last Run:** `2026-10-30T21:07:38.624112+00:00`
**Total Samples Scanned:** `18802` | **Total Rule Hits:** `365`

## Hits Breakdown by Source Feed
| Source Feed | Total Hits |
| :--- | :--- |
| **MalwareBazaar** | `211` |
| **VirusTotal Enterprise** | `43` |
| **Local File** | `111` |

## Hits Breakdown by Platform
| Platform | Total Hits |
| :--- | :--- |
| **MACOS** | `365` |
| **WINDOWS** | `0` |
| **LINUX** | `0` |
| **NON-PE** | `0` |

## Hits Breakdown by YARA Rule
| Rule Name | Total Detections |
| :--- | :--- |
| [`macOS_ClickFix_AppleScript_Dropper`](../yara-rules/) | `187` |
| [`OSX_Malware_EvilQuest_ThiefQuest`](../yara-rules/) | `100` |
| [`OSX_Stealer_AMOS_Generic`](../yara-rules/) | `39` |
| [`OSX_Foxveil_AMOS_Stage4_Generic`](../yara-rules/) | `18` |
| [`MALW_macOS_MacSync_Stealer_Universal`](../yara-rules/) | `7` |
| [`APT_macOS_RustBucket_Behavioral_Indicators`](../yara-rules/) | `3` |
| [`Macho_Trojan_CloudSync_Generic`](../yara-rules/) | `3` |
| [`Macho_Trojan_CloudSync_1006YR`](../yara-rules/) | `2` |
| [`Macho_Trojan_CloudSync_1007YR`](../yara-rules/) | `1` |
| [`Macho_Trojan_CloudSync_DMG`](../yara-rules/) | `1` |
| [`Macho_hVNCRat_generic`](../yara-rules/) | `1` |
| [`Macho_hVNCRat_campaign`](../yara-rules/) | `1` |
| [`Macho_hVNCRat_shelldropper`](../yara-rules/) | `1` |
| [`macOS_Backdoor_C5_Implant`](../yara-rules/) | `1` |

## Recent Positive Detections
| Timestamp | Source Feed | Rule | Platform | SHA256 | VT Detection | VT Threat Label |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `76aa197e55...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `e550ce5f81...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `d2bcb4acab...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `ac26450780...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `1958da2df1...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `1804de718d...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `ed3615ba0a...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `348dd45e60...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `603912ec0c...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `0921656055...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `46b43aa957...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `8e2cf5c91f...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `79b28c46e0...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `5882225773...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `9b1040bb03...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `78d06d558f...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `df5cabf6d7...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `ef72daf468...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `06e797057a...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `8df42fee04...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `d543749e28...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `3107f96a0d...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `7e5113e559...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `b80712b7c3...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `c37cfc0b8a...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `5f9c7dbcf0...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `d07c0566ad...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `a686a390e8...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `57573e7979...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `5316cfa1f4...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `1cfb7299a9...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `abce6cf93c...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `6249496af1...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `4391b9d36c...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `5e76d06b20...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `355b75d205...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `612e95fc8b...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `99fa8e5cf3...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `342c4f4ece...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `7e878d580c...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `7b3329e514...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `1b7f0fb1b0...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `fe84c0a7dc...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `cd96d8ace1...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `35100af8ed...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `ed1bd656e6...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `008faebef5...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `6935fa009a...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `67cc2395d1...` | `N/A` | `N/A` |
| 2026-10-30 21:07:38 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `5dd6b67cf8...` | `N/A` | `N/A` |

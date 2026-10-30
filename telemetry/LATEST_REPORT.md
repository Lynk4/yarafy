# Yarafy Telemetry & Threat Hunting Report

**Last Run:** `2026-10-30T21:11:52.337591+00:00`
**Total Samples Scanned:** `19002` | **Total Rule Hits:** `531`

## Hits Breakdown by Source Feed
| Source Feed | Total Hits |
| :--- | :--- |
| **MalwareBazaar** | `211` |
| **VirusTotal Enterprise** | `43` |
| **Local File** | `277` |

## Hits Breakdown by Platform
| Platform | Total Hits |
| :--- | :--- |
| **MACOS** | `531` |
| **WINDOWS** | `0` |
| **LINUX** | `0` |
| **NON-PE** | `0` |

## Hits Breakdown by YARA Rule
| Rule Name | Total Detections |
| :--- | :--- |
| [`OSX_Malware_EvilQuest_ThiefQuest`](../yara-rules/) | `266` |
| [`macOS_ClickFix_AppleScript_Dropper`](../yara-rules/) | `187` |
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
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `3a5cd04869...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `2acb983502...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `3c03957314...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `8e2dea31ae...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `62fce63e27...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `10097eded1...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `44f99435c7...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `e4f08ef8c3...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `8135c1e797...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `c1b636ad56...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `75965b776b...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `9b32211bb7...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `5073bb78d8...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `828eb9305f...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `124a86e26d...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `6c3cb28939...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `8d6d84f503...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `8d4a61df82...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `2b970baf23...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `2705fe042e...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `286132517b...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `a5a077cf92...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `6e008f6777...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `8a2293a997...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `720f3e7cb0...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `b8f1061f21...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `8c6a602bc1...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `3b5cc4a4e7...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `83fbc9e1bd...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `094246a399...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `c22a4c9c9a...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `3a7abe6803...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `08782f7ee0...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `db68a3b440...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `e9a5894b6e...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `993cf3b55f...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `56b4014b32...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `f35f140492...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `5e680b6bc4...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `d33e94f8e9...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `e23309a788...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `d81d2e9e29...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `3463d0eefe...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `00a4be25f2...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `0010b8d37b...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `1dbe2c1766...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `d06188a64e...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `1678f70850...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `0447bdaf4e...` | `N/A` | `N/A` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `452482525a...` | `N/A` | `N/A` |

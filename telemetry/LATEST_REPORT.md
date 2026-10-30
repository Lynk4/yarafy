# Yarafy Telemetry & Threat Hunting Report

**Last Run:** `2026-10-30T21:10:12.801322+00:00`
**Total Samples Scanned:** `18902` | **Total Rule Hits:** `452`

## Hits Breakdown by Source Feed
| Source Feed | Total Hits |
| :--- | :--- |
| **MalwareBazaar** | `211` |
| **VirusTotal Enterprise** | `43` |
| **Local File** | `198` |

## Hits Breakdown by Platform
| Platform | Total Hits |
| :--- | :--- |
| **MACOS** | `452` |
| **WINDOWS** | `0` |
| **LINUX** | `0` |
| **NON-PE** | `0` |

## Hits Breakdown by YARA Rule
| Rule Name | Total Detections |
| :--- | :--- |
| [`macOS_ClickFix_AppleScript_Dropper`](../yara-rules/) | `187` |
| [`OSX_Malware_EvilQuest_ThiefQuest`](../yara-rules/) | `187` |
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
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `3a2eb3fd20...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `81b8ef3f9c...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `a85c299b4e...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `c781d26b1c...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `cc485807b0...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `1ea65313ec...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `d527e86130...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `800a0adaaa...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `fca75f414c...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `718abf1e52...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `d6920451b9...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `15b5a3f591...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `5913439ae3...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `e510af2b90...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `a8e9ca30e6...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `e41ba8ba60...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `73be2307ab...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `04b04b4804...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `fc54e8b141...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `61280b90af...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `79af35c7ba...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `faad650a80...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `9fec744895...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `eb0baef731...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `6b8c359769...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `ed9c33c534...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `254bcd0617...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `69ee38457a...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `960cd28265...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `5183aac720...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `29b5558152...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `e46d7777ed...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `82a8ac53e8...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `f835823c50...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `ecd0df807d...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `ab25cda03f...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `620282a1e3...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `42d62a9325...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `5a4d8d14cb...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `411acb72f0...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `480b59d1ee...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `fee25854a0...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `f31c4ad175...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `f95e806da8...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `1d0709a320...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `5f35a0ea05...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `d262fb73b8...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `2392375245...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `936615151f...` | `N/A` | `N/A` |
| 2026-10-30 21:10:12 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `568f06141c...` | `N/A` | `N/A` |

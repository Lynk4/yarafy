# Yarafy Telemetry & Threat Hunting Report

**Last Run:** `2026-11-09T00:01:32.363604+00:00`
**Total Samples Scanned:** `22638` | **Total Rule Hits:** `659`

## Hits Breakdown by Source Feed
| Source Feed | Total Hits |
| :--- | :--- |
| **MalwareBazaar** | `311` |
| **VirusTotal Enterprise** | `43` |
| **Local File** | `305` |

## Hits Breakdown by Platform
| Platform | Total Hits |
| :--- | :--- |
| **MACOS** | `659` |
| **WINDOWS** | `0` |
| **LINUX** | `0` |
| **NON-PE** | `0` |

## Hits Breakdown by YARA Rule
| Rule Name | Total Detections |
| :--- | :--- |
| [`macOS_ClickFix_AppleScript_Dropper`](../yara-rules/) | `292` |
| [`OSX_Malware_EvilQuest_ThiefQuest`](../yara-rules/) | `266` |
| [`OSX_Stealer_AMOS_Generic`](../yara-rules/) | `40` |
| [`OSX_Foxveil_AMOS_Stage4_Generic`](../yara-rules/) | `19` |
| [`OSX_Avenger_Stealer`](../yara-rules/) | `14` |
| [`MALW_macOS_MacSync_Stealer_Universal`](../yara-rules/) | `7` |
| [`Macho_Trojan_CloudSync_Generic`](../yara-rules/) | `5` |
| [`Macho_Trojan_CloudSync_1006YR`](../yara-rules/) | `4` |
| [`APT_macOS_RustBucket_Behavioral_Indicators`](../yara-rules/) | `3` |
| [`Macho_Jockey_Implant`](../yara-rules/) | `2` |
| [`Macho_Trojan_CloudSync_1007YR`](../yara-rules/) | `1` |
| [`Macho_Trojan_CloudSync_DMG`](../yara-rules/) | `1` |
| [`Macho_hVNCRat_generic`](../yara-rules/) | `1` |
| [`Macho_hVNCRat_campaign`](../yara-rules/) | `1` |
| [`Macho_hVNCRat_shelldropper`](../yara-rules/) | `1` |
| [`macOS_Backdoor_C5_Implant`](../yara-rules/) | `1` |
| [`OSX_Avenger_Stealer_Keychain_Helper`](../yara-rules/) | `1` |

## Recent Positive Detections
| Timestamp | Source Feed | Rule | Platform | SHA256 | VT Detection | VT Threat Label |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | `4886ea2ed8...` | `N/A` | `N/A` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | `0039b2a4d4...` | `N/A` | `N/A` |
| 2026-11-09 00:01:32 | **Local File** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | `0039b2a4d4...` | `N/A` | `N/A` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | `1286c98e0e...` | `N/A` | `N/A` |
| 2026-11-09 00:01:32 | **Local File** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | `1286c98e0e...` | `N/A` | `N/A` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | `45ce45c4ab...` | `N/A` | `N/A` |
| 2026-11-09 00:01:32 | **Local File** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | `45ce45c4ab...` | `N/A` | `N/A` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | `0fe422f752...` | `N/A` | `N/A` |
| 2026-11-09 00:01:32 | **Local File** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | `0fe422f752...` | `N/A` | `N/A` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | `96b908b6ab...` | `N/A` | `N/A` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | `234815e6e0...` | `N/A` | `N/A` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | `a22d3b565a...` | `N/A` | `N/A` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | `6db19db41d...` | `N/A` | `N/A` |
| 2026-11-09 00:01:32 | **Local File** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | `6db19db41d...` | `N/A` | `N/A` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | `fb2e274ae9...` | `N/A` | `N/A` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | `5f3c2f6b4e...` | `N/A` | `N/A` |
| 2026-11-09 00:01:32 | **Local File** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | `5f3c2f6b4e...` | `N/A` | `N/A` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | `5d00706467...` | `N/A` | `N/A` |
| 2026-11-09 00:01:32 | **Local File** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | `5d00706467...` | `N/A` | `N/A` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | `d04adb8791...` | `N/A` | `N/A` |
| 2026-11-09 00:01:32 | **Local File** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | `d04adb8791...` | `N/A` | `N/A` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer_Keychain_Helper` | macos_stealers_pam_stealer_yar | `c77f94d0a5...` | `N/A` | `N/A` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | `06fdd1d97d...` | `N/A` | `N/A` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Foxveil_AMOS_Stage4_Generic` | macos_stealers_amos_yar | `06fdd1d97d...` | `N/A` | `N/A` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`323214d1eb...`](https://www.virustotal.com/gui/file/323214d1eb020eb1919c87bc48541f1e2997082279969adc77f52b6cc17f0135) | `29/59` | `trojan.amos/infostl` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`a0d1321649...`](https://www.virustotal.com/gui/file/a0d1321649b45899e56bd86f5dffec509f0cb8ac6e44acafb38f55649a69cbb0) | `28/63` | `trojan.amos/abmrisk` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`1db680ecf7...`](https://www.virustotal.com/gui/file/1db680ecf7e3c1668f2454df9d661fe3bf84a4e82031725bd871f8eeffd59eff) | `29/58` | `trojan.amos/infostl` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`eea3fc56ed...`](https://www.virustotal.com/gui/file/eea3fc56edae8f987bd841192f5810d240d27662e976d1087a68945f0e923172) | `25/56` | `trojan.amos/macho` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`0eefe5dd56...`](https://www.virustotal.com/gui/file/0eefe5dd5605680e24f2b6c0cb75f5dcdc4688b7c0f8ee2986a592a326cabc5f) | `27/61` | `trojan.amos/abapplication` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`503b965c67...`](https://www.virustotal.com/gui/file/503b965c67a4712791ce7cbdcbecd492fcb85bdbebb777ebffb4aa74708eb3c6) | `27/57` | `trojan.amos/infostl` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`b056036d41...`](https://www.virustotal.com/gui/file/b056036d41d9992cde1cff4c9db6ca343ce86e41fd4394b382df0db6d1c81989) | `30/63` | `trojan.amos/macho` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`dd9f917582...`](https://www.virustotal.com/gui/file/dd9f917582660b3d1623203343a57c8984e95b4503cf2fd9295fbda832d3bf6b) | `26/51` | `trojan.amos/infostl` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`4f9bfba5dc...`](https://www.virustotal.com/gui/file/4f9bfba5dc5b19360bd785ac5df0da4310e90da7cf3c0c1330ee77de037e0ee9) | `31/61` | `trojan.amos/infostl` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`1c4e9a6a9b...`](https://www.virustotal.com/gui/file/1c4e9a6a9bcce85414ef68e51bb2b0b8a869613ffd17dfde4062f84a17f4f249) | `31/63` | `trojan.amos/macho` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`21eceb4b63...`](https://www.virustotal.com/gui/file/21eceb4b63db325a89dedc3e6b0595b10731e25dee8158510ef0f91b49acae53) | `23/63` | `trojan.stealer/amos` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `Macho_Trojan_CloudSync_1006YR` | macos_droppers_cloudsync_yar | [`b3cca282ed...`](https://www.virustotal.com/gui/file/b3cca282ed4a60bda2297d84eb3fc0ecb74cae57a913ebcbc409fa0ee10b2845) | `3/63` | `trojan.cloudsyncd` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `Macho_Trojan_CloudSync_Generic` | macos_droppers_cloudsync_yar | [`b3cca282ed...`](https://www.virustotal.com/gui/file/b3cca282ed4a60bda2297d84eb3fc0ecb74cae57a913ebcbc409fa0ee10b2845) | `3/63` | `trojan.cloudsyncd` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `Macho_Trojan_CloudSync_1006YR` | macos_droppers_cloudsync_yar | [`e8b7503f40...`](https://www.virustotal.com/gui/file/e8b7503f40fbcc41ed6769584b410da29827e505160290335454214074b7a511) | `28/63` | `trojan.cloudsyncd/macho` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `Macho_Trojan_CloudSync_Generic` | macos_droppers_cloudsync_yar | [`e8b7503f40...`](https://www.virustotal.com/gui/file/e8b7503f40fbcc41ed6769584b410da29827e505160290335454214074b7a511) | `28/63` | `trojan.cloudsyncd/macho` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`87153046bb...`](https://www.virustotal.com/gui/file/87153046bb0e4d822defedf4546ae51f4e68402f3b10872f28f5ea8611774eac) | `31/63` | `trojan.amos/infostl` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`0b5981059d...`](https://www.virustotal.com/gui/file/0b5981059d2626952a96b9f06aaebe909697ebe7b9f9623d3f7ef127e2ff981a) | `32/63` | `trojan.amos/infostl` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`80f9844f15...`](https://www.virustotal.com/gui/file/80f9844f1582858b5afd0259e0d8f2b8f26a2e71f08bb0d43ae1a1850e3b2a41) | `31/63` | `trojan.amos/infostl` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`83fbae547d...`](https://www.virustotal.com/gui/file/83fbae547d319db480b78f3256d0f4dd1b21123458a547cd5688a23702a2393a) | `32/63` | `trojan.amos/infostl` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`82fc8392db...`](https://www.virustotal.com/gui/file/82fc8392dbf1d4f87aaaf087448566ae36d9387e47758c5645ef72369c7fe63f) | `30/63` | `trojan.amos/abpws` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`a1207ab455...`](https://www.virustotal.com/gui/file/a1207ab455644e9c9ba6a822f4bef88a519893421821c6840a6ec8bbf51bedd1) | `30/63` | `trojan.amos/infostl` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`5c1b00db39...`](https://www.virustotal.com/gui/file/5c1b00db39b643a1540d7c0d41bb4f6a8f12f76963f694fe15e30d7159c6dd42) | `29/63` | `trojan.amos/abmrisk` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`1915e2b479...`](https://www.virustotal.com/gui/file/1915e2b4792be27bedf68c2e496d5dcf0f870656263f3195bf2e5ea225af90e8) | `29/63` | `trojan.amos/abmrisk` |
| 2026-11-03 18:10:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`d561097aaf...`](https://www.virustotal.com/gui/file/d561097aaf56697eafd98e5fe24297866c9ea64375db931fa99dc8dfd640b84c) | `31/63` | `trojan.amos/infostl` |
| 2026-11-03 18:10:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`85733cc2d4...`](https://www.virustotal.com/gui/file/85733cc2d4fc2697579777f402c154603fd6576921698ed601bd636420329fe4) | `30/59` | `trojan.amos/infostl` |
| 2026-11-03 18:10:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`937e0b01af...`](https://www.virustotal.com/gui/file/937e0b01afe0b72a92d8b5cd0284f057240e833d783f5efb1385f9f5a600c320) | `30/62` | `trojan.amos/infostl` |

# Yarafy Telemetry & Threat Hunting Report

**Last Run:** `2026-11-23T07:27:54.965509+00:00`
**Total Samples Scanned:** `26175` | **Total Rule Hits:** `670`

## Hits Breakdown by Source Feed
| Source Feed | Total Hits |
| :--- | :--- |
| **MalwareBazaar** | `319` |
| **VirusTotal Enterprise** | `43` |
| **Local File** | `308` |

## Hits Breakdown by Platform
| Platform | Total Hits |
| :--- | :--- |
| **MACOS** | `670` |
| **WINDOWS** | `0` |
| **LINUX** | `0` |
| **NON-PE** | `0` |

## Hits Breakdown by YARA Rule
| Rule Name | Total Detections |
| :--- | :--- |
| [`macOS_ClickFix_AppleScript_Dropper`](../yara-rules/) | `292` |
| [`OSX_Malware_EvilQuest_ThiefQuest`](../yara-rules/) | `266` |
| [`OSX_Stealer_AMOS_Generic`](../yara-rules/) | `43` |
| [`OSX_Foxveil_AMOS_Stage4_Generic`](../yara-rules/) | `19` |
| [`OSX_Avenger_Stealer`](../yara-rules/) | `14` |
| [`osx_stealer_icmacos`](../yara-rules/) | `8` |
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
| 2026-11-15 02:34:20 | **Local File** | `osx_stealer_icmacos` | macos_stealers_Generic_stealers_yar | [`ad37f66434...`](https://www.virustotal.com/gui/file/ad37f66434ff098ffccf20caf5753d0b2f180a2904c389970ad0bb0294c046e4) | `28/62` | `trojan.stealer/bmhm` |
| 2026-11-15 02:34:20 | **Local File** | `osx_stealer_icmacos` | macos_stealers_Generic_stealers_yar | [`afdcaa1830...`](https://www.virustotal.com/gui/file/afdcaa1830a83f8ad418ac6d21aabe2ba626443956a3caf01054d5b339b9d8cb) | `25/63` | `trojan.stealer/amos` |
| 2026-11-15 02:34:20 | **Local File** | `osx_stealer_icmacos` | macos_stealers_Generic_stealers_yar | [`68c1691d2b...`](https://www.virustotal.com/gui/file/68c1691d2be97fa6119aaf85f20a76a5fbb81cf560f2c527ca517b12e51ee0ca) | `28/58` | `trojan.stealer/amos` |
| 2026-11-15 01:38:36 | **MalwareBazaar** | `osx_stealer_icmacos` | macos_stealers_Generic_stealers_yar | [`c8136413ad...`](https://www.virustotal.com/gui/file/c8136413ad38a1028050f5d508e25267b518c5fdeac80b6442103d1009d8924c) | `28/52` | `trojan.stealer/amos` |
| 2026-11-15 01:38:36 | **MalwareBazaar** | `osx_stealer_icmacos` | macos_stealers_Generic_stealers_yar | [`d9df05a3fb...`](https://www.virustotal.com/gui/file/d9df05a3fb68d302ecf134a1214b609c6ec0a3fb9122907214afac3908b587f4) | `29/55` | `trojan.stealer/amos` |
| 2026-11-15 01:38:36 | **MalwareBazaar** | `osx_stealer_icmacos` | macos_stealers_Generic_stealers_yar | [`e52855d447...`](https://www.virustotal.com/gui/file/e52855d447d152bb698e565f361161cdc8946183ab09bf3cbea89765a2b5ff31) | `35/63` | `trojan.stealer/amos` |
| 2026-11-15 01:38:36 | **MalwareBazaar** | `osx_stealer_icmacos` | macos_stealers_Generic_stealers_yar | [`a9b21ac011...`](https://www.virustotal.com/gui/file/a9b21ac0112855b835b5e5850ef167471eff7305d42b3a8104c1961b257a444d) | `35/63` | `trojan.stealer/amos` |
| 2026-11-15 01:38:36 | **MalwareBazaar** | `osx_stealer_icmacos` | macos_stealers_Generic_stealers_yar | [`bc8d70f000...`](https://www.virustotal.com/gui/file/bc8d70f000e73c0c7a69a2676805190e7109cab59df3e34c5a74d2cb7f13a7e4) | `33/62` | `trojan.stealer/amos` |
| 2026-11-14 15:28:11 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`e5566d680f...`](https://www.virustotal.com/gui/file/e5566d680f0c6484b51bceb7d737340bd43aff97164b24bff8b326d02c038af4) | `35/63` | `trojan.stealer/amos` |
| 2026-11-14 15:28:11 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`ae4f1b9547...`](https://www.virustotal.com/gui/file/ae4f1b9547db90636514df913a422eff22ebf1cf60712e1f1ec5753b6e26a9e8) | `33/60` | `trojan.stealer/amos` |
| 2026-11-14 15:28:11 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`2d352712ca...`](https://www.virustotal.com/gui/file/2d352712cad9e47d9c8ce0b62589e7c09c2a5dd97bd35bf72140a252cc600ea3) | `33/61` | `trojan.stealer/amos` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | [`4886ea2ed8...`](https://www.virustotal.com/gui/file/4886ea2ed8fb7421ac16d687a29c46b66bdf87987c3bbf8d4cb1bb32a3fc157a) | `21/62` | `trojan.macho/cnhl` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | [`0039b2a4d4...`](https://www.virustotal.com/gui/file/0039b2a4d422d9a1c7990df9046fa77245852fef1dcbe1772a582f0adf459c8b) | `24/62` | `trojan.infostl/macho` |
| 2026-11-09 00:01:32 | **Local File** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`0039b2a4d4...`](https://www.virustotal.com/gui/file/0039b2a4d422d9a1c7990df9046fa77245852fef1dcbe1772a582f0adf459c8b) | `24/62` | `trojan.infostl/macho` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | [`1286c98e0e...`](https://www.virustotal.com/gui/file/1286c98e0e858357b3945bd9c15f07dcbf68e8f508ee484207ea47fb718f697d) | `26/62` | `trojan.infostl/macho` |
| 2026-11-09 00:01:32 | **Local File** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`1286c98e0e...`](https://www.virustotal.com/gui/file/1286c98e0e858357b3945bd9c15f07dcbf68e8f508ee484207ea47fb718f697d) | `26/62` | `trojan.infostl/macho` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | [`45ce45c4ab...`](https://www.virustotal.com/gui/file/45ce45c4ab0be0b8e07570d60d5fa7211d706c52ad2ae0b1691560121e71052e) | `27/63` | `trojan.infostl/macho` |
| 2026-11-09 00:01:32 | **Local File** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`45ce45c4ab...`](https://www.virustotal.com/gui/file/45ce45c4ab0be0b8e07570d60d5fa7211d706c52ad2ae0b1691560121e71052e) | `27/63` | `trojan.infostl/macho` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | [`0fe422f752...`](https://www.virustotal.com/gui/file/0fe422f752f3e1fa75d3ad4556a1ca2a1a1e39bf883ee54e40698400e799d3f0) | `27/63` | `trojan.infostl/macho` |
| 2026-11-09 00:01:32 | **Local File** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`0fe422f752...`](https://www.virustotal.com/gui/file/0fe422f752f3e1fa75d3ad4556a1ca2a1a1e39bf883ee54e40698400e799d3f0) | `27/63` | `trojan.infostl/macho` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | [`96b908b6ab...`](https://www.virustotal.com/gui/file/96b908b6ab84aba07cbffcdc84aa973a3f7dbbead1a7ca836c4b4b19635fc4bf) | `23/63` | `trojan.pamstealer/abtrojan` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | [`234815e6e0...`](https://www.virustotal.com/gui/file/234815e6e03e8da6274c8f80d7cc2250ffd81ff3cfea88c61679282881be04dd) | `24/62` | `trojan.macho/pamstealer` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | [`a22d3b565a...`](https://www.virustotal.com/gui/file/a22d3b565ae34e315d8787a2d7f772b325eb8ef74d5917b77e7d5e079bb76470) | `24/62` | `trojan.macho/abtrojan` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | [`6db19db41d...`](https://www.virustotal.com/gui/file/6db19db41d3f023a6d5d5444e9362bad9657b9b92af2db90abd261c993a52520) | `27/63` | `trojan.infostl/pamstealer` |
| 2026-11-09 00:01:32 | **Local File** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`6db19db41d...`](https://www.virustotal.com/gui/file/6db19db41d3f023a6d5d5444e9362bad9657b9b92af2db90abd261c993a52520) | `27/63` | `trojan.infostl/pamstealer` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | [`fb2e274ae9...`](https://www.virustotal.com/gui/file/fb2e274ae9dcd0ff6e294d1e4785e06c7023a46abdcf7a063af0ab6f6c6fe251) | `24/63` | `trojan.pamstealer/abtrojan` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | [`5f3c2f6b4e...`](https://www.virustotal.com/gui/file/5f3c2f6b4e9bfbad3ee2ead10955aedf7de8ef9af23d7298f5fdb58d88e05b06) | `26/63` | `trojan.infostl/macho` |
| 2026-11-09 00:01:32 | **Local File** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`5f3c2f6b4e...`](https://www.virustotal.com/gui/file/5f3c2f6b4e9bfbad3ee2ead10955aedf7de8ef9af23d7298f5fdb58d88e05b06) | `26/63` | `trojan.infostl/macho` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | [`5d00706467...`](https://www.virustotal.com/gui/file/5d00706467733fa7533a627c335242c6dbfff44722ac7bdb30d719d9a31b974a) | `26/63` | `trojan.infostl/macho` |
| 2026-11-09 00:01:32 | **Local File** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`5d00706467...`](https://www.virustotal.com/gui/file/5d00706467733fa7533a627c335242c6dbfff44722ac7bdb30d719d9a31b974a) | `26/63` | `trojan.infostl/macho` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | [`d04adb8791...`](https://www.virustotal.com/gui/file/d04adb87914b01bb6ceb022a82b62d57c894459d5057cc821d58c0c1fe9ab31e) | `12/62` | `trojan.infostl/pamstealer` |
| 2026-11-09 00:01:32 | **Local File** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`d04adb8791...`](https://www.virustotal.com/gui/file/d04adb87914b01bb6ceb022a82b62d57c894459d5057cc821d58c0c1fe9ab31e) | `12/62` | `trojan.infostl/pamstealer` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer_Keychain_Helper` | macos_stealers_pam_stealer_yar | `c77f94d0a5...` | `N/A` | `N/A` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Avenger_Stealer` | macos_stealers_pam_stealer_yar | [`06fdd1d97d...`](https://www.virustotal.com/gui/file/06fdd1d97df1105c542ddb881d751b659d555b5522c266f6364dae9f350fcfd0) | `34/63` | `trojan.pamstealer/pamsteal` |
| 2026-11-09 00:01:32 | **Local File** | `OSX_Foxveil_AMOS_Stage4_Generic` | macos_stealers_amos_yar | [`06fdd1d97d...`](https://www.virustotal.com/gui/file/06fdd1d97df1105c542ddb881d751b659d555b5522c266f6364dae9f350fcfd0) | `34/63` | `trojan.pamstealer/pamsteal` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`323214d1eb...`](https://www.virustotal.com/gui/file/323214d1eb020eb1919c87bc48541f1e2997082279969adc77f52b6cc17f0135) | `31/62` | `trojan.stealer/amos` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`a0d1321649...`](https://www.virustotal.com/gui/file/a0d1321649b45899e56bd86f5dffec509f0cb8ac6e44acafb38f55649a69cbb0) | `34/63` | `trojan.stealer/amos` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`1db680ecf7...`](https://www.virustotal.com/gui/file/1db680ecf7e3c1668f2454df9d661fe3bf84a4e82031725bd871f8eeffd59eff) | `34/63` | `trojan.stealer/amos` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`eea3fc56ed...`](https://www.virustotal.com/gui/file/eea3fc56edae8f987bd841192f5810d240d27662e976d1087a68945f0e923172) | `33/63` | `trojan.stealer/amos` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`0eefe5dd56...`](https://www.virustotal.com/gui/file/0eefe5dd5605680e24f2b6c0cb75f5dcdc4688b7c0f8ee2986a592a326cabc5f) | `33/63` | `trojan.stealer/amos` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`503b965c67...`](https://www.virustotal.com/gui/file/503b965c67a4712791ce7cbdcbecd492fcb85bdbebb777ebffb4aa74708eb3c6) | `32/63` | `trojan.stealer/amos` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`b056036d41...`](https://www.virustotal.com/gui/file/b056036d41d9992cde1cff4c9db6ca343ce86e41fd4394b382df0db6d1c81989) | `33/63` | `trojan.stealer/amos` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`dd9f917582...`](https://www.virustotal.com/gui/file/dd9f917582660b3d1623203343a57c8984e95b4503cf2fd9295fbda832d3bf6b) | `31/57` | `trojan.stealer/amos` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`4f9bfba5dc...`](https://www.virustotal.com/gui/file/4f9bfba5dc5b19360bd785ac5df0da4310e90da7cf3c0c1330ee77de037e0ee9) | `34/63` | `trojan.stealer/amos` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`1c4e9a6a9b...`](https://www.virustotal.com/gui/file/1c4e9a6a9bcce85414ef68e51bb2b0b8a869613ffd17dfde4062f84a17f4f249) | `35/62` | `trojan.stealer/amos` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`21eceb4b63...`](https://www.virustotal.com/gui/file/21eceb4b63db325a89dedc3e6b0595b10731e25dee8158510ef0f91b49acae53) | `23/63` | `trojan.stealer/amos` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `Macho_Trojan_CloudSync_1006YR` | macos_droppers_cloudsync_yar | [`b3cca282ed...`](https://www.virustotal.com/gui/file/b3cca282ed4a60bda2297d84eb3fc0ecb74cae57a913ebcbc409fa0ee10b2845) | `31/61` | `trojan.cloudsyncd/bmjp` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `Macho_Trojan_CloudSync_Generic` | macos_droppers_cloudsync_yar | [`b3cca282ed...`](https://www.virustotal.com/gui/file/b3cca282ed4a60bda2297d84eb3fc0ecb74cae57a913ebcbc409fa0ee10b2845) | `31/61` | `trojan.cloudsyncd/bmjp` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `Macho_Trojan_CloudSync_1006YR` | macos_droppers_cloudsync_yar | [`e8b7503f40...`](https://www.virustotal.com/gui/file/e8b7503f40fbcc41ed6769584b410da29827e505160290335454214074b7a511) | `30/63` | `trojan.cloudsyncd/macho` |
| 2026-11-05 20:49:02 | **MalwareBazaar** | `Macho_Trojan_CloudSync_Generic` | macos_droppers_cloudsync_yar | [`e8b7503f40...`](https://www.virustotal.com/gui/file/e8b7503f40fbcc41ed6769584b410da29827e505160290335454214074b7a511) | `30/63` | `trojan.cloudsyncd/macho` |

# Yarafy Telemetry & Threat Hunting Report

**Last Run:** `2026-11-03T18:10:01.791690+00:00`
**Total Samples Scanned:** `20983` | **Total Rule Hits:** `612`

## Hits Breakdown by Source Feed
| Source Feed | Total Hits |
| :--- | :--- |
| **MalwareBazaar** | `288` |
| **VirusTotal Enterprise** | `43` |
| **Local File** | `281` |

## Hits Breakdown by Platform
| Platform | Total Hits |
| :--- | :--- |
| **MACOS** | `612` |
| **WINDOWS** | `0` |
| **LINUX** | `0` |
| **NON-PE** | `0` |

## Hits Breakdown by YARA Rule
| Rule Name | Total Detections |
| :--- | :--- |
| [`macOS_ClickFix_AppleScript_Dropper`](../yara-rules/) | `266` |
| [`OSX_Malware_EvilQuest_ThiefQuest`](../yara-rules/) | `266` |
| [`OSX_Stealer_AMOS_Generic`](../yara-rules/) | `39` |
| [`OSX_Foxveil_AMOS_Stage4_Generic`](../yara-rules/) | `18` |
| [`MALW_macOS_MacSync_Stealer_Universal`](../yara-rules/) | `7` |
| [`APT_macOS_RustBucket_Behavioral_Indicators`](../yara-rules/) | `3` |
| [`Macho_Trojan_CloudSync_Generic`](../yara-rules/) | `3` |
| [`Macho_Trojan_CloudSync_1006YR`](../yara-rules/) | `2` |
| [`Macho_Jockey_Implant`](../yara-rules/) | `2` |
| [`Macho_Trojan_CloudSync_1007YR`](../yara-rules/) | `1` |
| [`Macho_Trojan_CloudSync_DMG`](../yara-rules/) | `1` |
| [`Macho_hVNCRat_generic`](../yara-rules/) | `1` |
| [`Macho_hVNCRat_campaign`](../yara-rules/) | `1` |
| [`Macho_hVNCRat_shelldropper`](../yara-rules/) | `1` |
| [`macOS_Backdoor_C5_Implant`](../yara-rules/) | `1` |

## Recent Positive Detections
| Timestamp | Source Feed | Rule | Platform | SHA256 | VT Detection | VT Threat Label |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-11-03 18:10:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`d561097aaf...`](https://www.virustotal.com/gui/file/d561097aaf56697eafd98e5fe24297866c9ea64375db931fa99dc8dfd640b84c) | `27/62` | `trojan.amos/infostl` |
| 2026-11-03 18:10:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`85733cc2d4...`](https://www.virustotal.com/gui/file/85733cc2d4fc2697579777f402c154603fd6576921698ed601bd636420329fe4) | `20/62` | `trojan.amos/infostl` |
| 2026-11-03 18:10:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`937e0b01af...`](https://www.virustotal.com/gui/file/937e0b01afe0b72a92d8b5cd0284f057240e833d783f5efb1385f9f5a600c320) | `20/63` | `trojan.amos/infostl` |
| 2026-11-03 18:10:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`ae6a965e36...`](https://www.virustotal.com/gui/file/ae6a965e363eb206757d4b00741e2b7c0937f1efbb256df9007177421ded6962) | `17/63` | `trojan.amos/lummastealer` |
| 2026-11-03 18:10:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`46bcabf552...`](https://www.virustotal.com/gui/file/46bcabf552548de2f2fb4f4c3781d10aa2cd8e3699be5b5616a6c4df1039f981) | `19/62` | `trojan.amos/infostl` |
| 2026-11-03 18:10:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`bd4fb92057...`](https://www.virustotal.com/gui/file/bd4fb920575b7fa5f2b856cc49af0e6f55f0062dc67bb378aa4cb36760118c3e) | `16/63` | `trojan.amos/lummastealer` |
| 2026-11-03 18:10:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`910e33613d...`](https://www.virustotal.com/gui/file/910e33613d9ed72442909f57564d8aba029b77422b1c3138deadb8732d882d4a) | `20/63` | `trojan.amos/infostl` |
| 2026-11-03 18:10:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`48b170f32c...`](https://www.virustotal.com/gui/file/48b170f32c51d94fa7d9d2040b753500e8e3e23c934e3b900cad733b33687bc0) | `20/62` | `trojan.infostl/amos` |
| 2026-11-03 18:10:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`9f633733db...`](https://www.virustotal.com/gui/file/9f633733db4d5c8d085beb28c3ec145a7e0d0af6ea29f1092d410e3bbe833ac1) | `10/63` | `trojan.amos` |
| 2026-11-03 18:10:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`1dffdfbda8...`](https://www.virustotal.com/gui/file/1dffdfbda8c09dd397b1d65ef019202c1dd12c1b172a6f90e1f45918f3a9a4b7) | `21/62` | `trojan.infostl/amos` |
| 2026-11-03 18:10:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`9d3df907e1...`](https://www.virustotal.com/gui/file/9d3df907e1aae13743a47276d4e06ba974e3781763fa23f99c09867609a4fb4a) | `25/61` | `trojan.amos/infostl` |
| 2026-11-02 17:14:50 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`95b3a52bad...`](https://www.virustotal.com/gui/file/95b3a52bad5da0468d6af8a8c56e0ca7e307c2c0151f2531903e27c49458d308) | `29/57` | `trojan.amos/infostl` |
| 2026-11-02 17:14:50 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`b92921e816...`](https://www.virustotal.com/gui/file/b92921e81666ba02fcd593c5f18aa8952b639d1fe7d13849677dd27954c479e8) | `24/63` | `trojan.amos/infostl` |
| 2026-11-02 17:14:50 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`197596c123...`](https://www.virustotal.com/gui/file/197596c12388be1a4e07197e5b98535472a672ceab2db16c8c3737a025ffbb0d) | `21/62` | `trojan.amos/infostl` |
| 2026-11-02 17:14:50 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`ec038d8ecd...`](https://www.virustotal.com/gui/file/ec038d8ecdc9f33786ec79dab5b30ac1682bc9378540e1a7e775dda5c8bdb6b5) | `21/62` | `trojan.amos/infostl` |
| 2026-11-02 17:14:50 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`d314670054...`](https://www.virustotal.com/gui/file/d3146700547025c387b0f3e707f391d59f2b62c4c60b6ecbf5134c79e01d67e1) | `28/62` | `trojan.amos/infostl` |
| 2026-11-02 17:14:50 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`93c9298f7f...`](https://www.virustotal.com/gui/file/93c9298f7f23e0bdfc19785099fc85bb04acae14bbfe9f9cc3cb9355447ac47c) | `23/63` | `trojan.amos/infostl` |
| 2026-11-02 17:14:50 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`ba2fb68385...`](https://www.virustotal.com/gui/file/ba2fb68385233683f785e3bae69cb79360a2a6c48b43b44f9c43a3b8f54ca1a9) | `22/62` | `trojan.amos/infostl` |
| 2026-11-02 17:14:50 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`5c18af8d98...`](https://www.virustotal.com/gui/file/5c18af8d98e6b13dbf5b8b408d817a302a5239311fff0da0319e11c9d5ce76cb) | `26/52` | `trojan.amos/infostl` |
| 2026-11-02 17:14:50 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`b01d5a9d05...`](https://www.virustotal.com/gui/file/b01d5a9d05b788cdbff787e3317e207caec6b6e08979a1efe0f7764cbfdd86dc) | `22/62` | `trojan.amos/infostl` |
| 2026-11-02 17:14:50 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`64fb0d531b...`](https://www.virustotal.com/gui/file/64fb0d531b51a70cd4a40d4b2ece6c98d7a3d453c5d5b148f4cae75208584677) | `21/62` | `trojan.amos/infostl` |
| 2026-11-01 16:48:03 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`6ee52429a2...`](https://www.virustotal.com/gui/file/6ee52429a22ee09c723794eaa590cd4f08a4109d5e3bd9bb7e71f94de3e3851a) | `28/63` | `trojan.amos/asmalwfi` |
| 2026-11-01 16:48:03 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`1ec9297709...`](https://www.virustotal.com/gui/file/1ec9297709a225f912fc7145f43654bc1a6b61e56c9684bf22c6aaf0fad98289) | `29/62` | `trojan.amos/infostl` |
| 2026-11-01 16:48:03 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`981ff25c88...`](https://www.virustotal.com/gui/file/981ff25c886308d5350b4446184f14406be6cc01186bb19ebf0de8cf843e392f) | `29/62` | `trojan.amos/infostl` |
| 2026-11-01 16:48:03 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`b28c2590e6...`](https://www.virustotal.com/gui/file/b28c2590e605070470bbad8963a3f18abeb7c972ac65ba3dc77622cb3cb85324) | `31/63` | `trojan.amos/infostl` |
| 2026-11-01 16:48:03 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`9dc758ca7a...`](https://www.virustotal.com/gui/file/9dc758ca7a1e93859946e18206a4b3f34ef76b778b43f5226a40ffeb2444db48) | `29/61` | `trojan.amos/infostl` |
| 2026-11-01 16:48:03 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`e9e8cbb6e6...`](https://www.virustotal.com/gui/file/e9e8cbb6e60dec133269e83d5c9564b5fca8ff5293233ae2766bdfc1e17503d0) | `31/62` | `trojan.amos/infostl` |
| 2026-11-01 16:48:03 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`af95c361f4...`](https://www.virustotal.com/gui/file/af95c361f4a077a251c9879c2cbadd1394302db083b6753bba55784d792dcc2c) | `30/63` | `trojan.amos/infostl` |
| 2026-11-01 16:48:03 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`cd3569812a...`](https://www.virustotal.com/gui/file/cd3569812aefac3396be7f11124c068e200dc83e7882832adf9161e7b2656f75) | `28/63` | `trojan.amos/abmtrojan` |
| 2026-11-01 16:48:03 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`32da533a3e...`](https://www.virustotal.com/gui/file/32da533a3e59d5b86c115b4302897f5d8a5d791b34f9deb2b933c3476979fcd1) | `29/60` | `trojan.amos/infostl` |
| 2026-11-01 16:48:03 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`46b32e8232...`](https://www.virustotal.com/gui/file/46b32e8232bd0b359d3cdd5891c9030a58f0a949225cb3eba1b72014a034d5b3) | `30/63` | `trojan.amos/abtrojan` |
| 2026-11-01 16:48:03 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`21f5852d9a...`](https://www.virustotal.com/gui/file/21f5852d9ade22f90e63e67898dcc6f0fb240e782c826f513e34d685d3ff8ca8) | `30/63` | `trojan.amos/infostl` |
| 2026-11-01 15:48:08 | **Local File** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | `2338d9333c...` | `N/A` | `N/A` |
| 2026-11-01 15:48:08 | **Local File** | `Macho_Jockey_Implant` | macOS | `2338d9333c...` | `N/A` | `N/A` |
| 2026-11-01 15:48:08 | **Local File** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | `a1be741da7...` | `N/A` | `N/A` |
| 2026-11-01 15:48:08 | **Local File** | `Macho_Jockey_Implant` | macOS | `a1be741da7...` | `N/A` | `N/A` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`3168c669fa...`](https://www.virustotal.com/gui/file/3168c669fae2b267641c203e1abf6fa8e6011201ab8187dfe06d0168ff957c7f) | `22/63` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`2cbc03368b...`](https://www.virustotal.com/gui/file/2cbc03368b2c63103af1e705a0dd42efe93514f87461ee14d9df858ec19e6a68) | `21/63` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`0611cf61fa...`](https://www.virustotal.com/gui/file/0611cf61fa7ef2bab6cabd19207b0256a69a2981966b1f32691057c7dc03a433) | `21/63` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`b3ffa0ce81...`](https://www.virustotal.com/gui/file/b3ffa0ce815def773ca9e9807af167f1378fcebf91eafd1ddaf86b1238fa5412) | `29/56` | `trojan.infostl/macho` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`9078f1a436...`](https://www.virustotal.com/gui/file/9078f1a436d99d859645a65df94b93e80e516972146ce895efed935c642ccba9) | `23/62` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`d6ce062f26...`](https://www.virustotal.com/gui/file/d6ce062f26b771b19a085a727ca13d5c568037cee3039a1bbf8c261e8c44e363) | `25/63` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`114b69aa53...`](https://www.virustotal.com/gui/file/114b69aa53a40d7702a11ff81e3fc1d7104a3132c3395f403e6033c68f181230) | `22/63` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`470034fb48...`](https://www.virustotal.com/gui/file/470034fb481dec06585288f94abcc8e9375b12c29a86d64dc30b1a68c24c0282) | `21/62` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`1fbdd92514...`](https://www.virustotal.com/gui/file/1fbdd925143e28ea6542bcc3b15cd44de7c0b226082f6f99450f0e1822db2068) | `29/56` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`acd2e7872e...`](https://www.virustotal.com/gui/file/acd2e7872edb9612a92e835bd243a83d185407e1680dea2e70845620874ff1dc) | `31/63` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`6335a44275...`](https://www.virustotal.com/gui/file/6335a4427566446e65202fb47dac5bac3433308c5daabf2293afb3c795f5353c) | `32/63` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`87367d9c60...`](https://www.virustotal.com/gui/file/87367d9c60bb5923526138d10340a60d13d150f3280bba966d0ef8a335893635) | `31/62` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`e2fcffd2ce...`](https://www.virustotal.com/gui/file/e2fcffd2ce53fe38b555db86e14e96b706eb811367dba4725f96a248c667b9a8) | `34/59` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`643af4611e...`](https://www.virustotal.com/gui/file/643af4611e02c36280cdf4a9b22be3488ec48278db7511e268c13d0c11a0daf9) | `20/40` | `trojan.amos/infostl` |

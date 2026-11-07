# Yarafy Telemetry & Threat Hunting Report

**Last Run:** `2026-11-07T20:27:02.759219+00:00`
**Total Samples Scanned:** `22535` | **Total Rule Hits:** `635`

## Hits Breakdown by Source Feed
| Source Feed | Total Hits |
| :--- | :--- |
| **MalwareBazaar** | `311` |
| **VirusTotal Enterprise** | `43` |
| **Local File** | `281` |

## Hits Breakdown by Platform
| Platform | Total Hits |
| :--- | :--- |
| **MACOS** | `635` |
| **WINDOWS** | `0` |
| **LINUX** | `0` |
| **NON-PE** | `0` |

## Hits Breakdown by YARA Rule
| Rule Name | Total Detections |
| :--- | :--- |
| [`macOS_ClickFix_AppleScript_Dropper`](../yara-rules/) | `284` |
| [`OSX_Malware_EvilQuest_ThiefQuest`](../yara-rules/) | `266` |
| [`OSX_Stealer_AMOS_Generic`](../yara-rules/) | `40` |
| [`OSX_Foxveil_AMOS_Stage4_Generic`](../yara-rules/) | `18` |
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

## Recent Positive Detections
| Timestamp | Source Feed | Rule | Platform | SHA256 | VT Detection | VT Threat Label |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
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
| 2026-11-03 18:10:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`ae6a965e36...`](https://www.virustotal.com/gui/file/ae6a965e363eb206757d4b00741e2b7c0937f1efbb256df9007177421ded6962) | `29/61` | `trojan.amos/macho` |
| 2026-11-03 18:10:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`46bcabf552...`](https://www.virustotal.com/gui/file/46bcabf552548de2f2fb4f4c3781d10aa2cd8e3699be5b5616a6c4df1039f981) | `22/51` | `trojan.amos/infostl` |
| 2026-11-03 18:10:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`bd4fb92057...`](https://www.virustotal.com/gui/file/bd4fb920575b7fa5f2b856cc49af0e6f55f0062dc67bb378aa4cb36760118c3e) | `27/60` | `trojan.amos/macho` |
| 2026-11-03 18:10:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`910e33613d...`](https://www.virustotal.com/gui/file/910e33613d9ed72442909f57564d8aba029b77422b1c3138deadb8732d882d4a) | `27/60` | `trojan.amos/infostl` |
| 2026-11-03 18:10:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`48b170f32c...`](https://www.virustotal.com/gui/file/48b170f32c51d94fa7d9d2040b753500e8e3e23c934e3b900cad733b33687bc0) | `30/62` | `trojan.amos/infostl` |
| 2026-11-03 18:10:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`9f633733db...`](https://www.virustotal.com/gui/file/9f633733db4d5c8d085beb28c3ec145a7e0d0af6ea29f1092d410e3bbe833ac1) | `31/63` | `trojan.amos/macho` |
| 2026-11-03 18:10:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`1dffdfbda8...`](https://www.virustotal.com/gui/file/1dffdfbda8c09dd397b1d65ef019202c1dd12c1b172a6f90e1f45918f3a9a4b7) | `32/63` | `trojan.amos/infostl` |
| 2026-11-03 18:10:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`9d3df907e1...`](https://www.virustotal.com/gui/file/9d3df907e1aae13743a47276d4e06ba974e3781763fa23f99c09867609a4fb4a) | `33/62` | `trojan.amos/infostl` |
| 2026-11-02 17:14:50 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`95b3a52bad...`](https://www.virustotal.com/gui/file/95b3a52bad5da0468d6af8a8c56e0ca7e307c2c0151f2531903e27c49458d308) | `29/57` | `trojan.amos/infostl` |
| 2026-11-02 17:14:50 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`b92921e816...`](https://www.virustotal.com/gui/file/b92921e81666ba02fcd593c5f18aa8952b639d1fe7d13849677dd27954c479e8) | `30/60` | `trojan.amos/infostl` |
| 2026-11-02 17:14:50 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`197596c123...`](https://www.virustotal.com/gui/file/197596c12388be1a4e07197e5b98535472a672ceab2db16c8c3737a025ffbb0d) | `27/55` | `trojan.amos/infostl` |
| 2026-11-02 17:14:50 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`ec038d8ecd...`](https://www.virustotal.com/gui/file/ec038d8ecdc9f33786ec79dab5b30ac1682bc9378540e1a7e775dda5c8bdb6b5) | `30/63` | `trojan.infostl/multiverze` |
| 2026-11-02 17:14:50 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`d314670054...`](https://www.virustotal.com/gui/file/d3146700547025c387b0f3e707f391d59f2b62c4c60b6ecbf5134c79e01d67e1) | `31/63` | `trojan.amos/infostl` |
| 2026-11-02 17:14:50 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`93c9298f7f...`](https://www.virustotal.com/gui/file/93c9298f7f23e0bdfc19785099fc85bb04acae14bbfe9f9cc3cb9355447ac47c) | `25/56` | `trojan.infostl/macho` |
| 2026-11-02 17:14:50 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`ba2fb68385...`](https://www.virustotal.com/gui/file/ba2fb68385233683f785e3bae69cb79360a2a6c48b43b44f9c43a3b8f54ca1a9) | `25/56` | `trojan.infostl/macho` |
| 2026-11-02 17:14:50 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`5c18af8d98...`](https://www.virustotal.com/gui/file/5c18af8d98e6b13dbf5b8b408d817a302a5239311fff0da0319e11c9d5ce76cb) | `28/56` | `trojan.infostl/macho` |
| 2026-11-02 17:14:50 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`b01d5a9d05...`](https://www.virustotal.com/gui/file/b01d5a9d05b788cdbff787e3317e207caec6b6e08979a1efe0f7764cbfdd86dc) | `31/63` | `trojan.amos/infostl` |
| 2026-11-02 17:14:50 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`64fb0d531b...`](https://www.virustotal.com/gui/file/64fb0d531b51a70cd4a40d4b2ece6c98d7a3d453c5d5b148f4cae75208584677) | `31/63` | `trojan.amos/infostl` |
| 2026-11-01 16:48:03 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`6ee52429a2...`](https://www.virustotal.com/gui/file/6ee52429a22ee09c723794eaa590cd4f08a4109d5e3bd9bb7e71f94de3e3851a) | `22/53` | `trojan.amos/abtrojan` |
| 2026-11-01 16:48:03 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`1ec9297709...`](https://www.virustotal.com/gui/file/1ec9297709a225f912fc7145f43654bc1a6b61e56c9684bf22c6aaf0fad98289) | `29/62` | `trojan.amos/infostl` |
| 2026-11-01 16:48:03 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`981ff25c88...`](https://www.virustotal.com/gui/file/981ff25c886308d5350b4446184f14406be6cc01186bb19ebf0de8cf843e392f) | `32/63` | `trojan.amos/infostl` |
| 2026-11-01 16:48:03 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`b28c2590e6...`](https://www.virustotal.com/gui/file/b28c2590e605070470bbad8963a3f18abeb7c972ac65ba3dc77622cb3cb85324) | `32/63` | `trojan.amos/infostl` |
| 2026-11-01 16:48:03 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`9dc758ca7a...`](https://www.virustotal.com/gui/file/9dc758ca7a1e93859946e18206a4b3f34ef76b778b43f5226a40ffeb2444db48) | `31/63` | `trojan.amos/infostl` |
| 2026-11-01 16:48:03 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | [`e9e8cbb6e6...`](https://www.virustotal.com/gui/file/e9e8cbb6e60dec133269e83d5c9564b5fca8ff5293233ae2766bdfc1e17503d0) | `31/62` | `trojan.amos/infostl` |

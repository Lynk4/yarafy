# Yarafy Telemetry & Threat Hunting Report

**Last Run:** `2026-10-08T10:38:30.346812+00:00`
**Total Samples Scanned:** `15110` | **Total Rule Hits:** `100`

## Hits Breakdown by Source Feed
| Source Feed | Total Hits |
| :--- | :--- |
| **MalwareBazaar** | `54` |
| **VirusTotal Enterprise** | `43` |
| **Local File** | `3` |

## Hits Breakdown by Platform
| Platform | Total Hits |
| :--- | :--- |
| **MACOS** | `100` |
| **WINDOWS** | `0` |
| **LINUX** | `0` |
| **NON-PE** | `0` |

## Hits Breakdown by YARA Rule
| Rule Name | Total Detections |
| :--- | :--- |
| [`macOS_ClickFix_AppleScript_Dropper`](../yara-rules/) | `39` |
| [`OSX_Stealer_AMOS_Generic`](../yara-rules/) | `32` |
| [`OSX_Foxveil_AMOS_Stage4_Generic`](../yara-rules/) | `17` |
| [`MALW_macOS_MacSync_Stealer_Universal`](../yara-rules/) | `6` |
| [`APT_macOS_RustBucket_Behavioral_Indicators`](../yara-rules/) | `3` |
| [`Macho_Trojan_CloudSync_Generic`](../yara-rules/) | `3` |

## Recent Positive Detections
| Timestamp | Source Feed | Rule | Platform | SHA256 | VT Detection | VT Threat Label |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `MALW_macOS_MacSync_Stealer_Universal` | macos_MALW_macOS_MacSync_Stealer | [`f5471a00bb...`](https://www.virustotal.com/gui/file/f5471a00bb6cdaf01e44311c04de2e66c6f92ccc4b8e42bbb1bcb4e48f86ef3e) | `33/62` | `trojan.stealer/coins` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `MALW_macOS_MacSync_Stealer_Universal` | macos_MALW_macOS_MacSync_Stealer | [`f80ff07231...`](https://www.virustotal.com/gui/file/f80ff072316e2d62490df743cbd5363bfb6ec5459409cc162d0602f7a1c607bb) | `32/62` | `trojan.stealer/coins` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `Macho_Trojan_CloudSync_Generic` | macos_cloud_sync | [`3220acfe8a...`](https://www.virustotal.com/gui/file/3220acfe8afe73c9beec11714cb95e324c56fe3386c5109fcd4cb5ba4873c3a5) | `28/63` | `trojan.abtrojan/adhl` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`fd0cd32edf...`](https://www.virustotal.com/gui/file/fd0cd32edfe9b4f68dcc2fddb8f27c6102e9a9c8b90c5def07ac8e62b2a75303) | `35/63` | `trojan.stealer/amos` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`0f5669e692...`](https://www.virustotal.com/gui/file/0f5669e692760a1316a750622ecd871897d32da3486dd323f024d680543c368a) | `33/59` | `trojan.stealer/amos` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`73491d3f3b...`](https://www.virustotal.com/gui/file/73491d3f3bcfe0c1d4ebefecf8230d0c460fa89703381d9b8923daaa4be170f4) | `34/61` | `trojan.stealer/amos` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`579fb6787d...`](https://www.virustotal.com/gui/file/579fb6787dd60d5fb1ebfe275ccfa58e4b73db4cdc4909de23ac5dd3a9c52439) | `35/63` | `trojan.stealer/amos` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`63320c69b5...`](https://www.virustotal.com/gui/file/63320c69b5733e125a587216bf2a93ac239c2a98686b2a1a00ec23f2b4177648) | `32/58` | `trojan.stealer/amos` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`38c8c79ec7...`](https://www.virustotal.com/gui/file/38c8c79ec773bfc700559243293f4b4409756d5adf63ad78a08d7ca2f38ee0dc) | `36/63` | `trojan.stealer/amos` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`6bfcdb4920...`](https://www.virustotal.com/gui/file/6bfcdb4920383375b7e519918df7eb4db751b974b5571a15ce66b82478012620) | `30/58` | `trojan.stealer/amos` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`4504006d19...`](https://www.virustotal.com/gui/file/4504006d1911057be42435d4625f03d83c4d0b7b6898d14beb9cdeba6cf667b9) | `33/63` | `trojan.amos/stealer` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `Macho_Trojan_CloudSync_Generic` | macos_cloud_sync | [`524a7bcc8e...`](https://www.virustotal.com/gui/file/524a7bcc8edcadc6f4381459f79769e1ec534aa78f66e5c38a6678bd55cf2572) | `24/58` | `trojan.abtrojan/class` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `Macho_Trojan_CloudSync_Generic` | macos_cloud_sync | [`cc54d90920...`](https://www.virustotal.com/gui/file/cc54d90920a73cc5e176664f61c6f601c95d693e431e79ae1148cb91e83c9235) | `25/63` | `trojan.abtrojan/class` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`689797d97d...`](https://www.virustotal.com/gui/file/689797d97d31c3893e2c8a792614262f1fa9e714d646aef46bc4a6371fa59126) | `34/63` | `trojan.stealer/amos` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `OSX_Foxveil_AMOS_Stage4_Generic` | macos_stealer | [`c4c7cc2f8e...`](https://www.virustotal.com/gui/file/c4c7cc2f8e281b36d0bc29de6e08d354d83c4f734acaded25e7c8dfb1f580db5) | `1/62` | `unknown` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `OSX_Foxveil_AMOS_Stage4_Generic` | macos_stealer | [`3740e3883b...`](https://www.virustotal.com/gui/file/3740e3883b64840461b3dfe2ce86695f32a14f28c8e0353c860ff6939a8c2538) | `10/62` | `trojan.stealer/amos` |
| 2026-09-23 05:01:05 | **MalwareBazaar** | `OSX_Foxveil_AMOS_Stage4_Generic` | macos_stealer | [`c48bd4f678...`](https://www.virustotal.com/gui/file/c48bd4f678a498b9173353d8fd400093541326e6b40a1a99c9a15fd28721ed69) | `30/62` | `trojan.infostl/stealer` |
| 2026-09-23 05:01:05 | **MalwareBazaar** | `OSX_Foxveil_AMOS_Stage4_Generic` | macos_stealer | [`08074ec033...`](https://www.virustotal.com/gui/file/08074ec033c1a5dcfb0125a352f7f499f29f61d8ed2ce2f693d48813074810d4) | `28/63` | `trojan.stealer/abtrojan` |
| 2026-09-23 05:01:05 | **MalwareBazaar** | `OSX_Foxveil_AMOS_Stage4_Generic` | macos_stealer | [`a7c0d024ed...`](https://www.virustotal.com/gui/file/a7c0d024ed24dcbc1b17cbda430a39edb52325c30ad9b7207c0267e43fbec4b7) | `29/63` | `trojan.stealer/abtrojan` |
| 2026-09-18 07:20:48 | **Local File** | `APT_macOS_RustBucket_Behavioral_Indicators` | macos_rust_bucket | [`3474d98ec9...`](https://www.virustotal.com/gui/file/3474d98ec917eac063525284c86585eb283f4188c7df2f31bf35c16f8787e81c) | `32/63` | `trojan.nukesped/lazarus` |
| 2026-09-18 07:20:48 | **Local File** | `APT_macOS_RustBucket_Behavioral_Indicators` | macos_rust_bucket | [`7887638bca...`](https://www.virustotal.com/gui/file/7887638bcafd57e2896c7c16698e927ce92fd7d409aae698d33cdca3ce8d25b8) | `33/62` | `trojan.nukesped/lazarus` |
| 2026-09-18 07:20:48 | **Local File** | `APT_macOS_RustBucket_Behavioral_Indicators` | macos_rust_bucket | [`9f54ca45b4...`](https://www.virustotal.com/gui/file/9f54ca45b40d1893537bd1899d2343146364d7e3ddca0d51f5c4c0cf238ecae4) | `28/59` | `trojan.lazarus/nukesped` |
| 2026-09-16 10:24:15 | **MalwareBazaar** | `OSX_Foxveil_AMOS_Stage4_Generic` | macos_stealer | [`4903c40fbd...`](https://www.virustotal.com/gui/file/4903c40fbdb96cf39f35ed592a886a39d230564b26dd80aef3fa6c58bc501551) | `23/59` | `trojan.amos/amosstealer` |
| 2026-09-16 10:24:15 | **MalwareBazaar** | `OSX_Foxveil_AMOS_Stage4_Generic` | macos_stealer | [`b95ea80546...`](https://www.virustotal.com/gui/file/b95ea805469383b5a419c5043de45bb2b13f36b3a513f98bd608b3f7294f064f) | `27/63` | `trojan.amos/amosstealer` |
| 2026-09-16 10:24:15 | **MalwareBazaar** | `OSX_Foxveil_AMOS_Stage4_Generic` | macos_stealer | [`76c2e4e7fb...`](https://www.virustotal.com/gui/file/76c2e4e7fb5290366d7bd04703ea60ec92d314ff651172387b9c6dbfca22b82a) | `28/62` | `trojan.amos/stealer` |
| 2026-09-16 10:24:15 | **MalwareBazaar** | `OSX_Foxveil_AMOS_Stage4_Generic` | macos_stealer | [`60362accd0...`](https://www.virustotal.com/gui/file/60362accd00f57e929f33799f43f6d9588f469577004eb05aba96bc21ca119ba) | `29/60` | `trojan.amos/infostl` |
| 2026-09-16 10:24:15 | **MalwareBazaar** | `OSX_Foxveil_AMOS_Stage4_Generic` | macos_stealer | [`3e5097274c...`](https://www.virustotal.com/gui/file/3e5097274c863873dfc79f315c39c30eb61e49e74db1bcee76bb372f584b9ff3) | `27/59` | `trojan.amos/infostl` |
| 2026-09-16 10:24:15 | **MalwareBazaar** | `OSX_Foxveil_AMOS_Stage4_Generic` | macos_stealer | [`fd4896cf61...`](https://www.virustotal.com/gui/file/fd4896cf61b676a39918f119247f3f7c746b29645e732ab09b3318f8479da728) | `26/62` | `trojan.stealer/multiverze` |
| 2026-09-16 10:24:15 | **MalwareBazaar** | `OSX_Foxveil_AMOS_Stage4_Generic` | macos_stealer | [`beac3bae8f...`](https://www.virustotal.com/gui/file/beac3bae8f10cbb37ddde43f41dc44c0dd1c19e8e38723700e901751f6bd5072) | `25/60` | `trojan.stealer/multiverze` |
| 2026-09-16 10:24:15 | **MalwareBazaar** | `OSX_Foxveil_AMOS_Stage4_Generic` | macos_stealer | [`b3c05142af...`](https://www.virustotal.com/gui/file/b3c05142afc6d7c708c55ba7a97dbb4272f43353205e8cab7b9a8117959cc270) | `23/59` | `trojan.stealer/multiverze` |
| 2026-09-16 10:24:15 | **MalwareBazaar** | `OSX_Foxveil_AMOS_Stage4_Generic` | macos_stealer | [`708a0836a8...`](https://www.virustotal.com/gui/file/708a0836a8c20e79f2ae522f097787326a90965e0532f3fd488d8d6e428f77b6) | `25/62` | `trojan.stealer/multiverze` |
| 2026-09-16 10:24:15 | **MalwareBazaar** | `OSX_Foxveil_AMOS_Stage4_Generic` | macos_stealer | [`204b5d236e...`](https://www.virustotal.com/gui/file/204b5d236e4384b23c1f0201bc52c06f32ef8eea679b975e9b432f2b111d1dbc) | `28/63` | `trojan.stealer/multiverze` |
| 2026-09-16 10:24:15 | **MalwareBazaar** | `OSX_Foxveil_AMOS_Stage4_Generic` | macos_stealer | [`a981fdba66...`](https://www.virustotal.com/gui/file/a981fdba66721eb21e7a3c0ab18e487247bbcf97158737ab8c80e98f4ec240dd) | `25/61` | `trojan.stealer/multiverze` |
| 2026-09-16 10:24:15 | **MalwareBazaar** | `OSX_Foxveil_AMOS_Stage4_Generic` | macos_stealer | [`841f0ccf4e...`](https://www.virustotal.com/gui/file/841f0ccf4e6e782476a0844cc861f7f44d7f321bc232444ef5f306fdba8944eb) | `26/63` | `trojan.stealer/amos` |
| 2026-09-05 20:36:41 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`170515dc93...`](https://www.virustotal.com/gui/file/170515dc93120111760cc8c9e1deefb9a81939d123749d15f13ad5eca55042da) | `21/61` | `trojan.coruna/falsesign` |
| 2026-09-05 15:21:19 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`7a8aac687e...`](https://www.virustotal.com/gui/file/7a8aac687ea67207c19e1c74edb73e8a1a341a0fae0b75f2b434054922763f99) | `15/61` | `trojan.macho/multiverze` |
| 2026-09-05 15:21:19 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`aa39343403...`](https://www.virustotal.com/gui/file/aa3934340337aaceee150fd8e2acaa5b5da71a59161585594e53d0477d9d87c6) | `23/63` | `trojan.coruna/falsesign` |
| 2026-09-05 07:20:33 | **VirusTotal Enterprise** | `MALW_macOS_MacSync_Stealer_Universal` | macos_MALW_macOS_MacSync_Stealer | [`9a8d315d8c...`](https://www.virustotal.com/gui/file/9a8d315d8cde1cb627c6844997f9db980174a478dbb1c936a9cd245d9f5745bb) | `8/76` | `trojan.coins` |
| 2026-09-04 05:40:37 | **VirusTotal Enterprise** | `OSX_Stealer_AMOS_Generic` | macos | [`c69dfd8e46...`](https://www.virustotal.com/gui/file/c69dfd8e46ebea022ac512d9596fe5b1345bcd631815f0e759ea2e941d80df93) | `33/76` | `trojan.stealer/amos` |
| 2026-09-04 05:40:37 | **VirusTotal Enterprise** | `OSX_Stealer_AMOS_Generic` | macos | [`6cbcd5c5b3...`](https://www.virustotal.com/gui/file/6cbcd5c5b3c1bdef8d23f019fce29221ffc0f6ea32c79e2d1a1b57f40571bca5) | `33/76` | `trojan.stealer/amos` |
| 2026-09-04 05:40:37 | **VirusTotal Enterprise** | `OSX_Stealer_AMOS_Generic` | macos | [`124f942b3f...`](https://www.virustotal.com/gui/file/124f942b3f3dc9052766ba141f76d434f995f83e95a7ce8a53018c4f2f377410) | `27/76` | `trojan.stealer/amos` |
| 2026-09-04 05:40:37 | **VirusTotal Enterprise** | `OSX_Stealer_AMOS_Generic` | macos | [`a5c87b8f2d...`](https://www.virustotal.com/gui/file/a5c87b8f2d582e6c145a4f07b2e1a475e4da74dbfd33dc49fffdfc27a184666c) | `18/76` | `trojan.stealer/amos` |
| 2026-09-04 05:40:37 | **VirusTotal Enterprise** | `OSX_Stealer_AMOS_Generic` | macos | [`e97f729d30...`](https://www.virustotal.com/gui/file/e97f729d30190d8e798254e12bbc95c31c8c6f82718d582fe8fa30a0ac4d2c11) | `18/76` | `trojan.stealer/amos` |
| 2026-09-04 05:40:37 | **VirusTotal Enterprise** | `OSX_Stealer_AMOS_Generic` | macos | [`aa293672aa...`](https://www.virustotal.com/gui/file/aa293672aa84cf35ce0418ce081f23ea7fc028926f5b369464923ea753c33f21) | `32/76` | `trojan.stealer/amos` |
| 2026-09-03 17:22:39 | **VirusTotal Enterprise** | `OSX_Stealer_AMOS_Generic` | macos | [`3b9aa24a02...`](https://www.virustotal.com/gui/file/3b9aa24a02b112fd7881c9c7fdccba1b4677e138b4571d211b54a1cf5b68fe0d) | `28/76` | `trojan.stealer/amos` |
| 2026-09-03 17:22:39 | **VirusTotal Enterprise** | `OSX_Stealer_AMOS_Generic` | macos | [`a5655a9b4c...`](https://www.virustotal.com/gui/file/a5655a9b4c4889bfd7fcbf928d4979afcacb1577fff3697defae7c0cccafea8a) | `17/76` | `trojan.stealer/amos` |
| 2026-09-03 05:14:39 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`aaa56fb51a...`](https://www.virustotal.com/gui/file/aaa56fb51a0dd7cf74667d090d456cc24f6b5b3b3484831f4371e38481cb9fb4) | `11/76` | `trojan.amos/camelot` |
| 2026-09-03 05:14:39 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`9a2e9044e2...`](https://www.virustotal.com/gui/file/9a2e9044e2c60d273fab7035a00740c7ec49dc1c1b82e8c697b4b90ab2f2db4f) | `11/76` | `trojan.amos/camelot` |
| 2026-09-03 05:14:39 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`8151817669...`](https://www.virustotal.com/gui/file/81518176695d31946a991e2ed84c458d687b16ea77b92e718d38a2d915be8bdb) | `8/76` | `trojan.amos/camelot` |
| 2026-09-03 05:14:39 | **VirusTotal Enterprise** | `OSX_Stealer_AMOS_Generic` | macos | [`520ac683d4...`](https://www.virustotal.com/gui/file/520ac683d4919cc6cc40104dbf1c147df89baee25a4d591ac635eae8c3b6a1a2) | `28/76` | `trojan.stealer/amos` |

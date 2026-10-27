# Yarafy Telemetry & Threat Hunting Report

**Last Run:** `2026-10-27T22:02:30.007835+00:00`
**Total Samples Scanned:** `18397` | **Total Rule Hits:** `264`

## Hits Breakdown by Source Feed
| Source Feed | Total Hits |
| :--- | :--- |
| **MalwareBazaar** | `211` |
| **VirusTotal Enterprise** | `43` |
| **Local File** | `10` |

## Hits Breakdown by Platform
| Platform | Total Hits |
| :--- | :--- |
| **MACOS** | `264` |
| **WINDOWS** | `0` |
| **LINUX** | `0` |
| **NON-PE** | `0` |

## Hits Breakdown by YARA Rule
| Rule Name | Total Detections |
| :--- | :--- |
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

## Recent Positive Detections
| Timestamp | Source Feed | Rule | Platform | SHA256 | VT Detection | VT Threat Label |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-10-27 22:02:30 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`4f937f9bcf...`](https://www.virustotal.com/gui/file/4f937f9bcfbb1ac38a7c0f791a760425bb555ba8002752b879ddda303c1a425e) | `20/62` | `trojan.amos/infostl` |
| 2026-10-27 22:02:30 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`4fd0502c48...`](https://www.virustotal.com/gui/file/4fd0502c48d621cb9fec491391d408e9c19f5643b57b3841c9fa1d488c779d97) | `13/62` | `trojan.amos/pwbwx7` |
| 2026-10-27 22:02:30 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`8d8dd9808f...`](https://www.virustotal.com/gui/file/8d8dd9808f875b74c2ba8aa735c00e661b2d366f658d4d78a79bbb041b504eb2) | `15/62` | `trojan.amos/gr1b1g` |
| 2026-10-27 22:02:30 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`04e30db39d...`](https://www.virustotal.com/gui/file/04e30db39d13194ddd1d20dcc31779bf3e174d7957931be3aa7cb92f852fa11e) | `13/59` | `trojan.amos/gxt9ax` |
| 2026-10-27 22:02:30 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`46c09f852a...`](https://www.virustotal.com/gui/file/46c09f852a7f05361b8758d10aba4426d4eacab74ed6e0ea5fdef20812934133) | `11/57` | `trojan.amos/anhl` |
| 2026-10-27 22:02:30 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`c3ce73d8db...`](https://www.virustotal.com/gui/file/c3ce73d8dbdb4c9323ed56386f5c0861d69f3ef257f821705b9326ed8058b5e3) | `13/62` | `trojan.amos/lummastealer` |
| 2026-10-27 22:02:30 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`2b2db5ba05...`](https://www.virustotal.com/gui/file/2b2db5ba050175472c1ba8c4853b151de3a7ff55f3eeca901802ec75aa73b770) | `16/61` | `trojan.amos/abpws` |
| 2026-10-27 22:02:30 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`44e49692c1...`](https://www.virustotal.com/gui/file/44e49692c182143a7630be5decb072a12fb1462aaf143284411de135697896de) | `20/62` | `trojan.infostl/amos` |
| 2026-10-27 22:02:30 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`8c34eeface...`](https://www.virustotal.com/gui/file/8c34eefaceeed222cd9779fb3e72d0c9c87df96ebfcdc7b19b9e696ab16afcc3) | `16/62` | `trojan.amos/lummastealer` |
| 2026-10-27 22:02:30 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`8fc35a16f8...`](https://www.virustotal.com/gui/file/8fc35a16f8829ea8dadecc724830813583e2b5d668cb733932c8d1c3d1733fa2) | `8/53` | `trojan.infostl/lummastealer` |
| 2026-10-27 22:02:30 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`1d892af7a9...`](https://www.virustotal.com/gui/file/1d892af7a9b3989131c81cf4e1adcc52822390ee06cbd304eea43031c3d31ec1) | `18/63` | `trojan.infostl/amos` |
| 2026-10-27 22:02:30 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`67fc8fa7d9...`](https://www.virustotal.com/gui/file/67fc8fa7d9f844275afbbdf7fe3949074f3abb94319a774c0dcc9d5dfd9b1845) | `27/57` | `trojan.stealer/amosstealer` |
| 2026-10-27 22:02:30 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`163a3b1821...`](https://www.virustotal.com/gui/file/163a3b1821e5527f75e7620b6cfd10718c715c96a8cb72a71465fe0a887bf253) | `18/63` | `trojan.amos/infostl` |
| 2026-10-27 22:02:30 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`297878107f...`](https://www.virustotal.com/gui/file/297878107f9a04137afb70647994becb2452fff58104faf93203fac09248241b) | `15/63` | `trojan.amos/ltgl` |
| 2026-10-27 22:02:30 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`bd1c28603a...`](https://www.virustotal.com/gui/file/bd1c28603a4fae25b60dc7263c88ffcc7fc14f1cf2cac5143d5bfa786b151433) | `16/63` | `trojan.infostl/amos` |
| 2026-10-27 22:02:30 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`7d969f25af...`](https://www.virustotal.com/gui/file/7d969f25af3d016f00dd2858f28c5f2ff166f13b85072eaa8d736885ee956068) | `6/36` | `trojan.aujl/lummastealer` |
| 2026-10-26 20:05:47 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`533fdbf6b5...`](https://www.virustotal.com/gui/file/533fdbf6b54775472b63e8e67a29d1647c207273b3cb32971f8647c42c6066a7) | `21/62` | `trojan.amos/abtrojan` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`b2a38245d0...`](https://www.virustotal.com/gui/file/b2a38245d0cd7985793e03df229a46ea8cee0941b8b1dc116a3a128e8fe1aa03) | `25/63` | `trojan.amos/abtrojan` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`6d2c7f1837...`](https://www.virustotal.com/gui/file/6d2c7f1837bd52c975c29c8ac8c0bc2f4b5b688ac987482da05c77e0ea2295c5) | `27/63` | `trojan.amos/abtrojan` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`9081546dcd...`](https://www.virustotal.com/gui/file/9081546dcd8528fa3b26aabcab3baf5ece17faadcb0f6e697e7591f73c6ed839) | `27/62` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`27e4adf263...`](https://www.virustotal.com/gui/file/27e4adf26375ac044a8631d8998471b0c4746635cb8e45d9f12e5d6a24d080d9) | `24/61` | `trojan.amos/abtrojan` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`3169f13963...`](https://www.virustotal.com/gui/file/3169f13963324e6b06335f3f19c672630ddc0c0da423b2d0bdd9378d1de6de71) | `28/63` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`c7bebd02f8...`](https://www.virustotal.com/gui/file/c7bebd02f8db04103ac5f83078e634535db5ff1d3a59fe241b707c36813d2983) | `27/62` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`ab253de692...`](https://www.virustotal.com/gui/file/ab253de6924568c6a4574561fc6ec14ee98e5fd48e98162245c71a612af96a26) | `24/62` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`71fbe49d22...`](https://www.virustotal.com/gui/file/71fbe49d223d272852212f304d1dfa207b671b060426a3e619e6c0c6813b589d) | `26/63` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`c3bca04a52...`](https://www.virustotal.com/gui/file/c3bca04a525efbce865d03bd7cc7631c7dca3e9c50f4e1949c955541e3660103) | `22/57` | `trojan.amos/lummastealer` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`67b75dbf7e...`](https://www.virustotal.com/gui/file/67b75dbf7e0fa3009c3726b03cafd47b8eea8b7bd937409de615015410b3aa64) | `24/61` | `trojan.amos/class` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`ffc3f8bdd9...`](https://www.virustotal.com/gui/file/ffc3f8bdd9d37069c190378fc681e70992d9b88d9b8810cf00a1d89080c9ee8f) | `23/55` | `trojan.amos/cgow` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`af9fedc9c2...`](https://www.virustotal.com/gui/file/af9fedc9c2e8a653812e75ba6315e41b734d33e1f85868a4834670b19863adba) | `20/62` | `trojan.amos/ht1ll7` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`62d5eae2e4...`](https://www.virustotal.com/gui/file/62d5eae2e4f7deba6554026ee460e04ca0b100761f9fad62aa79983b6c5c444a) | `26/62` | `trojan.amos/abtrojan` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`598b0992d6...`](https://www.virustotal.com/gui/file/598b0992d69d55845c1be3233b3abdc63ad1184cbc01705d5bbd1e65ea11fdbb) | `20/52` | `trojan.amos/abtrojan` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`c15a21e69b...`](https://www.virustotal.com/gui/file/c15a21e69b3142e50d4e42a4203741d924795b44a6a3907dcaf2a5dec0ae9d77) | `24/61` | `trojan.amos/lummastealer` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`b61faf483a...`](https://www.virustotal.com/gui/file/b61faf483a13cc25f7b90129cb7088cd498560a09c1a014b5ca72ab713814352) | `28/62` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`5670d4f794...`](https://www.virustotal.com/gui/file/5670d4f79411fd5cb2ec03c2b5ed81b44e2b0681a72de5d9ce0de4001066d02a) | `21/53` | `trojan.amos/macho` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`ff72b39a55...`](https://www.virustotal.com/gui/file/ff72b39a559646d5a546eba3c939994ce9c3ed28efe200fa7929018c11292dd3) | `23/62` | `trojan.amos/cgow` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`0bb6aca14a...`](https://www.virustotal.com/gui/file/0bb6aca14af0fb513500770ca601c5b66e46c47e565f6e87c31f0c293fa8f5e3) | `23/58` | `trojan.amos/adhl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`6015a6d3a0...`](https://www.virustotal.com/gui/file/6015a6d3a00d5771932ce7abf625a53c0bc4ba6b2353bd7e033f2434d708fe16) | `23/58` | `trojan.amos/lummastealer` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`840ebbef89...`](https://www.virustotal.com/gui/file/840ebbef896ec2ccff40ce45096b63a6145665244077626d78509d7fdc32f6dd) | `27/61` | `trojan.amos/abtrojan` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`d2ec7a8765...`](https://www.virustotal.com/gui/file/d2ec7a876540ce8f4096e004a42db4cb541383a2bd85087169bc96fda4c875db) | `28/61` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`11387a0d24...`](https://www.virustotal.com/gui/file/11387a0d240ca6a184d4fd7524e63661012b26a51926ba6562fd7d966ad1b23d) | `28/62` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`fb3a907fa1...`](https://www.virustotal.com/gui/file/fb3a907fa1c573b1d5604fb511c9c9c04d3f8b75bbdacd1402c31b53b5393a23) | `26/61` | `trojan.amos/abtrojan` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`0bde7e85c0...`](https://www.virustotal.com/gui/file/0bde7e85c0d4d2f39996772a6348b1bee4717349afa648a301f182529429c81d) | `30/62` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`06a3833ccb...`](https://www.virustotal.com/gui/file/06a3833ccb61fe1dea39f628f1425524fd865c05a850aaf12da84bca23713292) | `27/62` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`2df7b49b99...`](https://www.virustotal.com/gui/file/2df7b49b9987822e437f1b88efedd9fbe58a7f524ec02974034c6188f6e39c35) | `28/62` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`70b2276aaa...`](https://www.virustotal.com/gui/file/70b2276aaa5ff9a8e714d625b9238c5bad790145be09827fb928143810df3bc9) | `24/61` | `trojan.amos/iqil` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`0d98501ac7...`](https://www.virustotal.com/gui/file/0d98501ac73fd2c318e0e1a4a223b9e2589f235627e512eac8b88a275315b69a) | `24/62` | `trojan.amos/cdhl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`2c4229230f...`](https://www.virustotal.com/gui/file/2c4229230fdcb224538828468a8642aaf4429a1591fe83776f8b3aa683d65050) | `27/61` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`eaddd0e6bf...`](https://www.virustotal.com/gui/file/eaddd0e6bf1c396859cee853792e6878977c8951829e1c43a66b204cc11a6a47) | `29/62` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`a9c7b69cec...`](https://www.virustotal.com/gui/file/a9c7b69cece1e5999a2302d4152bc038ffe8305e84e3d974ace49132241c3206) | `25/62` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`e59471dbb0...`](https://www.virustotal.com/gui/file/e59471dbb08a04c5ec6df736f149919cc5333ef19da2b2de298d4f429d0c3612) | `21/61` | `trojan.amos/lummastealer` |

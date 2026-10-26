# Yarafy Telemetry & Threat Hunting Report

**Last Run:** `2026-10-26T20:05:47.015161+00:00`
**Total Samples Scanned:** `18067` | **Total Rule Hits:** `248`

## Hits Breakdown by Source Feed
| Source Feed | Total Hits |
| :--- | :--- |
| **MalwareBazaar** | `195` |
| **VirusTotal Enterprise** | `43` |
| **Local File** | `10` |

## Hits Breakdown by Platform
| Platform | Total Hits |
| :--- | :--- |
| **MACOS** | `248` |
| **WINDOWS** | `0` |
| **LINUX** | `0` |
| **NON-PE** | `0` |

## Hits Breakdown by YARA Rule
| Rule Name | Total Detections |
| :--- | :--- |
| [`macOS_ClickFix_AppleScript_Dropper`](../yara-rules/) | `172` |
| [`OSX_Stealer_AMOS_Generic`](../yara-rules/) | `38` |
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
| 2026-10-26 20:05:47 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | `533fdbf6b5...` | `N/A` | `N/A` |
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
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | `af9fedc9c2...` | `N/A` | `N/A` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`62d5eae2e4...`](https://www.virustotal.com/gui/file/62d5eae2e4f7deba6554026ee460e04ca0b100761f9fad62aa79983b6c5c444a) | `26/62` | `trojan.amos/abtrojan` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`598b0992d6...`](https://www.virustotal.com/gui/file/598b0992d69d55845c1be3233b3abdc63ad1184cbc01705d5bbd1e65ea11fdbb) | `20/52` | `trojan.amos/abtrojan` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`c15a21e69b...`](https://www.virustotal.com/gui/file/c15a21e69b3142e50d4e42a4203741d924795b44a6a3907dcaf2a5dec0ae9d77) | `24/61` | `trojan.amos/lummastealer` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`b61faf483a...`](https://www.virustotal.com/gui/file/b61faf483a13cc25f7b90129cb7088cd498560a09c1a014b5ca72ab713814352) | `28/62` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`5670d4f794...`](https://www.virustotal.com/gui/file/5670d4f79411fd5cb2ec03c2b5ed81b44e2b0681a72de5d9ce0de4001066d02a) | `23/62` | `trojan.amos/abkkbh` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`ff72b39a55...`](https://www.virustotal.com/gui/file/ff72b39a559646d5a546eba3c939994ce9c3ed28efe200fa7929018c11292dd3) | `23/62` | `trojan.amos/cgow` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`0bb6aca14a...`](https://www.virustotal.com/gui/file/0bb6aca14af0fb513500770ca601c5b66e46c47e565f6e87c31f0c293fa8f5e3) | `23/58` | `trojan.amos/adhl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`6015a6d3a0...`](https://www.virustotal.com/gui/file/6015a6d3a00d5771932ce7abf625a53c0bc4ba6b2353bd7e033f2434d708fe16) | `23/58` | `trojan.amos/lummastealer` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`840ebbef89...`](https://www.virustotal.com/gui/file/840ebbef896ec2ccff40ce45096b63a6145665244077626d78509d7fdc32f6dd) | `27/61` | `trojan.amos/abtrojan` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`d2ec7a8765...`](https://www.virustotal.com/gui/file/d2ec7a876540ce8f4096e004a42db4cb541383a2bd85087169bc96fda4c875db) | `28/62` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`11387a0d24...`](https://www.virustotal.com/gui/file/11387a0d240ca6a184d4fd7524e63661012b26a51926ba6562fd7d966ad1b23d) | `28/62` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`fb3a907fa1...`](https://www.virustotal.com/gui/file/fb3a907fa1c573b1d5604fb511c9c9c04d3f8b75bbdacd1402c31b53b5393a23) | `25/62` | `trojan.amos/abtrojan` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`0bde7e85c0...`](https://www.virustotal.com/gui/file/0bde7e85c0d4d2f39996772a6348b1bee4717349afa648a301f182529429c81d) | `30/62` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`06a3833ccb...`](https://www.virustotal.com/gui/file/06a3833ccb61fe1dea39f628f1425524fd865c05a850aaf12da84bca23713292) | `22/55` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`2df7b49b99...`](https://www.virustotal.com/gui/file/2df7b49b9987822e437f1b88efedd9fbe58a7f524ec02974034c6188f6e39c35) | `24/58` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`70b2276aaa...`](https://www.virustotal.com/gui/file/70b2276aaa5ff9a8e714d625b9238c5bad790145be09827fb928143810df3bc9) | `23/62` | `trojan.amos/iqil` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`0d98501ac7...`](https://www.virustotal.com/gui/file/0d98501ac73fd2c318e0e1a4a223b9e2589f235627e512eac8b88a275315b69a) | `21/62` | `trojan.amos/cdhl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`2c4229230f...`](https://www.virustotal.com/gui/file/2c4229230fdcb224538828468a8642aaf4429a1591fe83776f8b3aa683d65050) | `28/62` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`eaddd0e6bf...`](https://www.virustotal.com/gui/file/eaddd0e6bf1c396859cee853792e6878977c8951829e1c43a66b204cc11a6a47) | `28/62` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`a9c7b69cec...`](https://www.virustotal.com/gui/file/a9c7b69cece1e5999a2302d4152bc038ffe8305e84e3d974ace49132241c3206) | `22/62` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`e59471dbb0...`](https://www.virustotal.com/gui/file/e59471dbb08a04c5ec6df736f149919cc5333ef19da2b2de298d4f429d0c3612) | `17/58` | `trojan.amos/lummastealer` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`3ab2cca811...`](https://www.virustotal.com/gui/file/3ab2cca8113b62240a9bce2d312a920a55f0a2313c6a8f76d0427400e6d6ab3f) | `22/62` | `trojan.amos/abpws` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`49006e5ef2...`](https://www.virustotal.com/gui/file/49006e5ef2cd5c0b48dcd4ec4f14ff17e15b737191dbb22c93bbac963f89ab15) | `16/57` | `trojan.amos/dnhl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`6bbd6311fa...`](https://www.virustotal.com/gui/file/6bbd6311fa06d6dba192c8739fb1519b9a86074f718bae304c2bdc92c2608e7f) | `21/60` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`d60004e652...`](https://www.virustotal.com/gui/file/d60004e652baebc1230dc7262b2983b3d8c62f1f7b132edaba8b68c6a82b20c0) | `17/62` | `trojan.amos/lummastealer` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`f09773a220...`](https://www.virustotal.com/gui/file/f09773a220d16e25ff8626af5ae925829bf180bcceb84431f72778bfe84a0475) | `23/62` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`540d24a82a...`](https://www.virustotal.com/gui/file/540d24a82a36a3e60497ee29fa51e3cc9963ecc50a9fa77fb245670d34879e09) | `24/62` | `trojan.amos/infostl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`dba12dd044...`](https://www.virustotal.com/gui/file/dba12dd044d53dc35cb15d9432a2e6fa139d9f76d813ace626b3f84bac9f67ea) | `20/54` | `trojan.infostl/efv569` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`78d0bbf3dd...`](https://www.virustotal.com/gui/file/78d0bbf3ddb244caae5b955e6e9476e26f33f5a2e37b9d02863ad34b6476fb64) | `22/62` | `trojan.amos/abtrojan` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`dc4db648c1...`](https://www.virustotal.com/gui/file/dc4db648c12775028fd2eaa82e831fafb1aa0b9e950fea74033eeb23220d1bca) | `15/55` | `trojan.amos/hmnw` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`d838168d23...`](https://www.virustotal.com/gui/file/d838168d234ce4bedef14162b85b2c47ac97539e16a3d451682d493b5a173785) | `20/61` | `trojan.amos/infostealer` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`18438ce3e5...`](https://www.virustotal.com/gui/file/18438ce3e58bdbe47c9d7058ce05f456d5792d99926be82eb894fba985c567c8) | `19/62` | `trojan.abapplication/amos` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`33dd4fa348...`](https://www.virustotal.com/gui/file/33dd4fa348582867ac7ccec455f018a929207b16d1f3e6771fc0f7f2b91572e0) | `9/54` | `trojan.bdhl/lummastealer` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`94ecec6587...`](https://www.virustotal.com/gui/file/94ecec65874eef8917d8f91d11724bca77194319c8711aecec0f8b39d6db93ca) | `14/61` | `trojan.abpws/amos` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`7ec6df0cae...`](https://www.virustotal.com/gui/file/7ec6df0cae345fd0c3bdb220c2634e52cbb9ece8755143587a546e00d91b2ad8) | `9/55` | `trojan.amos/bujl` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`b2b904053a...`](https://www.virustotal.com/gui/file/b2b904053a6d1b783e597bbab0d0ac9cf8d33dfd06b06e7a9ab3d99a769dd10b) | `11/49` | `trojan.infostl/aplw` |
| 2026-10-26 11:44:45 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`9c7713ce0a...`](https://www.virustotal.com/gui/file/9c7713ce0a1fa2ef4b43651ef3a984b1656a6ee8dc3a94c4682e5e5e86428373) | `12/62` | `trojan.amos/lummastealer` |

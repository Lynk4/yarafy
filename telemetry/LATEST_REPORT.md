# Yarafy Telemetry & Threat Hunting Report

**Last Run:** `2026-09-02T11:09:18.798440+00:00`
**Total Samples Scanned:** `1322` | **Total Rule Hits:** `42`

## Hits Breakdown by Source Feed
| Source Feed | Total Hits |
| :--- | :--- |
| **MalwareBazaar** | `20` |
| **VirusTotal Enterprise** | `22` |

## Hits Breakdown by Platform
| Platform | Total Hits |
| :--- | :--- |
| **MACOS** | `42` |

## Hits Breakdown by YARA Rule
| Rule Name | Total Detections |
| :--- | :--- |
| [`macOS_ClickFix_AppleScript_Dropper`](../yara-rules/) | `26` |
| [`OSX_Stealer_AMOS_Generic`](../yara-rules/) | `13` |
| [`MALW_macOS_MacSync_Stealer_Universal`](../yara-rules/) | `3` |

## Recent Positive Detections
| Timestamp | Source Feed | Rule | Platform | SHA256 | VT Detection | VT Threat Label |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-09-02 08:06:00 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`0ce6c083c8...`](https://www.virustotal.com/gui/file/0ce6c083c86d95df0962b6274a705631ccb87f5eb497b0fadd34d6040bb4913c) | `12/76` | `trojan.amos/amosstealer` |
| 2026-09-02 08:06:00 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`55364ff47a...`](https://www.virustotal.com/gui/file/55364ff47a8789d5c4b414dd7dae05820e8129d6c7592708778550b6b3e220f3) | `10/76` | `trojan.amos/camelot` |
| 2026-09-02 08:06:00 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`e5a00c378d...`](https://www.virustotal.com/gui/file/e5a00c378da0a2bbcc1233a620a115f73c627d9ac9831f66be713632d9611183) | `12/76` | `trojan.amos/amosstealer` |
| 2026-09-02 08:06:00 | **VirusTotal Enterprise** | `OSX_Stealer_AMOS_Generic` | macos | [`1bde09781d...`](https://www.virustotal.com/gui/file/1bde09781d733947ff7658c89a4e55af3486f7a9db5e50b24a812e4cc1451e61) | `28/76` | `trojan.stealer/amos` |
| 2026-09-02 08:06:00 | **VirusTotal Enterprise** | `OSX_Stealer_AMOS_Generic` | macos | [`72a3e5de94...`](https://www.virustotal.com/gui/file/72a3e5de9427ba286e1eff30367d629db37f327c55801ace3ad3324f8476a794) | `19/76` | `trojan.stealer/amos` |
| 2026-09-01 15:39:30 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`63cba47e46...`](https://www.virustotal.com/gui/file/63cba47e46c0b4051c1d9d7e476743f1ce3b7868ceb425a7e8f877460917d2a0) | `12/76` | `trojan.amos/camelot` |
| 2026-09-01 15:39:30 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`8043fedb8e...`](https://www.virustotal.com/gui/file/8043fedb8e00499538421af1ffdf4371553c5c93506c6b2d82bf2660823fd05e) | `12/76` | `trojan.amos/amosstealer` |
| 2026-09-01 15:39:30 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`fb5f2418ab...`](https://www.virustotal.com/gui/file/fb5f2418abc9c44235a6495f91cb95e6df19dc1fd30181c8ad5bc91797a55f66) | `13/76` | `trojan.amos/amosstealer` |
| 2026-09-01 15:39:30 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`4bae510072...`](https://www.virustotal.com/gui/file/4bae510072353a0493b1bb58f167e1afb7636f11531dfa696df804fa50d582ef) | `7/76` | `trojan.amos/camelot` |
| 2026-09-01 15:39:30 | **VirusTotal Enterprise** | `OSX_Stealer_AMOS_Generic` | macos | [`162740169b...`](https://www.virustotal.com/gui/file/162740169bc202ab264ebf99a6e1a8789522601986be7965277a77460b103e2b) | `28/76` | `trojan.stealer/amos` |
| 2026-09-01 15:39:30 | **VirusTotal Enterprise** | `OSX_Stealer_AMOS_Generic` | macos | [`f2b8d86adc...`](https://www.virustotal.com/gui/file/f2b8d86adc1cfe5833d07c0ac09c69192bd1ca54717cc40dd00977deb426b53f) | `17/76` | `trojan.stealer/amos` |
| 2026-09-01 10:24:38 | **VirusTotal Enterprise** | `MALW_macOS_MacSync_Stealer_Universal` | macos_MALW_macOS_MacSync_Stealer | [`9ff32f7c01...`](https://www.virustotal.com/gui/file/9ff32f7c0108e9d27a3b491edf04827b6ca025f44db68aeadc44eeb97c9aab11) | `27/76` | `trojan.coins/infostl` |
| 2026-09-01 10:24:38 | **VirusTotal Enterprise** | `MALW_macOS_MacSync_Stealer_Universal` | macos_MALW_macOS_MacSync_Stealer | [`a864c989d8...`](https://www.virustotal.com/gui/file/a864c989d8a28cc5d2162050bb862775ee7297ce305c19014a0c63a4b73e993b) | `23/76` | `trojan.coins/abtrojan` |
| 2026-09-01 07:05:16 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`76c2e4e7fb...`](https://www.virustotal.com/gui/file/76c2e4e7fb5290366d7bd04703ea60ec92d314ff651172387b9c6dbfca22b82a) | `11/76` | `trojan.amos/camelot` |
| 2026-09-01 07:05:16 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`ef1d615bbf...`](https://www.virustotal.com/gui/file/ef1d615bbf15dbee3d2dd51f843a462230014f0212423182c38d93140e176460) | `10/76` | `trojan.amos/camelot` |
| 2026-09-01 07:05:16 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`620662ab49...`](https://www.virustotal.com/gui/file/620662ab495dacef6ac971ab82da995d430b9b0e9f92445acd136e0cd07d6821) | `11/76` | `trojan.amos/camelot` |
| 2026-09-01 07:05:16 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`e20f38eedb...`](https://www.virustotal.com/gui/file/e20f38eedb7fd126834250aa43453faa99833e7c0f39029691dad8ca5e9f5ce9) | `10/76` | `trojan.camelot/multiverze` |
| 2026-09-01 07:05:16 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`04465e8d0c...`](https://www.virustotal.com/gui/file/04465e8d0cebb270bacc5db8bb874cf01bd4ba85afd317b9d8748cbcb53ce5c7) | `10/76` | `trojan.amos/camelot` |
| 2026-09-01 07:05:16 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`e0ad9eab55...`](https://www.virustotal.com/gui/file/e0ad9eab55dee8da82090915d94b2b07ae2b0537312b4d0397fec8bb1380ad2c) | `11/76` | `trojan.amos/camelot` |
| 2026-09-01 07:05:16 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`e4e8aa9a82...`](https://www.virustotal.com/gui/file/e4e8aa9a827e820fd98fa061442cac2ac95fbb7ed1b3e5a0d99aef048e4a123e) | `11/76` | `trojan.amos/camelot` |
| 2026-09-01 07:05:16 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`780dc4cb1b...`](https://www.virustotal.com/gui/file/780dc4cb1bf8697cbc784c8926cc7f55b64c04e8eaa51d20f938cfa352f8c998) | `10/76` | `trojan.amos/camelot` |
| 2026-09-01 07:05:16 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`00f918996b...`](https://www.virustotal.com/gui/file/00f918996b9192c8ccd0ba4ad80f6f2ed17844d6cbe00eb65afb9df0c8f05430) | `11/76` | `trojan.amos/camelot` |
| 2026-08-31 14:41:41 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`30f97ae88f...`](https://www.virustotal.com/gui/file/30f97ae88f8861eeadeb54854d47078724e52e2ef36dd847180663b7f5763168) | `37/62` | `trojan.amos/stealer` |
| 2026-08-31 14:41:41 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`135fc266af...`](https://www.virustotal.com/gui/file/135fc266af08a28fc7b2d3e0c2ca92e9611e626cec13fb70b9eaad1278b72793) | `37/61` | `trojan.mettle/meterpreter` |
| 2026-08-31 14:41:41 | **MalwareBazaar** | `MALW_macOS_MacSync_Stealer_Universal` | macos_MALW_macOS_MacSync_Stealer | [`4d751dd363...`](https://www.virustotal.com/gui/file/4d751dd363298589cb436d78cd302f9d794ae1e3670722a464884be908671a9c) | `31/58` | `trojan.stealer/infostl` |
| 2026-08-31 14:41:41 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`a6fd2f09eb...`](https://www.virustotal.com/gui/file/a6fd2f09eb81bf3afc83c4b019f21c63aa89a73239e67d0acdf6c8f4e714f2ba) | `35/59` | `trojan.mettle/meterpreter` |
| 2026-08-31 14:41:41 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`a7bb346838...`](https://www.virustotal.com/gui/file/a7bb346838db73301fe16e8f6bf2e0caee397570bc0df184484245a2715fb9f5) | `38/62` | `trojan.mettle/meterpreter` |
| 2026-08-31 14:41:41 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`a91d954fa5...`](https://www.virustotal.com/gui/file/a91d954fa5a9a1f167625e7ac8314a481e32a9dbee4635533b52be21be4e508b) | `34/62` | `trojan.stealer/infostl` |
| 2026-08-31 14:41:41 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`f284297b7b...`](https://www.virustotal.com/gui/file/f284297b7bf551617553a9c19f101b3aa55f94e3fb60cab2e596e4c287908281) | `34/62` | `trojan.stealer/infostl` |
| 2026-08-31 14:41:41 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`23f900e9fb...`](https://www.virustotal.com/gui/file/23f900e9fb8ff57f420901178a087cc5570dcaf1fd161d8e8c0b38fcdb4e68f1) | `28/60` | `trojan.stealer/amos` |
| 2026-08-31 14:41:41 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`43e4dfdd3c...`](https://www.virustotal.com/gui/file/43e4dfdd3c1295e54a2704158c50e1ce5913f8d700790441367cba8abe07195b) | `29/60` | `trojan.stealer/amos` |
| 2026-08-31 14:41:41 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`b30b4b58eb...`](https://www.virustotal.com/gui/file/b30b4b58eb215b60a8526c506d689ffab91ed43124709bc20b4085edf9d5361b) | `32/59` | `trojan.stealer/amos` |
| 2026-08-31 14:41:41 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`fc20091668...`](https://www.virustotal.com/gui/file/fc2009166867bee88885f2f889a608260cb971c1e946bbb79ea7d75ae0d429f6) | `29/61` | `trojan.stealer/atomic` |
| 2026-08-31 14:41:41 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`81bedb0639...`](https://www.virustotal.com/gui/file/81bedb0639d5857c6d28b23b06cf87f812c1070d2c7c6ee8c985362a0ef2b873) | `32/60` | `trojan.stealer/amos` |
| 2026-08-31 14:41:41 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`4c487d86d9...`](https://www.virustotal.com/gui/file/4c487d86d904ec55002123163e8db6dfa93918a342036cf0d155ce9c2f662c7a) | `31/58` | `trojan.stealer/amos` |
| 2026-08-31 14:41:41 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`ec0d13eb92...`](https://www.virustotal.com/gui/file/ec0d13eb92a22465723e904b2ace56ddf20489810971f3b437197fdc78d10098) | `33/62` | `trojan.amos/stealer` |
| 2026-08-31 14:41:41 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`29be0f5627...`](https://www.virustotal.com/gui/file/29be0f56275f051181ea3ec37ddc3d3807cde34cb65de855709fae0e13786a40) | `29/62` | `trojan.stealer/atomic` |
| 2026-08-31 14:41:41 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`c48bd4f678...`](https://www.virustotal.com/gui/file/c48bd4f678a498b9173353d8fd400093541326e6b40a1a99c9a15fd28721ed69) | `28/61` | `trojan.stealer/abtrojan` |
| 2026-08-31 14:41:41 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`275aeaa88d...`](https://www.virustotal.com/gui/file/275aeaa88d853ddb93c6e3c102beb1aa2ba41ca1b68af25b47781d9f4460bc5d) | `33/62` | `trojan.stealer/amos` |
| 2026-08-31 14:41:41 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`9e221f4564...`](https://www.virustotal.com/gui/file/9e221f45649bdd5d7fdd77949083b1d37ac34f8cf3cbf91b686edb1c6b2262f6) | `33/62` | `trojan.stealer/amos` |
| 2026-08-31 14:41:41 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`0f808ec0e7...`](https://www.virustotal.com/gui/file/0f808ec0e7d9fb413f44331ba5fc6a23ca282363f244062f0acaa418e55b2ec8) | `33/62` | `trojan.stealer/amos` |
| 2026-08-31 14:41:41 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`05d0d69ca9...`](https://www.virustotal.com/gui/file/05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72) | `25/61` | `trojan.amos/camelot` |

# Yarafy Telemetry & Threat Hunting Report

**Last Run:** `2026-09-01T07:05:16.190034+00:00`
**Total Samples Scanned:** `586` | **Total Rule Hits:** `29`

## Hits Breakdown by Source Feed
| Source Feed | Total Hits |
| :--- | :--- |
| **VirusTotal Enterprise** | `9` |

## Hits Breakdown by Platform
| Platform | Total Hits |
| :--- | :--- |
| **MACOS** | `29` |

## Hits Breakdown by YARA Rule
| Rule Name | Total Detections |
| :--- | :--- |
| [`macOS_ClickFix_AppleScript_Dropper`](../yara-rules/) | `19` |
| [`OSX_Stealer_AMOS_Generic`](../yara-rules/) | `9` |
| [`MALW_macOS_MacSync_Stealer_Universal`](../yara-rules/) | `1` |

## Recent Positive Detections
| Timestamp | Source Feed | Rule | Platform | SHA256 | VT Detection | VT Threat Label |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-09-01 07:05:16 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`76c2e4e7fb...`](https://www.virustotal.com/gui/file/76c2e4e7fb5290366d7bd04703ea60ec92d314ff651172387b9c6dbfca22b82a) | `11/76` | `trojan.amos/camelot` |
| 2026-09-01 07:05:16 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`ef1d615bbf...`](https://www.virustotal.com/gui/file/ef1d615bbf15dbee3d2dd51f843a462230014f0212423182c38d93140e176460) | `10/76` | `trojan.amos/camelot` |
| 2026-09-01 07:05:16 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`620662ab49...`](https://www.virustotal.com/gui/file/620662ab495dacef6ac971ab82da995d430b9b0e9f92445acd136e0cd07d6821) | `11/76` | `trojan.amos/camelot` |
| 2026-09-01 07:05:16 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`e20f38eedb...`](https://www.virustotal.com/gui/file/e20f38eedb7fd126834250aa43453faa99833e7c0f39029691dad8ca5e9f5ce9) | `10/76` | `trojan.camelot/multiverze` |
| 2026-09-01 07:05:16 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`04465e8d0c...`](https://www.virustotal.com/gui/file/04465e8d0cebb270bacc5db8bb874cf01bd4ba85afd317b9d8748cbcb53ce5c7) | `10/76` | `trojan.amos/camelot` |
| 2026-09-01 07:05:16 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`e0ad9eab55...`](https://www.virustotal.com/gui/file/e0ad9eab55dee8da82090915d94b2b07ae2b0537312b4d0397fec8bb1380ad2c) | `11/76` | `trojan.amos/camelot` |
| 2026-09-01 07:05:16 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`e4e8aa9a82...`](https://www.virustotal.com/gui/file/e4e8aa9a827e820fd98fa061442cac2ac95fbb7ed1b3e5a0d99aef048e4a123e) | `11/76` | `trojan.amos/camelot` |
| 2026-09-01 07:05:16 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`780dc4cb1b...`](https://www.virustotal.com/gui/file/780dc4cb1bf8697cbc784c8926cc7f55b64c04e8eaa51d20f938cfa352f8c998) | `10/76` | `trojan.amos/camelot` |
| 2026-09-01 07:05:16 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`00f918996b...`](https://www.virustotal.com/gui/file/00f918996b9192c8ccd0ba4ad80f6f2ed17844d6cbe00eb65afb9df0c8f05430) | `11/76` | `trojan.amos/camelot` |
| 2026-08-31 14:41:41 | **Unknown** | `OSX_Stealer_AMOS_Generic` | macos | [`30f97ae88f...`](https://www.virustotal.com/gui/file/30f97ae88f8861eeadeb54854d47078724e52e2ef36dd847180663b7f5763168) | `37/62` | `trojan.amos/stealer` |
| 2026-08-31 14:41:41 | **Unknown** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`135fc266af...`](https://www.virustotal.com/gui/file/135fc266af08a28fc7b2d3e0c2ca92e9611e626cec13fb70b9eaad1278b72793) | `37/61` | `trojan.mettle/meterpreter` |
| 2026-08-31 14:41:41 | **Unknown** | `MALW_macOS_MacSync_Stealer_Universal` | macos_MALW_macOS_MacSync_Stealer | [`4d751dd363...`](https://www.virustotal.com/gui/file/4d751dd363298589cb436d78cd302f9d794ae1e3670722a464884be908671a9c) | `31/58` | `trojan.stealer/infostl` |
| 2026-08-31 14:41:41 | **Unknown** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`a6fd2f09eb...`](https://www.virustotal.com/gui/file/a6fd2f09eb81bf3afc83c4b019f21c63aa89a73239e67d0acdf6c8f4e714f2ba) | `35/59` | `trojan.mettle/meterpreter` |
| 2026-08-31 14:41:41 | **Unknown** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`a7bb346838...`](https://www.virustotal.com/gui/file/a7bb346838db73301fe16e8f6bf2e0caee397570bc0df184484245a2715fb9f5) | `38/62` | `trojan.mettle/meterpreter` |
| 2026-08-31 14:41:41 | **Unknown** | `OSX_Stealer_AMOS_Generic` | macos | [`a91d954fa5...`](https://www.virustotal.com/gui/file/a91d954fa5a9a1f167625e7ac8314a481e32a9dbee4635533b52be21be4e508b) | `34/62` | `trojan.stealer/infostl` |
| 2026-08-31 14:41:41 | **Unknown** | `OSX_Stealer_AMOS_Generic` | macos | [`f284297b7b...`](https://www.virustotal.com/gui/file/f284297b7bf551617553a9c19f101b3aa55f94e3fb60cab2e596e4c287908281) | `34/62` | `trojan.stealer/infostl` |
| 2026-08-31 14:41:41 | **Unknown** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`23f900e9fb...`](https://www.virustotal.com/gui/file/23f900e9fb8ff57f420901178a087cc5570dcaf1fd161d8e8c0b38fcdb4e68f1) | `28/60` | `trojan.stealer/amos` |
| 2026-08-31 14:41:41 | **Unknown** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`43e4dfdd3c...`](https://www.virustotal.com/gui/file/43e4dfdd3c1295e54a2704158c50e1ce5913f8d700790441367cba8abe07195b) | `29/60` | `trojan.stealer/amos` |
| 2026-08-31 14:41:41 | **Unknown** | `OSX_Stealer_AMOS_Generic` | macos | [`b30b4b58eb...`](https://www.virustotal.com/gui/file/b30b4b58eb215b60a8526c506d689ffab91ed43124709bc20b4085edf9d5361b) | `32/59` | `trojan.stealer/amos` |
| 2026-08-31 14:41:41 | **Unknown** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`fc20091668...`](https://www.virustotal.com/gui/file/fc2009166867bee88885f2f889a608260cb971c1e946bbb79ea7d75ae0d429f6) | `29/61` | `trojan.stealer/atomic` |
| 2026-08-31 14:41:41 | **Unknown** | `OSX_Stealer_AMOS_Generic` | macos | [`81bedb0639...`](https://www.virustotal.com/gui/file/81bedb0639d5857c6d28b23b06cf87f812c1070d2c7c6ee8c985362a0ef2b873) | `32/60` | `trojan.stealer/amos` |
| 2026-08-31 14:41:41 | **Unknown** | `OSX_Stealer_AMOS_Generic` | macos | [`4c487d86d9...`](https://www.virustotal.com/gui/file/4c487d86d904ec55002123163e8db6dfa93918a342036cf0d155ce9c2f662c7a) | `31/58` | `trojan.stealer/amos` |
| 2026-08-31 14:41:41 | **Unknown** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`ec0d13eb92...`](https://www.virustotal.com/gui/file/ec0d13eb92a22465723e904b2ace56ddf20489810971f3b437197fdc78d10098) | `33/62` | `trojan.amos/stealer` |
| 2026-08-31 14:41:41 | **Unknown** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`29be0f5627...`](https://www.virustotal.com/gui/file/29be0f56275f051181ea3ec37ddc3d3807cde34cb65de855709fae0e13786a40) | `29/62` | `trojan.stealer/atomic` |
| 2026-08-31 14:41:41 | **Unknown** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`c48bd4f678...`](https://www.virustotal.com/gui/file/c48bd4f678a498b9173353d8fd400093541326e6b40a1a99c9a15fd28721ed69) | `28/61` | `trojan.stealer/abtrojan` |

# Yarafy Telemetry & Threat Hunting Report

**Last Run:** `2026-08-31T13:32:12.521808+00:00`
**Total Samples Scanned:** `133` | **Total Rule Hits:** `13`

## Hits Breakdown by Platform
| Platform | Total Hits |
| :--- | :--- |
| **MACOS** | `13` |

## Hits Breakdown by YARA Rule
| Rule Name | Total Detections |
| :--- | :--- |
| [`macOS_ClickFix_AppleScript_Dropper`](../yara-rules/) | `10` |
| [`infostealer_macos_banshee`](../yara-rules/) | `2` |
| [`infostealer_macos_amos`](../yara-rules/) | `1` |

## Recent Positive Detections
| Timestamp | Rule | Platform | SHA256 | VT Detection | VT Threat Label |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-08-31 13:32:12 | `infostealer_macos_banshee` | macos | [`15d1afca78...`](https://www.virustotal.com/gui/file/15d1afca780e2ea6ffec8c4862a3401e003b5e79ce5f9076b4eea4ab599bc4ce) | `33/62` | `trojan.stealer/macstealer` |
| 2026-08-31 13:32:12 | `infostealer_macos_banshee` | macos | [`f14dd83e60...`](https://www.virustotal.com/gui/file/f14dd83e60b8ca6d52e667ed85adafa9b849df33e428b005b05b7c6732de526a) | `28/56` | `trojan.stealer/macstealer` |
| 2026-08-31 13:32:12 | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`135fc266af...`](https://www.virustotal.com/gui/file/135fc266af08a28fc7b2d3e0c2ca92e9611e626cec13fb70b9eaad1278b72793) | `37/61` | `trojan.mettle/meterpreter` |
| 2026-08-31 13:32:12 | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`a6fd2f09eb...`](https://www.virustotal.com/gui/file/a6fd2f09eb81bf3afc83c4b019f21c63aa89a73239e67d0acdf6c8f4e714f2ba) | `35/59` | `trojan.mettle/meterpreter` |
| 2026-08-31 13:32:12 | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`a7bb346838...`](https://www.virustotal.com/gui/file/a7bb346838db73301fe16e8f6bf2e0caee397570bc0df184484245a2715fb9f5) | `38/62` | `trojan.mettle/meterpreter` |
| 2026-08-31 13:32:12 | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`23f900e9fb...`](https://www.virustotal.com/gui/file/23f900e9fb8ff57f420901178a087cc5570dcaf1fd161d8e8c0b38fcdb4e68f1) | `28/60` | `trojan.stealer/amos` |
| 2026-08-31 13:32:12 | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`43e4dfdd3c...`](https://www.virustotal.com/gui/file/43e4dfdd3c1295e54a2704158c50e1ce5913f8d700790441367cba8abe07195b) | `29/60` | `trojan.stealer/amos` |
| 2026-08-31 13:32:12 | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`fc20091668...`](https://www.virustotal.com/gui/file/fc2009166867bee88885f2f889a608260cb971c1e946bbb79ea7d75ae0d429f6) | `29/61` | `trojan.stealer/atomic` |
| 2026-08-31 13:32:12 | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`ec0d13eb92...`](https://www.virustotal.com/gui/file/ec0d13eb92a22465723e904b2ace56ddf20489810971f3b437197fdc78d10098) | `33/62` | `trojan.amos/stealer` |
| 2026-08-31 13:32:12 | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`29be0f5627...`](https://www.virustotal.com/gui/file/29be0f56275f051181ea3ec37ddc3d3807cde34cb65de855709fae0e13786a40) | `29/62` | `trojan.stealer/atomic` |
| 2026-08-31 13:32:12 | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`c48bd4f678...`](https://www.virustotal.com/gui/file/c48bd4f678a498b9173353d8fd400093541326e6b40a1a99c9a15fd28721ed69) | `28/61` | `trojan.stealer/abtrojan` |
| 2026-08-31 13:32:12 | `infostealer_macos_amos` | macos | [`de5748aac4...`](https://www.virustotal.com/gui/file/de5748aac4a4d4cb48cf050652679e6bc49eda33d9ffaa0d280b578122fab55a) | `32/63` | `trojan.stealer/infostl` |
| 2026-08-31 13:32:12 | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`05d0d69ca9...`](https://www.virustotal.com/gui/file/05d0d69ca9f28d70bd35d7acc7b0130032abea012418d36a9b84230f8e4f9f72) | `25/61` | `trojan.amos/camelot` |

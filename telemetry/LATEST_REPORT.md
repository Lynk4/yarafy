# Yarafy Telemetry & Threat Hunting Report

**Last Run:** `2026-09-05T10:52:15.063121+00:00`
**Total Samples Scanned:** `6672` | **Total Rule Hits:** `63`

## Hits Breakdown by Source Feed
| Source Feed | Total Hits |
| :--- | :--- |
| **MalwareBazaar** | `20` |
| **VirusTotal Enterprise** | `43` |

## Hits Breakdown by Platform
| Platform | Total Hits |
| :--- | :--- |
| **MACOS** | `63` |
| **WINDOWS** | `0` |
| **LINUX** | `0` |
| **NON-PE** | `0` |

## Hits Breakdown by YARA Rule
| Rule Name | Total Detections |
| :--- | :--- |
| [`macOS_ClickFix_AppleScript_Dropper`](../yara-rules/) | `34` |
| [`OSX_Stealer_AMOS_Generic`](../yara-rules/) | `25` |
| [`MALW_macOS_MacSync_Stealer_Universal`](../yara-rules/) | `4` |

## Recent Positive Detections
| Timestamp | Source Feed | Rule | Platform | SHA256 | VT Detection | VT Threat Label |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
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
| 2026-09-03 05:14:39 | **VirusTotal Enterprise** | `OSX_Stealer_AMOS_Generic` | macos | [`871ef3467b...`](https://www.virustotal.com/gui/file/871ef3467b7dfae4117cf63607010299e413c45af28694c2b5aef9c85561a484) | `18/76` | `trojan.stealer/amos` |
| 2026-09-03 05:14:39 | **VirusTotal Enterprise** | `OSX_Stealer_AMOS_Generic` | macos | [`1f78a436c5...`](https://www.virustotal.com/gui/file/1f78a436c529a6da706486ee8bd4a6adfe879bea858ef7d3393833d1158c36ce) | `18/76` | `trojan.stealer/amos` |
| 2026-09-03 05:14:39 | **VirusTotal Enterprise** | `OSX_Stealer_AMOS_Generic` | macos | [`2a3a9a9d69...`](https://www.virustotal.com/gui/file/2a3a9a9d69c8cfa90879da2294d603a81fc9e97349b22e6a0aed3b565e092c1d) | `28/76` | `trojan.stealer/amos` |
| 2026-09-02 15:18:39 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`fad2eda617...`](https://www.virustotal.com/gui/file/fad2eda61740a347df03b0f64fee4510fc05631549c4d501487522cb8fb980c4) | `11/76` | `trojan.amos/camelot` |
| 2026-09-02 15:18:39 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`23269d1af5...`](https://www.virustotal.com/gui/file/23269d1af542f94427f6994c509de9b1c31bdad5cc48ed1acc773130faf5bd9a) | `11/76` | `trojan.amos/camelot` |
| 2026-09-02 15:18:39 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`7ac18a4680...`](https://www.virustotal.com/gui/file/7ac18a468064212c7c74d602364e43afde5b00a93ac7e84acf321ae2279a1213) | `10/76` | `trojan.amos/camelot` |
| 2026-09-02 15:18:39 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`69670fdc89...`](https://www.virustotal.com/gui/file/69670fdc892a5794bc78811ef551dcd40bed770cfa4f6aa6851db688c6466dd0) | `11/76` | `trojan.amos/camelot` |
| 2026-09-02 15:18:39 | **VirusTotal Enterprise** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`ea8f3d6c2b...`](https://www.virustotal.com/gui/file/ea8f3d6c2bfd3701bf1091f280843e29dec54d9403d77c680079d208fa2924a7) | `11/76` | `trojan.amos/camelot` |
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

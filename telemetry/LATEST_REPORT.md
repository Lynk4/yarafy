# Yarafy Telemetry & Threat Hunting Report

**Last Run:** `2026-10-19T02:52:22.004609+00:00`
**Total Samples Scanned:** `16232` | **Total Rule Hits:** `138`

## Hits Breakdown by Source Feed
| Source Feed | Total Hits |
| :--- | :--- |
| **MalwareBazaar** | `85` |
| **VirusTotal Enterprise** | `43` |
| **Local File** | `10` |

## Hits Breakdown by Platform
| Platform | Total Hits |
| :--- | :--- |
| **MACOS** | `138` |
| **WINDOWS** | `0` |
| **LINUX** | `0` |
| **NON-PE** | `0` |

## Hits Breakdown by YARA Rule
| Rule Name | Total Detections |
| :--- | :--- |
| [`macOS_ClickFix_AppleScript_Dropper`](../yara-rules/) | `63` |
| [`OSX_Stealer_AMOS_Generic`](../yara-rules/) | `38` |
| [`OSX_Foxveil_AMOS_Stage4_Generic`](../yara-rules/) | `17` |
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
| 2026-10-19 02:52:22 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`b5d4aba0fe...`](https://www.virustotal.com/gui/file/b5d4aba0fe4004e851756d0329f0c165db2c1667c7c73516e0f1537c9afd3298) | `6/63` | `trojan.` |
| 2026-10-19 02:52:22 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`ff9c8f57fa...`](https://www.virustotal.com/gui/file/ff9c8f57fa3ec4c935c343bc636dee3253e6b6e4dbbd0d64e7898f0c7f7c5598) | `6/63` | `trojan.` |
| 2026-10-19 02:52:22 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`0119e2bc22...`](https://www.virustotal.com/gui/file/0119e2bc2281379155fe73917dc347f31501873867e7d8174b71c8cdbf0e5c8f) | `6/60` | `trojan.` |
| 2026-10-19 02:52:22 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`40dc77a48f...`](https://www.virustotal.com/gui/file/40dc77a48faae52f4ab7e2fbac202427947ffd48fc4e3dc6ed9f9b4403dc590c) | `6/63` | `trojan.` |
| 2026-10-19 02:32:11 | **Local File** | `MALW_macOS_MacSync_Stealer_Universal` | macos_MALW_macOS_MacSync_Stealer | [`fa65230781...`](https://www.virustotal.com/gui/file/fa65230781d2d3afc4152f23e3c4c91a91978d67dda2519d6eeb42476d41dc5a) | `26/63` | `trojan.stealer/coins` |
| 2026-10-19 02:32:11 | **Local File** | `OSX_Stealer_AMOS_Generic` | macos | `592d93f589...` | `N/A` | `N/A` |
| 2026-10-19 02:32:11 | **Local File** | `Macho_hVNCRat_shelldropper` | macos_stealer | [`dce578f5af...`](https://www.virustotal.com/gui/file/dce578f5af994c77785b96087e4fd4d8124482eab896dceb175a26342a84e31b) | `5/58` | `trojan.horse/qgil` |
| 2026-10-19 02:32:11 | **Local File** | `Macho_hVNCRat_campaign` | macos_stealer | [`5681c400f0...`](https://www.virustotal.com/gui/file/5681c400f0ed8431b3950e92864e52cffb0bf93a359edffb49e423ad5e8ef0b8) | `4/63` | `trojan.horse/stealer` |
| 2026-10-19 02:32:11 | **Local File** | `Macho_hVNCRat_generic` | macos_stealer | [`5681c400f0...`](https://www.virustotal.com/gui/file/5681c400f0ed8431b3950e92864e52cffb0bf93a359edffb49e423ad5e8ef0b8) | `4/63` | `trojan.horse/stealer` |
| 2026-10-19 02:32:11 | **Local File** | `Macho_Trojan_CloudSync_DMG` | macos_cloud_sync | [`faf2eea05f...`](https://www.virustotal.com/gui/file/faf2eea05f3c9f1c4ef8f6be339f5459a38f95cfd9d512bc24e2803230e5c7bf) | `20/58` | `trojan.multiverze/abtrojan` |
| 2026-10-19 02:32:11 | **Local File** | `Macho_Trojan_CloudSync_1007YR` | macos_stealer | [`faf2eea05f...`](https://www.virustotal.com/gui/file/faf2eea05f3c9f1c4ef8f6be339f5459a38f95cfd9d512bc24e2803230e5c7bf) | `20/58` | `trojan.multiverze/abtrojan` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`cefb465886...`](https://www.virustotal.com/gui/file/cefb465886bc813ac91e9ad5b1835eefe9828f251b58eb0da012ee4022ff6d98) | `21/60` | `trojan.class/macho` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`104a6e4b1d...`](https://www.virustotal.com/gui/file/104a6e4b1da8f7b42bdaf887b82f2c12348c6b1ffe52d1de2d964b6329492ad7) | `35/63` | `trojan.stealer/amos` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`3bf9ac9cb2...`](https://www.virustotal.com/gui/file/3bf9ac9cb26ecffd2ab26bb14c81c110b53fe31c196cc774291ad4af804023c3) | `22/63` | `trojan.abrisk/class` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`ecf0f6b181...`](https://www.virustotal.com/gui/file/ecf0f6b181632fb335c800bcc77cccc5584bc15b5ac594dc68019f05081c3d5d) | `16/57` | `trojan.class/egairtigado` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`51ad0fe878...`](https://www.virustotal.com/gui/file/51ad0fe8782d9756f1fc647bfd19e649b1b3e55e8b641a295062c935c1939bd8) | `21/61` | `trojan.class/deulm0` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`322a9bdadc...`](https://www.virustotal.com/gui/file/322a9bdadc796f2b2a7459b949ff367ed3258e9a8eefb1af161b557418ce845d) | `23/62` | `trojan.abrisk/amos` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`efc0f30e9b...`](https://www.virustotal.com/gui/file/efc0f30e9b1c8e4b1479006ecdcc95d5d4fa0627af8b294a6babe57da17b58d3) | `22/63` | `trojan.egairtigado/class` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`e6490a700b...`](https://www.virustotal.com/gui/file/e6490a700b965a6dcf264eb1e8291217d9e52f167470d70bc24806697fabeeaa) | `12/61` | `trojan.ssmw/xfzrkq` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`d64921058e...`](https://www.virustotal.com/gui/file/d64921058e03078b75565d5aeea126e75698f39be3c6387d17c5d9fa8536d0ac) | `6/40` | `trojan.wimw` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`f2c7af231a...`](https://www.virustotal.com/gui/file/f2c7af231a3dc1a9291a2421d2b67e3c6ed829073fdcbd7aeec3c33a933d2f6e) | `10/57` | `trojan.amos/kcnw` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`aa2fe64a8b...`](https://www.virustotal.com/gui/file/aa2fe64a8b365f79ba99c5cae660602063d6b555b3dd2e40d05f5293ca2c2a96) | `14/63` | `trojan.amos/class` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`813bb6f2bc...`](https://www.virustotal.com/gui/file/813bb6f2bc378364b4a0ed1405fe6ccd34a1510c4c94fe98f5908e6514999c1a) | `13/63` | `trojan.amos/fajl` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`6c118d4bd1...`](https://www.virustotal.com/gui/file/6c118d4bd1a56f56756b78134474c2a5becd3f138803d3297155691a427f6524) | `12/63` | `trojan.dkjl` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`89a2531114...`](https://www.virustotal.com/gui/file/89a25311145ada1664428064bc5b4ae16ec3e322b1399f3d4e753de8aba3ea06) | `16/63` | `trojan.stealer/amos` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`85fce98269...`](https://www.virustotal.com/gui/file/85fce9826974549c2dd4c92a3207cf2543e10676ad2dfad7c8ea429f616cdf21) | `12/63` | `trojan.abpws/jajl` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`e395c53437...`](https://www.virustotal.com/gui/file/e395c5343703a570d12620c81b9593ea6117d2f57c95bd8247704d9dbd256ce6) | `30/63` | `trojan.stealer/amos` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`81e34b0ec6...`](https://www.virustotal.com/gui/file/81e34b0ec6928234d0a24f9b1634d1e2201fe0fca38bf048229d750ba35f64ca) | `7/63` | `trojan.fajl` |
| 2026-10-16 09:42:46 | **MalwareBazaar** | `Macho_Trojan_CloudSync_1006YR` | macos_stealer | [`524a7bcc8e...`](https://www.virustotal.com/gui/file/524a7bcc8edcadc6f4381459f79769e1ec534aa78f66e5c38a6678bd55cf2572) | `29/62` | `trojan.cldsync/abtrojan` |
| 2026-10-16 09:42:46 | **MalwareBazaar** | `Macho_Trojan_CloudSync_1006YR` | macos_stealer | [`cc54d90920...`](https://www.virustotal.com/gui/file/cc54d90920a73cc5e176664f61c6f601c95d693e431e79ae1148cb91e83c9235) | `29/62` | `trojan.cldsync/abtrojan` |
| 2026-10-16 09:42:46 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`4799b1f412...`](https://www.virustotal.com/gui/file/4799b1f41221745e4e3e902526b9635e697b64c5c07a344b59fe1a6ddc018c34) | `34/62` | `trojan.stealer/amos` |
| 2026-10-16 09:42:46 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`5b2531253b...`](https://www.virustotal.com/gui/file/5b2531253b7fd1a18516dd937ad2e0ca3093b3b2f058b1a173fc65b037b37493) | `8/58` | `trojan.gajl/multiverze` |
| 2026-10-16 09:33:37 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`e42b8c35db...`](https://www.virustotal.com/gui/file/e42b8c35db5ab7169327b9185c3e05db4a156e8922b985da61bcbd6223df8aea) | `19/62` | `trojan.amos/class` |
| 2026-10-16 09:33:37 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`1e8ed19e77...`](https://www.virustotal.com/gui/file/1e8ed19e771e7a9378daf3b3652802143345db8ea4196e560e54f28176ef958a) | `21/63` | `trojan.amos/class` |
| 2026-10-16 09:33:37 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`faf572c1c9...`](https://www.virustotal.com/gui/file/faf572c1c989ca17101d5003bceb8b4796e709b93bf014f642b2a2c4b7b77fb4) | `16/57` | `trojan.amos/class` |
| 2026-10-16 09:33:37 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`c3b8375f09...`](https://www.virustotal.com/gui/file/c3b8375f092798ac851bfacdb94310ccabfebcbe106f6e7324764a0e4fd4ea57) | `6/61` | `trojan.` |
| 2026-10-12 12:01:07 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`ddb7afd3e2...`](https://www.virustotal.com/gui/file/ddb7afd3e2d53100759643bb3b94b5cf011840d518d5553f33ae5c780af784e6) | `21/63` | `trojan.imnw/multiverze` |
| 2026-10-09 09:35:31 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`9135f4d24e...`](https://www.virustotal.com/gui/file/9135f4d24e45365b9680df64f6d0f51dba3a4ff7b740ca1cff3bc6b9998c474c) | `31/58` | `trojan.stealer/amos` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `MALW_macOS_MacSync_Stealer_Universal` | macos_MALW_macOS_MacSync_Stealer | [`f5471a00bb...`](https://www.virustotal.com/gui/file/f5471a00bb6cdaf01e44311c04de2e66c6f92ccc4b8e42bbb1bcb4e48f86ef3e) | `33/62` | `trojan.stealer/coins` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `MALW_macOS_MacSync_Stealer_Universal` | macos_MALW_macOS_MacSync_Stealer | [`f80ff07231...`](https://www.virustotal.com/gui/file/f80ff072316e2d62490df743cbd5363bfb6ec5459409cc162d0602f7a1c607bb) | `32/62` | `trojan.stealer/coins` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `Macho_Trojan_CloudSync_Generic` | macos_cloud_sync | [`3220acfe8a...`](https://www.virustotal.com/gui/file/3220acfe8afe73c9beec11714cb95e324c56fe3386c5109fcd4cb5ba4873c3a5) | `30/63` | `trojan.cldsync/ravartar` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`fd0cd32edf...`](https://www.virustotal.com/gui/file/fd0cd32edfe9b4f68dcc2fddb8f27c6102e9a9c8b90c5def07ac8e62b2a75303) | `35/63` | `trojan.stealer/amos` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`0f5669e692...`](https://www.virustotal.com/gui/file/0f5669e692760a1316a750622ecd871897d32da3486dd323f024d680543c368a) | `35/62` | `trojan.stealer/amos` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`73491d3f3b...`](https://www.virustotal.com/gui/file/73491d3f3bcfe0c1d4ebefecf8230d0c460fa89703381d9b8923daaa4be170f4) | `36/63` | `trojan.stealer/amos` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`579fb6787d...`](https://www.virustotal.com/gui/file/579fb6787dd60d5fb1ebfe275ccfa58e4b73db4cdc4909de23ac5dd3a9c52439) | `35/61` | `trojan.stealer/amos` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`63320c69b5...`](https://www.virustotal.com/gui/file/63320c69b5733e125a587216bf2a93ac239c2a98686b2a1a00ec23f2b4177648) | `33/60` | `trojan.stealer/amos` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`38c8c79ec7...`](https://www.virustotal.com/gui/file/38c8c79ec773bfc700559243293f4b4409756d5adf63ad78a08d7ca2f38ee0dc) | `35/60` | `trojan.stealer/amos` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`6bfcdb4920...`](https://www.virustotal.com/gui/file/6bfcdb4920383375b7e519918df7eb4db751b974b5571a15ce66b82478012620) | `34/63` | `trojan.stealer/amos` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`4504006d19...`](https://www.virustotal.com/gui/file/4504006d1911057be42435d4625f03d83c4d0b7b6898d14beb9cdeba6cf667b9) | `35/63` | `trojan.amos/amosstealer` |
| 2026-10-08 06:28:54 | **MalwareBazaar** | `Macho_Trojan_CloudSync_Generic` | macos_cloud_sync | [`524a7bcc8e...`](https://www.virustotal.com/gui/file/524a7bcc8edcadc6f4381459f79769e1ec534aa78f66e5c38a6678bd55cf2572) | `29/62` | `trojan.cldsync/abtrojan` |

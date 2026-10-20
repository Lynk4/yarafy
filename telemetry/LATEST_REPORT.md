# Yarafy Telemetry & Threat Hunting Report

**Last Run:** `2026-10-20T18:52:09.961170+00:00`
**Total Samples Scanned:** `17066` | **Total Rule Hits:** `159`

## Hits Breakdown by Source Feed
| Source Feed | Total Hits |
| :--- | :--- |
| **MalwareBazaar** | `106` |
| **VirusTotal Enterprise** | `43` |
| **Local File** | `10` |

## Hits Breakdown by Platform
| Platform | Total Hits |
| :--- | :--- |
| **MACOS** | `159` |
| **WINDOWS** | `0` |
| **LINUX** | `0` |
| **NON-PE** | `0` |

## Hits Breakdown by YARA Rule
| Rule Name | Total Detections |
| :--- | :--- |
| [`macOS_ClickFix_AppleScript_Dropper`](../yara-rules/) | `83` |
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
| 2026-10-20 18:52:09 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`89ab3b9e84...`](https://www.virustotal.com/gui/file/89ab3b9e84198d8bb8d207964ee8cc02d75da3d6bdbd9cf1ccf34f9500272053) | `10/63` | `trojan.amos/najl` |
| 2026-10-20 18:52:09 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`2ff0a95949...`](https://www.virustotal.com/gui/file/2ff0a9594923b8896910fd338b4a899649bb89bca20ace4d00b9fada9da93441) | `6/63` | `trojan.` |
| 2026-10-20 08:26:32 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`1e7cc2bd06...`](https://www.virustotal.com/gui/file/1e7cc2bd060683795a7bfa0ee3610e6b896c71ad20677b65ccde4278594911f9) | `17/63` | `trojan.abtrojan/adlsb4` |
| 2026-10-20 08:26:32 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`2f4b6d386a...`](https://www.virustotal.com/gui/file/2f4b6d386a70eea4d5aaa951b8a9095095410cef0963b4a769aa9cc4b7e356a0) | `14/63` | `trojan.amos/wocsql` |
| 2026-10-20 08:26:32 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`2d6f829d87...`](https://www.virustotal.com/gui/file/2d6f829d87773207cabc9360f8aae81adcf838829be00b0b6040fb7ebccf393e) | `14/63` | `trojan.amos/ing4jl` |
| 2026-10-20 08:26:32 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`4079024414...`](https://www.virustotal.com/gui/file/407902441438f0f73a0ce5f5b89f50f9b6fcf7551a6179617fa21efac1cd524f) | `12/61` | `trojan.umhl` |
| 2026-10-20 08:26:32 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`f59d0a5f63...`](https://www.virustotal.com/gui/file/f59d0a5f63972619bb2c5184cecbe7d4fc59d5e291ede27ba13acbe49dab839b) | `13/62` | `trojan.krv1gq/ncnw` |
| 2026-10-20 08:26:32 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`706c3b12e8...`](https://www.virustotal.com/gui/file/706c3b12e8be63504ef14663eb7084a2d14587419166918f2fe32cfe55d78ee8) | `12/63` | `trojan.iqil/z1prtc` |
| 2026-10-20 08:26:32 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`ac4484f613...`](https://www.virustotal.com/gui/file/ac4484f6139484fd0099d9fa54d6feebb91c26418f4e7aed9eba6185da58b7d4) | `11/63` | `trojan.szb01p/timw` |
| 2026-10-20 08:26:32 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`863ea1012d...`](https://www.virustotal.com/gui/file/863ea1012d1379896cba11f581f4a8e8c86143297f5cdf4c432a8d652a717107) | `12/63` | `trojan.amos/kajl` |
| 2026-10-20 08:26:32 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`1b317f7c91...`](https://www.virustotal.com/gui/file/1b317f7c91282bc41153d12a28a41a883eeb655c245e76f8c3142a8cc8458bb4) | `12/63` | `trojan.amos/wmhl` |
| 2026-10-20 08:26:32 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`9d0c0819b9...`](https://www.virustotal.com/gui/file/9d0c0819b915625b6c7bc2898cb5f1248df6ab941ce86447c059c4d6de5e0002) | `12/63` | `trojan.amos/snkl` |
| 2026-10-20 08:26:32 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`bc0bde5dd5...`](https://www.virustotal.com/gui/file/bc0bde5dd5ca313436bc7119c5f603d9f4fb99dcbb09b2eaa5fd7ccda2c33794) | `13/63` | `trojan.amos/psmw` |
| 2026-10-19 21:33:01 | **MalwareBazaar** | `OSX_Foxveil_AMOS_Stage4_Generic` | macos_stealer | [`8e9dd132e0...`](https://www.virustotal.com/gui/file/8e9dd132e044d2d44ef09c4bcce1ab64f089100a7c6414c9b8d0c95c57cabcd0) | `32/63` | `trojan.amos/infostl` |
| 2026-10-19 21:33:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`ab5b9b53b6...`](https://www.virustotal.com/gui/file/ab5b9b53b603bc5bc8abb0eb0aab014d82d20b603b40fdc69642b5b907fcea43) | `18/63` | `trojan.amos/class` |
| 2026-10-19 21:33:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`225f89ad50...`](https://www.virustotal.com/gui/file/225f89ad501a71af48f405b6c61309a6c0f041ad8add6625e75274c536954f1f) | `20/63` | `trojan.amos/class` |
| 2026-10-19 21:33:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`08e7c04e22...`](https://www.virustotal.com/gui/file/08e7c04e22c51313e5095f2db39e11fcc59adf56a63481ae92d8730e2788edc7) | `12/63` | `trojan.amos` |
| 2026-10-19 21:33:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`47258dad12...`](https://www.virustotal.com/gui/file/47258dad12e7bbb34a8421c79e98a10f62adc6d613fa8d94c30599fffbb040f8) | `12/63` | `trojan.amos/bnhl` |
| 2026-10-19 21:33:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`cf28f44cfe...`](https://www.virustotal.com/gui/file/cf28f44cfec7384cd572f5457a2d7e4a09fd72f7a29264393961fa4493b29c19) | `21/63` | `trojan.abtrojan/class` |
| 2026-10-19 21:33:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | `b0a7077b5d...` | `N/A` | `N/A` |
| 2026-10-19 21:33:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | `a436ac961c...` | `N/A` | `N/A` |
| 2026-10-19 02:52:22 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`b5d4aba0fe...`](https://www.virustotal.com/gui/file/b5d4aba0fe4004e851756d0329f0c165db2c1667c7c73516e0f1537c9afd3298) | `24/63` | `trojan.amos/class` |
| 2026-10-19 02:52:22 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`ff9c8f57fa...`](https://www.virustotal.com/gui/file/ff9c8f57fa3ec4c935c343bc636dee3253e6b6e4dbbd0d64e7898f0c7f7c5598) | `22/63` | `trojan.amos/cbg41x` |
| 2026-10-19 02:52:22 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`0119e2bc22...`](https://www.virustotal.com/gui/file/0119e2bc2281379155fe73917dc347f31501873867e7d8174b71c8cdbf0e5c8f) | `21/63` | `trojan.amos/class` |
| 2026-10-19 02:52:22 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`40dc77a48f...`](https://www.virustotal.com/gui/file/40dc77a48faae52f4ab7e2fbac202427947ffd48fc4e3dc6ed9f9b4403dc590c) | `21/63` | `trojan.amos/class` |
| 2026-10-19 02:32:11 | **Local File** | `MALW_macOS_MacSync_Stealer_Universal` | macos_MALW_macOS_MacSync_Stealer | [`fa65230781...`](https://www.virustotal.com/gui/file/fa65230781d2d3afc4152f23e3c4c91a91978d67dda2519d6eeb42476d41dc5a) | `26/63` | `trojan.stealer/coins` |
| 2026-10-19 02:32:11 | **Local File** | `OSX_Stealer_AMOS_Generic` | macos | [`592d93f589...`](https://www.virustotal.com/gui/file/592d93f5899fb3245b962e9388e503efa085729cc41e1404feaf5ab04aeded45) | `32/63` | `trojan.stealer/amos` |
| 2026-10-19 02:32:11 | **Local File** | `Macho_hVNCRat_shelldropper` | macos_stealer | [`dce578f5af...`](https://www.virustotal.com/gui/file/dce578f5af994c77785b96087e4fd4d8124482eab896dceb175a26342a84e31b) | `5/58` | `trojan.horse/qgil` |
| 2026-10-19 02:32:11 | **Local File** | `Macho_hVNCRat_campaign` | macos_stealer | [`5681c400f0...`](https://www.virustotal.com/gui/file/5681c400f0ed8431b3950e92864e52cffb0bf93a359edffb49e423ad5e8ef0b8) | `4/63` | `trojan.horse/stealer` |
| 2026-10-19 02:32:11 | **Local File** | `Macho_hVNCRat_generic` | macos_stealer | [`5681c400f0...`](https://www.virustotal.com/gui/file/5681c400f0ed8431b3950e92864e52cffb0bf93a359edffb49e423ad5e8ef0b8) | `4/63` | `trojan.horse/stealer` |
| 2026-10-19 02:32:11 | **Local File** | `Macho_Trojan_CloudSync_DMG` | macos_cloud_sync | [`faf2eea05f...`](https://www.virustotal.com/gui/file/faf2eea05f3c9f1c4ef8f6be339f5459a38f95cfd9d512bc24e2803230e5c7bf) | `20/58` | `trojan.multiverze/abtrojan` |
| 2026-10-19 02:32:11 | **Local File** | `Macho_Trojan_CloudSync_1007YR` | macos_stealer | [`faf2eea05f...`](https://www.virustotal.com/gui/file/faf2eea05f3c9f1c4ef8f6be339f5459a38f95cfd9d512bc24e2803230e5c7bf) | `20/58` | `trojan.multiverze/abtrojan` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`cefb465886...`](https://www.virustotal.com/gui/file/cefb465886bc813ac91e9ad5b1835eefe9828f251b58eb0da012ee4022ff6d98) | `23/61` | `trojan.class/macho` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`104a6e4b1d...`](https://www.virustotal.com/gui/file/104a6e4b1da8f7b42bdaf887b82f2c12348c6b1ffe52d1de2d964b6329492ad7) | `35/63` | `trojan.stealer/amos` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`3bf9ac9cb2...`](https://www.virustotal.com/gui/file/3bf9ac9cb26ecffd2ab26bb14c81c110b53fe31c196cc774291ad4af804023c3) | `24/63` | `trojan.egairtigado/abrisk` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`ecf0f6b181...`](https://www.virustotal.com/gui/file/ecf0f6b181632fb335c800bcc77cccc5584bc15b5ac594dc68019f05081c3d5d) | `24/63` | `trojan.egairtigado/abtrojan` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`51ad0fe878...`](https://www.virustotal.com/gui/file/51ad0fe8782d9756f1fc647bfd19e649b1b3e55e8b641a295062c935c1939bd8) | `24/63` | `trojan.class/deulm0` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`322a9bdadc...`](https://www.virustotal.com/gui/file/322a9bdadc796f2b2a7459b949ff367ed3258e9a8eefb1af161b557418ce845d) | `26/63` | `trojan.egairtigado/abrisk` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`efc0f30e9b...`](https://www.virustotal.com/gui/file/efc0f30e9b1c8e4b1479006ecdcc95d5d4fa0627af8b294a6babe57da17b58d3) | `28/63` | `trojan.egairtigado/abtrojan` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`e6490a700b...`](https://www.virustotal.com/gui/file/e6490a700b965a6dcf264eb1e8291217d9e52f167470d70bc24806697fabeeaa) | `25/63` | `trojan.multiverze/amos` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`d64921058e...`](https://www.virustotal.com/gui/file/d64921058e03078b75565d5aeea126e75698f39be3c6387d17c5d9fa8536d0ac) | `24/63` | `trojan.egairtigado/amos` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`f2c7af231a...`](https://www.virustotal.com/gui/file/f2c7af231a3dc1a9291a2421d2b67e3c6ed829073fdcbd7aeec3c33a933d2f6e) | `25/63` | `trojan.amos/egairtigado` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`aa2fe64a8b...`](https://www.virustotal.com/gui/file/aa2fe64a8b365f79ba99c5cae660602063d6b555b3dd2e40d05f5293ca2c2a96) | `25/63` | `trojan.amos/class` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`813bb6f2bc...`](https://www.virustotal.com/gui/file/813bb6f2bc378364b4a0ed1405fe6ccd34a1510c4c94fe98f5908e6514999c1a) | `25/63` | `trojan.amos/class` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`6c118d4bd1...`](https://www.virustotal.com/gui/file/6c118d4bd1a56f56756b78134474c2a5becd3f138803d3297155691a427f6524) | `27/63` | `trojan.egairtigado/abtrojan` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`89a2531114...`](https://www.virustotal.com/gui/file/89a25311145ada1664428064bc5b4ae16ec3e322b1399f3d4e753de8aba3ea06) | `30/63` | `trojan.stealer/amos` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`85fce98269...`](https://www.virustotal.com/gui/file/85fce9826974549c2dd4c92a3207cf2543e10676ad2dfad7c8ea429f616cdf21) | `22/63` | `trojan.abpws/amos` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `OSX_Stealer_AMOS_Generic` | macos | [`e395c53437...`](https://www.virustotal.com/gui/file/e395c5343703a570d12620c81b9593ea6117d2f57c95bd8247704d9dbd256ce6) | `30/57` | `trojan.stealer/amos` |
| 2026-10-18 21:15:48 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`81e34b0ec6...`](https://www.virustotal.com/gui/file/81e34b0ec6928234d0a24f9b1634d1e2201fe0fca38bf048229d750ba35f64ca) | `22/60` | `trojan.amos/class` |
| 2026-10-16 09:42:46 | **MalwareBazaar** | `Macho_Trojan_CloudSync_1006YR` | macos_stealer | [`524a7bcc8e...`](https://www.virustotal.com/gui/file/524a7bcc8edcadc6f4381459f79769e1ec534aa78f66e5c38a6678bd55cf2572) | `29/62` | `trojan.cldsync/abtrojan` |

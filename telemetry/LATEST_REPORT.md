# Yarafy Telemetry & Threat Hunting Report

**Last Run:** `2026-10-22T15:06:28.931817+00:00`
**Total Samples Scanned:** `17345` | **Total Rule Hits:** `188`

## Hits Breakdown by Source Feed
| Source Feed | Total Hits |
| :--- | :--- |
| **MalwareBazaar** | `135` |
| **VirusTotal Enterprise** | `43` |
| **Local File** | `10` |

## Hits Breakdown by Platform
| Platform | Total Hits |
| :--- | :--- |
| **MACOS** | `188` |
| **WINDOWS** | `0` |
| **LINUX** | `0` |
| **NON-PE** | `0` |

## Hits Breakdown by YARA Rule
| Rule Name | Total Detections |
| :--- | :--- |
| [`macOS_ClickFix_AppleScript_Dropper`](../yara-rules/) | `112` |
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
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`2e5bb8cc05...`](https://www.virustotal.com/gui/file/2e5bb8cc0558dfed95e93207bdcc39dfd3ed21851d7ba1e8d56dee83088c5e66) | `15/52` | `trojan.class/togkpj` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`13b4b87da6...`](https://www.virustotal.com/gui/file/13b4b87da6046356804ccfa023d66b9809371027b00f62fb4e4812dca34a1571) | `22/63` | `trojan.infostl/amos` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`66a39ad4e5...`](https://www.virustotal.com/gui/file/66a39ad4e53d93de95c3db38822fb265dcc8835328d591edaf3bbbe5098f391f) | `18/63` | `trojan.amos/abtrojan` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`0ef806bb25...`](https://www.virustotal.com/gui/file/0ef806bb25a7206b2a7ab4c936ac6aa540c4777574068d51ec3d65c9e1fb67c4) | `17/63` | `trojan.amos/abtrojan` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`09b5143a55...`](https://www.virustotal.com/gui/file/09b5143a55acbb87423681f6c70a1bbed0034289a7448becc5d3adab51fddb77) | `17/63` | `trojan.amos/abpws` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`4892ea6ae9...`](https://www.virustotal.com/gui/file/4892ea6ae970b1c57b505e511ace698878b29666e0da59867b712ea83db1563b) | `17/62` | `trojan.amos/abtrojan` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`8a2daf154b...`](https://www.virustotal.com/gui/file/8a2daf154b45503f88abb0f9f77ba79ad4044f235f03c2a1ff5604bc9ef1c227) | `15/63` | `trojan.amos/gb0tgg` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`6e7dcc1716...`](https://www.virustotal.com/gui/file/6e7dcc1716e5a94f937f66f0796d10280abe40a11f13d2a258784468de71c478) | `15/63` | `trojan.amos/fkjl` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`68b736e2aa...`](https://www.virustotal.com/gui/file/68b736e2aa1c565c1748fcb17a5e44bbf1727714047fbf50e8c9c9d6844fe6ea) | `21/63` | `trojan.infostl/amos` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`461f5d168c...`](https://www.virustotal.com/gui/file/461f5d168c724db1094e76955ce5ebe15ea611d7d0b497c5f06ffb0baffa10c8) | `23/62` | `trojan.infostl/abtrojan` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`1d6102cbdf...`](https://www.virustotal.com/gui/file/1d6102cbdf119cd3655d9beb30698a97ab69d996f2a1b913c0bd95b32076d2ac) | `18/63` | `trojan.infostl/abpws` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`7a3e4f6ac3...`](https://www.virustotal.com/gui/file/7a3e4f6ac3d726df49bad8f9a1c00bd75a57341238a1be9dac90be5b50b3385c) | `10/63` | `trojan.abbackdoor/siuj` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`30b4ae5036...`](https://www.virustotal.com/gui/file/30b4ae5036e76367f9d1165253dc81d4c7ae9fdced72c95cb4ecffc1f6aefcfd) | `18/63` | `trojan.infostl/class` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`c6dcafd1aa...`](https://www.virustotal.com/gui/file/c6dcafd1aaa7cdbf84e2cc6f1f6b3e6cc6a7c1b74ab995003a5d6f828cdf1268) | `20/63` | `trojan.infostl/abapplication` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`621ed067e8...`](https://www.virustotal.com/gui/file/621ed067e8214758b584df19b7f9726559d32af16267e6217f878d0b96378a29) | `7/59` | `trojan.ogil` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`d47d4a39e8...`](https://www.virustotal.com/gui/file/d47d4a39e80e5c8c233aa4ecfe28d42f89f688a96421ad68baaf4bd5a4c81b31) | `14/63` | `trojan.mmdhlt/uimw` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`bfaba22e0b...`](https://www.virustotal.com/gui/file/bfaba22e0b58c2f5ab977de4322563fdeb3f5a90a573175181f34d4830a7fc97) | `10/61` | `trojan.ssmw` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`a4f89e85ca...`](https://www.virustotal.com/gui/file/a4f89e85ca176c7fccd50335b80e9cb31887297c3e8abb879e35636ae7c6cd68) | `12/60` | `trojan.infostl/gflw` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`805a857543...`](https://www.virustotal.com/gui/file/805a8575437df0241e4f24d3c3d377e7dbcb42924ad9e41664bd0bc7dc26ed9d) | `9/63` | `trojan.eajl` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`94521a0d9d...`](https://www.virustotal.com/gui/file/94521a0d9d77513864171e00075b46b5bededbd849efe056687d8494353815d4) | `13/62` | `trojan.infostl/ekjl` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`932761c3c9...`](https://www.virustotal.com/gui/file/932761c3c90d8db72e53b5e2cbf5f86eee95e15be50e0a4dab91d6e16b33cbd8) | `15/63` | `trojan.infostl/abapplication` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`aeea065171...`](https://www.virustotal.com/gui/file/aeea0651716d990d527a48473e7b54cd56849aee87b8916294c8f2ae81831617) | `11/63` | `trojan.vimw` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`9edd2a4e7c...`](https://www.virustotal.com/gui/file/9edd2a4e7ce79550637ab4dd1dec171087dcf7313547e0935d64725101140a9b) | `10/63` | `trojan.tnkl` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`b626c19713...`](https://www.virustotal.com/gui/file/b626c19713c716a0bc5a49d801300eaade449cec525012a35a6477295b6729a4) | `12/63` | `trojan.infostl` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`44306aa415...`](https://www.virustotal.com/gui/file/44306aa41505302c109d90a5c85c68541b98bf783cb47af912a55b4d5a3dcc99) | `8/60` | `trojan.` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`66bb0add89...`](https://www.virustotal.com/gui/file/66bb0add8962b6b2cf5bb3358e6777a421b54968674d838d7ccd2d3a6da555a0) | `12/63` | `trojan.sgil` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`c81b8c0775...`](https://www.virustotal.com/gui/file/c81b8c0775f0fa25cfe09cab180e88426340cd1e171c033cd70145294504fefd) | `13/63` | `trojan.infostealer/abtrojan` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`1b9ebec7a7...`](https://www.virustotal.com/gui/file/1b9ebec7a73d0a7c135f71904fef98602fa5ff49d137bb145608da207541c15b) | `14/63` | `trojan.infostealer/infostl` |
| 2026-10-22 15:06:28 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`ccdc4d7aa7...`](https://www.virustotal.com/gui/file/ccdc4d7aa75140392ae4d6296c229cb456617f64b6509be93f61ca91412d9af6) | `8/63` | `trojan.lcnw` |
| 2026-10-20 18:52:09 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`89ab3b9e84...`](https://www.virustotal.com/gui/file/89ab3b9e84198d8bb8d207964ee8cc02d75da3d6bdbd9cf1ccf34f9500272053) | `10/63` | `trojan.amos/najl` |
| 2026-10-20 18:52:09 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`2ff0a95949...`](https://www.virustotal.com/gui/file/2ff0a9594923b8896910fd338b4a899649bb89bca20ace4d00b9fada9da93441) | `22/63` | `trojan.infostl/amos` |
| 2026-10-20 08:26:32 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`1e7cc2bd06...`](https://www.virustotal.com/gui/file/1e7cc2bd060683795a7bfa0ee3610e6b896c71ad20677b65ccde4278594911f9) | `25/62` | `trojan.abtrojan/adlsb4` |
| 2026-10-20 08:26:32 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`2f4b6d386a...`](https://www.virustotal.com/gui/file/2f4b6d386a70eea4d5aaa951b8a9095095410cef0963b4a769aa9cc4b7e356a0) | `19/62` | `trojan.amos/class` |
| 2026-10-20 08:26:32 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`2d6f829d87...`](https://www.virustotal.com/gui/file/2d6f829d87773207cabc9360f8aae81adcf838829be00b0b6040fb7ebccf393e) | `26/63` | `trojan.amos/infostl` |
| 2026-10-20 08:26:32 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`4079024414...`](https://www.virustotal.com/gui/file/407902441438f0f73a0ce5f5b89f50f9b6fcf7551a6179617fa21efac1cd524f) | `25/63` | `trojan.abtrojan/amos` |
| 2026-10-20 08:26:32 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`f59d0a5f63...`](https://www.virustotal.com/gui/file/f59d0a5f63972619bb2c5184cecbe7d4fc59d5e291ede27ba13acbe49dab839b) | `18/63` | `trojan.amos/class` |
| 2026-10-20 08:26:32 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`706c3b12e8...`](https://www.virustotal.com/gui/file/706c3b12e8be63504ef14663eb7084a2d14587419166918f2fe32cfe55d78ee8) | `17/60` | `trojan.amos/class` |
| 2026-10-20 08:26:32 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`ac4484f613...`](https://www.virustotal.com/gui/file/ac4484f6139484fd0099d9fa54d6feebb91c26418f4e7aed9eba6185da58b7d4) | `15/60` | `trojan.amos/class` |
| 2026-10-20 08:26:32 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`863ea1012d...`](https://www.virustotal.com/gui/file/863ea1012d1379896cba11f581f4a8e8c86143297f5cdf4c432a8d652a717107) | `19/62` | `trojan.amos/class` |
| 2026-10-20 08:26:32 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`1b317f7c91...`](https://www.virustotal.com/gui/file/1b317f7c91282bc41153d12a28a41a883eeb655c245e76f8c3142a8cc8458bb4) | `24/63` | `trojan.amos/infostl` |
| 2026-10-20 08:26:32 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`9d0c0819b9...`](https://www.virustotal.com/gui/file/9d0c0819b915625b6c7bc2898cb5f1248df6ab941ce86447c059c4d6de5e0002) | `24/63` | `trojan.amos/infostl` |
| 2026-10-20 08:26:32 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`bc0bde5dd5...`](https://www.virustotal.com/gui/file/bc0bde5dd5ca313436bc7119c5f603d9f4fb99dcbb09b2eaa5fd7ccda2c33794) | `23/63` | `trojan.amos/class` |
| 2026-10-19 21:33:01 | **MalwareBazaar** | `OSX_Foxveil_AMOS_Stage4_Generic` | macos_stealer | [`8e9dd132e0...`](https://www.virustotal.com/gui/file/8e9dd132e044d2d44ef09c4bcce1ab64f089100a7c6414c9b8d0c95c57cabcd0) | `32/63` | `trojan.amos/infostl` |
| 2026-10-19 21:33:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`ab5b9b53b6...`](https://www.virustotal.com/gui/file/ab5b9b53b603bc5bc8abb0eb0aab014d82d20b603b40fdc69642b5b907fcea43) | `21/63` | `trojan.amos/class` |
| 2026-10-19 21:33:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`225f89ad50...`](https://www.virustotal.com/gui/file/225f89ad501a71af48f405b6c61309a6c0f041ad8add6625e75274c536954f1f) | `21/63` | `trojan.amos/class` |
| 2026-10-19 21:33:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`08e7c04e22...`](https://www.virustotal.com/gui/file/08e7c04e22c51313e5095f2db39e11fcc59adf56a63481ae92d8730e2788edc7) | `18/62` | `trojan.amos/class` |
| 2026-10-19 21:33:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`47258dad12...`](https://www.virustotal.com/gui/file/47258dad12e7bbb34a8421c79e98a10f62adc6d613fa8d94c30599fffbb040f8) | `19/62` | `trojan.amos/bnhl` |
| 2026-10-19 21:33:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`cf28f44cfe...`](https://www.virustotal.com/gui/file/cf28f44cfec7384cd572f5457a2d7e4a09fd72f7a29264393961fa4493b29c19) | `26/63` | `trojan.abtrojan/amos` |
| 2026-10-19 21:33:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`b0a7077b5d...`](https://www.virustotal.com/gui/file/b0a7077b5d5baa1fb2d31115fbf226bac47f54c9aa499de343385cab6712f79c) | `11/63` | `trojan.` |
| 2026-10-19 21:33:01 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | `a436ac961c...` | `N/A` | `N/A` |

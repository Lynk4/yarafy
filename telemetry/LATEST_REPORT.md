# Yarafy Telemetry & Threat Hunting Report

**Last Run:** `2026-11-01T15:48:08.463222+00:00`
**Total Samples Scanned:** `19383` | **Total Rule Hits:** `580`

## Hits Breakdown by Source Feed
| Source Feed | Total Hits |
| :--- | :--- |
| **MalwareBazaar** | `256` |
| **VirusTotal Enterprise** | `43` |
| **Local File** | `281` |

## Hits Breakdown by Platform
| Platform | Total Hits |
| :--- | :--- |
| **MACOS** | `580` |
| **WINDOWS** | `0` |
| **LINUX** | `0` |
| **NON-PE** | `0` |

## Hits Breakdown by YARA Rule
| Rule Name | Total Detections |
| :--- | :--- |
| [`OSX_Malware_EvilQuest_ThiefQuest`](../yara-rules/) | `266` |
| [`macOS_ClickFix_AppleScript_Dropper`](../yara-rules/) | `234` |
| [`OSX_Stealer_AMOS_Generic`](../yara-rules/) | `39` |
| [`OSX_Foxveil_AMOS_Stage4_Generic`](../yara-rules/) | `18` |
| [`MALW_macOS_MacSync_Stealer_Universal`](../yara-rules/) | `7` |
| [`APT_macOS_RustBucket_Behavioral_Indicators`](../yara-rules/) | `3` |
| [`Macho_Trojan_CloudSync_Generic`](../yara-rules/) | `3` |
| [`Macho_Trojan_CloudSync_1006YR`](../yara-rules/) | `2` |
| [`Macho_Jockey_Implant`](../yara-rules/) | `2` |
| [`Macho_Trojan_CloudSync_1007YR`](../yara-rules/) | `1` |
| [`Macho_Trojan_CloudSync_DMG`](../yara-rules/) | `1` |
| [`Macho_hVNCRat_generic`](../yara-rules/) | `1` |
| [`Macho_hVNCRat_campaign`](../yara-rules/) | `1` |
| [`Macho_hVNCRat_shelldropper`](../yara-rules/) | `1` |
| [`macOS_Backdoor_C5_Implant`](../yara-rules/) | `1` |

## Recent Positive Detections
| Timestamp | Source Feed | Rule | Platform | SHA256 | VT Detection | VT Threat Label |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-11-01 15:48:08 | **Local File** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | `2338d9333c...` | `N/A` | `N/A` |
| 2026-11-01 15:48:08 | **Local File** | `Macho_Jockey_Implant` | macOS | `2338d9333c...` | `N/A` | `N/A` |
| 2026-11-01 15:48:08 | **Local File** | `macOS_ClickFix_AppleScript_Dropper` | macos_droppers_clickfix_yar | `a1be741da7...` | `N/A` | `N/A` |
| 2026-11-01 15:48:08 | **Local File** | `Macho_Jockey_Implant` | macOS | `a1be741da7...` | `N/A` | `N/A` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`3168c669fa...`](https://www.virustotal.com/gui/file/3168c669fae2b267641c203e1abf6fa8e6011201ab8187dfe06d0168ff957c7f) | `22/63` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`2cbc03368b...`](https://www.virustotal.com/gui/file/2cbc03368b2c63103af1e705a0dd42efe93514f87461ee14d9df858ec19e6a68) | `21/63` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`0611cf61fa...`](https://www.virustotal.com/gui/file/0611cf61fa7ef2bab6cabd19207b0256a69a2981966b1f32691057c7dc03a433) | `21/63` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`b3ffa0ce81...`](https://www.virustotal.com/gui/file/b3ffa0ce815def773ca9e9807af167f1378fcebf91eafd1ddaf86b1238fa5412) | `23/63` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`9078f1a436...`](https://www.virustotal.com/gui/file/9078f1a436d99d859645a65df94b93e80e516972146ce895efed935c642ccba9) | `23/62` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`d6ce062f26...`](https://www.virustotal.com/gui/file/d6ce062f26b771b19a085a727ca13d5c568037cee3039a1bbf8c261e8c44e363) | `25/63` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`114b69aa53...`](https://www.virustotal.com/gui/file/114b69aa53a40d7702a11ff81e3fc1d7104a3132c3395f403e6033c68f181230) | `22/63` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`470034fb48...`](https://www.virustotal.com/gui/file/470034fb481dec06585288f94abcc8e9375b12c29a86d64dc30b1a68c24c0282) | `21/62` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`1fbdd92514...`](https://www.virustotal.com/gui/file/1fbdd925143e28ea6542bcc3b15cd44de7c0b226082f6f99450f0e1822db2068) | `23/62` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`acd2e7872e...`](https://www.virustotal.com/gui/file/acd2e7872edb9612a92e835bd243a83d185407e1680dea2e70845620874ff1dc) | `31/63` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`6335a44275...`](https://www.virustotal.com/gui/file/6335a4427566446e65202fb47dac5bac3433308c5daabf2293afb3c795f5353c) | `32/63` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`87367d9c60...`](https://www.virustotal.com/gui/file/87367d9c60bb5923526138d10340a60d13d150f3280bba966d0ef8a335893635) | `30/63` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`e2fcffd2ce...`](https://www.virustotal.com/gui/file/e2fcffd2ce53fe38b555db86e14e96b706eb811367dba4725f96a248c667b9a8) | `24/54` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`643af4611e...`](https://www.virustotal.com/gui/file/643af4611e02c36280cdf4a9b22be3488ec48278db7511e268c13d0c11a0daf9) | `30/63` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`a2badf05b1...`](https://www.virustotal.com/gui/file/a2badf05b11de0f772600c9fef2357c1f514a0ca21feb43240f188dbf7522992) | `30/62` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`bb44908841...`](https://www.virustotal.com/gui/file/bb4490884100ee84e132ea822d06da99508becdc16e434dcf11ade19b0971dd0) | `30/62` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`8220416c31...`](https://www.virustotal.com/gui/file/8220416c319dfc519aaf6023ac5c50394d758e3ebe436f3e7c43ff7feb19c0a0) | `30/63` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`8ac8e98308...`](https://www.virustotal.com/gui/file/8ac8e983086e7e35004a8ea6575a37e14b986c518b13bc5c906e3df89f37d8d3) | `30/63` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`1c5efea856...`](https://www.virustotal.com/gui/file/1c5efea856059fc548f2b21e9e6e5079727949e5c86f8f428acfeef314ed1060) | `30/63` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`5300c0e029...`](https://www.virustotal.com/gui/file/5300c0e0296ae4d2897ea72b5282b2fa57f8b824507e1a3d9dd80d6530395fdc) | `29/62` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`f64b308043...`](https://www.virustotal.com/gui/file/f64b3080432867f3778e62399cc109dfbc10ddc924bc5221daa3c1d54eecc831) | `30/63` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`0c6dc7c70d...`](https://www.virustotal.com/gui/file/0c6dc7c70dd1f121245c5eb743c18fc8a9532024e137535070d6c8479e7ccd9a) | `21/63` | `trojan.infostl/amos` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`83ef81d48a...`](https://www.virustotal.com/gui/file/83ef81d48afa643d27fe562d1c4a709a35a42b10cd57ea82213f0fdeb9d78633) | `30/61` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`69092c70e3...`](https://www.virustotal.com/gui/file/69092c70e390ba31429d4bbd08ca01eef3415e665551d3d3a66b673f36ed48d3) | `13/63` | `trojan.infostl/amos` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`85279394e9...`](https://www.virustotal.com/gui/file/85279394e95efea3d2678c9561021cb4a9f7a4d88dbafc74668ee918fff0fd0a) | `9/55` | `trojan.infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`54c7ebe70c...`](https://www.virustotal.com/gui/file/54c7ebe70c5981d14bda4f2ed99adbac28fcf390e4ddd0e0f272dd893f6caa1b) | `14/63` | `trojan.infostl/amos` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`23746b4516...`](https://www.virustotal.com/gui/file/23746b451646aeaec0e56f813c7654fd75cb3c5a6d7c0e75fcda66c6287e5df2) | `13/63` | `trojan.infostl/amos` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`f9713062c7...`](https://www.virustotal.com/gui/file/f9713062c7f48d9689b2f921def5c3ebcb35e036b2ab694d625102dbadce8b52) | `13/63` | `trojan.infostl/amos` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`bb4568b5a0...`](https://www.virustotal.com/gui/file/bb4568b5a0a179f5391be75ac164900363133b29c24b225438f66c17a741d2dd) | `12/63` | `trojan.infostl/amos` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`a8ee26aaa4...`](https://www.virustotal.com/gui/file/a8ee26aaa41e04b86cdeebd2c3748171bec0f8e4fab02f9a48cd5bbedd5db544) | `12/63` | `trojan.infostl/amos` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`9eabb901cc...`](https://www.virustotal.com/gui/file/9eabb901cc361b1b74cda3d7449ccc45d4b142c822c5e78b47246b0d8bbf7bee) | `14/63` | `trojan.infostl/amos` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`eb38f2f91b...`](https://www.virustotal.com/gui/file/eb38f2f91b58545f0511de0954534472e65de8b07abb57cee40a73576b0318af) | `14/63` | `trojan.infostl/amos` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`2a93e929b6...`](https://www.virustotal.com/gui/file/2a93e929b69caa6dc56901cda012b0073d83a4682a025193a0fc7234fedff83f) | `14/63` | `trojan.infostl/amos` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`c3eec7ca61...`](https://www.virustotal.com/gui/file/c3eec7ca615e28918446d87032d4630279a77979a8e863cc43456b109d664d48) | `12/63` | `trojan.infostl/amos` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`1eb39dbd8c...`](https://www.virustotal.com/gui/file/1eb39dbd8ca631431e37f173fa80b00fbac4a6c3a26effe6dacbe5b3eb4d8ecd) | `30/63` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`ccb3693600...`](https://www.virustotal.com/gui/file/ccb36936001ee1f0c0c70eac9f7fe177d5652afb20f351ff1122c93e42045320) | `29/61` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`14c2594cae...`](https://www.virustotal.com/gui/file/14c2594caebd59572aaf0410e92b06f112dc3b2b9640c66aa820b87d5b898689) | `14/62` | `trojan.infostl/amos` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`747ae1b662...`](https://www.virustotal.com/gui/file/747ae1b6626bd476e0d01ca5862d73d789393ec17481ca652669351d43a6bd3a) | `24/63` | `trojan.infostl/amos` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`bff661c290...`](https://www.virustotal.com/gui/file/bff661c290456430436cb22cf83826e9e63b2959764fe27cdb725cb975b8f416) | `6/61` | `trojan.amos` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`ac22530ddc...`](https://www.virustotal.com/gui/file/ac22530ddcc9b0ce1841dcc1c82ce813dc04a2c37d29bf393388d3a214ac6626) | `12/62` | `trojan.infostl/amos` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`326eaea523...`](https://www.virustotal.com/gui/file/326eaea523a3f44a6faebafb5bc8bf4395c713b4a6d375e8b57f2f6d23602983) | `13/63` | `trojan.infostl/adhl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`99ec22bed7...`](https://www.virustotal.com/gui/file/99ec22bed70db1293ac55f87019f49d4ce04e2deacb503f498b072b72979d524) | `11/63` | `trojan.infostl/amos` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`3f84244dca...`](https://www.virustotal.com/gui/file/3f84244dcab460b6fba60510836251c5999611c7f440d6bdad5c63121909a9f9) | `15/63` | `trojan.infostl/abapplication` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`7c3b234169...`](https://www.virustotal.com/gui/file/7c3b234169d90ac5d8b18e56e5c46012319124a225316a962506b236fc952075) | `29/63` | `trojan.amos/infostl` |
| 2026-10-31 19:26:14 | **MalwareBazaar** | `macOS_ClickFix_AppleScript_Dropper` | macos_macOS_ClickFix_AppleScript | [`3bba0dd56b...`](https://www.virustotal.com/gui/file/3bba0dd56b220041d6a7080fa8f53d8563bf2ced7796e88c9dc1b7beba44785a) | `18/47` | `trojan.infostl/amos` |
| 2026-10-30 21:11:52 | **Local File** | `OSX_Malware_EvilQuest_ThiefQuest` | macos_ransomware | `3a5cd04869...` | `N/A` | `N/A` |

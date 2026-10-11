# Cypher AI — MITRE ATT&CK Database Complete Inventory

## 1. Enterprise Tactics (15 Total)

| ATT&CK ID | Name | Shortname |
|---|---|---|
| TA0001 | Initial Access | `initial-access` |
| TA0002 | Execution | `execution` |
| TA0003 | Persistence | `persistence` |
| TA0004 | Privilege Escalation | `privilege-escalation` |
| TA0005 | Stealth | `stealth` |
| TA0006 | Credential Access | `credential-access` |
| TA0007 | Discovery | `discovery` |
| TA0008 | Lateral Movement | `lateral-movement` |
| TA0009 | Collection | `collection` |
| TA0010 | Exfiltration | `exfiltration` |
| TA0011 | Command and Control | `command-and-control` |
| TA0040 | Impact | `impact` |
| TA0042 | Resource Development | `resource-development` |
| TA0043 | Reconnaissance | `reconnaissance` |
| TA0112 | Defense Impairment | `defense-impairment` |

## 2. Defensive Mitigations (44 Total)

| ATT&CK ID | Mitigation Name |
|---|---|
| M1013 | Application Developer Guidance |
| M1015 | Active Directory Configuration |
| M1016 | Vulnerability Scanning |
| M1017 | User Training |
| M1018 | User Account Management |
| M1019 | Threat Intelligence Program |
| M1020 | SSL/TLS Inspection |
| M1021 | Restrict Web-Based Content |
| M1022 | Restrict File and Directory Permissions |
| M1024 | Restrict Registry Permissions |
| M1025 | Privileged Process Integrity |
| M1026 | Privileged Account Management |
| M1027 | Password Policies |
| M1028 | Operating System Configuration |
| M1029 | Remote Data Storage |
| M1030 | Network Segmentation |
| M1031 | Network Intrusion Prevention |
| M1032 | Multi-factor Authentication |
| M1033 | Limit Software Installation |
| M1034 | Limit Hardware Installation |
| M1035 | Limit Access to Resource Over Network |
| M1036 | Account Use Policies |
| M1037 | Filter Network Traffic |
| M1038 | Execution Prevention |
| M1039 | Environment Variable Permissions |
| M1040 | Behavior Prevention on Endpoint |
| M1041 | Encrypt Sensitive Information |
| M1042 | Disable or Remove Feature or Program |
| M1043 | Credential Access Protection |
| M1044 | Restrict Library Loading |
| M1045 | Code Signing |
| M1046 | Boot Integrity |
| M1047 | Audit |
| M1048 | Application Isolation and Sandboxing |
| M1049 | Antivirus/Antimalware |
| M1050 | Exploit Protection |
| M1051 | Update Software |
| M1052 | User Account Control |
| M1053 | Data Backup |
| M1054 | Software Configuration |
| M1055 | Do Not Mitigate |
| M1056 | Pre-compromise |
| M1057 | Data Loss Prevention |
| M1060 | Out-of-Band Communications Channel |

## 3. Threat Groups / APTs (176 Total)

| ATT&CK ID | Group Name | Known Aliases |
|---|---|---|
| G0001 | Axiom | Axiom, Group 72 |
| G0002 | Moafee | Moafee |
| G0003 | Cleaver | Cleaver, Threat Group 2889, TG-2889 |
| G0004 | Ke3chang | Ke3chang, APT15, Mirage, Vixen Panda, GREF |
| G0005 | APT12 | APT12, IXESHE, DynCalc, Numbered Panda, DNSCALC |
| G0006 | APT1 | APT1, Comment Crew, Comment Group, Comment Panda |
| G0007 | APT28 | APT28, IRON TWILIGHT, SNAKEMACKEREL, Swallowtail, Group 74 |
| G0008 | Carbanak | Carbanak, Anunak |
| G0009 | Deep Panda | Deep Panda, Shell Crew, WebMasters, KungFu Kittens, PinkPanther |
| G0010 | Turla | Turla, IRON HUNTER, Group 88, Waterbug, WhiteBear |
| G0011 | PittyTiger | PittyTiger |
| G0012 | Darkhotel | Darkhotel, DUBNIUM, Zigzag Hail |
| G0013 | APT30 | APT30 |
| G0016 | APT29 | APT29, IRON RITUAL, IRON HEMLOCK, NobleBaron, Dark Halo |
| G0017 | DragonOK | DragonOK |
| G0018 | admin@338 | admin@338 |
| G0019 | Naikon | Naikon |
| G0020 | Equation | Equation |
| G0021 | Molerats | Molerats, Operation Molerats, Gaza Cybergang |
| G0022 | APT3 | APT3, Gothic Panda, Pirpi, UPS Team, Buckeye |
| G0023 | APT16 | APT16 |
| G0024 | Putter Panda | Putter Panda, APT2, MSUpdater |
| G0025 | APT17 | APT17, Deputy Dog |
| G0026 | APT18 | APT18, TG-0416, Dynamite Panda, Threat Group-0416 |
| G0027 | Threat Group-3390 | Threat Group-3390, Earth Smilodon, TG-3390, Emissary Panda, BRONZE UNION |
| G0028 | Threat Group-1314 | Threat Group-1314, TG-1314 |
| G0029 | Scarlet Mimic | Scarlet Mimic |
| G0030 | Lotus Blossom | Lotus Blossom, DRAGONFISH, Spring Dragon, RADIUM, Raspberry Typhoon |
| G0032 | Lazarus Group | Lazarus Group, Labyrinth Chollima, HIDDEN COBRA, Guardians of Peace, ZINC |
| G0033 | Poseidon Group | Poseidon Group |
| G0034 | Sandworm Team | Sandworm Team, ELECTRUM, Telebots, IRON VIKING, BlackEnergy (Group) |
| G0035 | Dragonfly | Dragonfly, TEMP.Isotope, DYMALLOY, Berserk Bear, TG-4192 |
| G0036 | GCMAN | GCMAN |
| G0037 | FIN6 | FIN6, Magecart Group 6, ITG08, Skeleton Spider, TAAL |
| G0038 | Stealth Falcon | Stealth Falcon |
| G0039 | Suckfly | Suckfly |
| G0040 | Patchwork | Patchwork, Hangover Group, Dropping Elephant, Chinastrats, MONSOON |
| G0041 | Strider | Strider, ProjectSauron |
| G0043 | Group5 | Group5 |
| G0044 | Winnti Group | Winnti Group, Blackfly |
| G0045 | menuPass | menuPass, Cicada, POTASSIUM, Stone Panda, APT10 |
| G0046 | FIN7 | FIN7, GOLD NIAGARA, ITG14, Carbon Spider, ELBRUS |
| G0047 | Gamaredon Group | Gamaredon Group, IRON TILDEN, Primitive Bear, ACTINIUM, Armageddon |
| G0048 | RTM | RTM |
| G0049 | OilRig | OilRig, COBALT GYPSY, IRN2, APT34, Helix Kitten |
| G0050 | APT32 | APT32, SeaLotus, OceanLotus, APT-C-00, Canvas Cyclone |
| G0051 | FIN10 | FIN10 |
| G0052 | CopyKittens | CopyKittens |
| G0053 | FIN5 | FIN5 |
| G0054 | Sowbug | Sowbug |
| G0055 | NEODYMIUM | NEODYMIUM |
| G0056 | PROMETHIUM | PROMETHIUM, StrongPity |
| G0059 | Magic Hound | Magic Hound, TA453, COBALT ILLUSION, Charming Kitten, ITG18 |
| G0060 | BRONZE BUTLER | BRONZE BUTLER, REDBALDKNIGHT, Tick |
| G0061 | FIN8 | FIN8, Syssphinx |
| G0062 | TA459 | TA459 |
| G0063 | BlackOasis | BlackOasis |
| G0064 | APT33 | APT33, HOLMIUM, Elfin, Peach Sandstorm |
| G0065 | Leviathan | Leviathan, MUDCARP, Kryptonite Panda, Gadolinium, BRONZE MOHAWK |
| G0066 | Elderwood | Elderwood, Elderwood Gang, Beijing Group, Sneaky Panda |
| G0067 | APT37 | APT37, InkySquid, ScarCruft, Reaper, Group123 |
| G0068 | PLATINUM | PLATINUM |
| G0069 | MuddyWater | MuddyWater, Earth Vetala, MERCURY, Static Kitten, Seedworm |
| G0070 | Dark Caracal | Dark Caracal |
| G0071 | Orangeworm | Orangeworm |
| G0073 | APT19 | APT19, Codoso, C0d0so0, Codoso Team, Sunshop Group |
| G0075 | Rancor | Rancor |
| G0076 | Thrip | Thrip |
| G0077 | Leafminer | Leafminer, Raspite |
| G0078 | Gorgon Group | Gorgon Group |
| G0079 | DarkHydrus | DarkHydrus |
| G0080 | Cobalt Group | Cobalt Group, GOLD KINGSWOOD, Cobalt Gang, Cobalt Spider |
| G0081 | Tropic Trooper | Tropic Trooper, Pirate Panda, KeyBoy |
| G0082 | APT38 | APT38, NICKEL GLADSTONE, BeagleBoyz, Bluenoroff, Stardust Chollima |
| G0083 | SilverTerrier | SilverTerrier |
| G0084 | Gallmaker | Gallmaker |
| G0085 | FIN4 | FIN4 |
| G0087 | APT39 | APT39, ITG07, Chafer, Remix Kitten |
| G0088 | TEMP.Veles | TEMP.Veles, XENOTIME |
| G0089 | The White Company | The White Company |
| G0090 | WIRTE | WIRTE, Ashen Lepus |
| G0091 | Silence | Silence, Whisper Spider |
| G0092 | TA505 | TA505, Hive0065, Spandex Tempest, CHIMBORAZO |
| G0093 | GALLIUM | GALLIUM, Granite Typhoon |
| G0094 | Kimsuky | Kimsuky, Black Banshee, Velvet Chollima, Emerald Sleet, THALLIUM |
| G0095 | Machete | Machete, APT-C-43, El Machete |
| G0096 | APT41 | APT41, Wicked Panda, Brass Typhoon, BARIUM |
| G0098 | BlackTech | BlackTech, Palmerworm |
| G0099 | APT-C-36 | APT-C-36, Blind Eagle, TAG-144, AguilaCiega, APT-Q-98 |
| G0100 | Inception | Inception, Inception Framework, Cloud Atlas |
| G0102 | Wizard Spider | Wizard Spider, UNC1878, TEMP.MixMaster, Grim Spider, FIN12 |
| G0103 | Mofang | Mofang |
| G0105 | DarkVishnya | DarkVishnya |
| G0106 | Rocke | Rocke |
| G0107 | Whitefly | Whitefly |
| G0108 | Blue Mockingbird | Blue Mockingbird |
| G0112 | Windshift | Windshift, Bahamut |
| G0114 | Chimera | Chimera |
| G0115 | GOLD SOUTHFIELD | GOLD SOUTHFIELD, Pinchy Spider |
| G0117 | Fox Kitten | Fox Kitten, UNC757, Parisite, Pioneer Kitten, RUBIDIUM |
| G0119 | Indrik Spider | Indrik Spider, Evil Corp, Manatee Tempest, DEV-0243, UNC2165 |
| G0120 | Evilnum | Evilnum |
| G0121 | Sidewinder | Sidewinder, T-APT-04, Rattlesnake |
| G0122 | Silent Librarian | Silent Librarian, TA407, COBALT DICKENS |
| G0123 | Volatile Cedar | Volatile Cedar, Lebanese Cedar |
| G0124 | Windigo | Windigo |
| G0125 | HAFNIUM | HAFNIUM, Operation Exchange Marauder, Silk Typhoon |
| G0126 | Higaisa | Higaisa |
| G0127 | TA551 | TA551, GOLD CABIN, Shathak |
| G0128 | ZIRCONIUM | ZIRCONIUM, APT31, Violet Typhoon |
| G0129 | Mustang Panda | Mustang Panda, TA416, RedDelta, BRONZE PRESIDENT, STATELY TAURUS |
| G0130 | Ajax Security Team | Ajax Security Team, Operation Woolen-Goldfish, AjaxTM, Rocket Kitten, Flying Kitten |
| G0131 | Tonto Team | Tonto Team, Earth Akhlut, BRONZE HUNTLEY, CactusPete, Karma Panda |
| G0133 | Nomadic Octopus | Nomadic Octopus, DustSquad |
| G0134 | Transparent Tribe | Transparent Tribe, COPPER FIELDSTONE, APT36, Mythic Leopard, ProjectM |
| G0135 | BackdoorDiplomacy | BackdoorDiplomacy |
| G0136 | IndigoZebra | IndigoZebra |
| G0137 | Ferocious Kitten | Ferocious Kitten |
| G0138 | Andariel | Andariel, Silent Chollima, PLUTONIUM, Onyx Sleet |
| G0139 | TeamTNT | TeamTNT |
| G0140 | LazyScripter | LazyScripter |
| G0142 | Confucius | Confucius, Confucius APT |
| G0143 | Aquatic Panda | Aquatic Panda |
| G1001 | HEXANE | HEXANE, Lyceum, Siamesekitten, Spirlin |
| G1002 | BITTER | BITTER, T-APT-17 |
| G1003 | Ember Bear | Ember Bear, UNC2589, Bleeding Bear, DEV-0586, Cadet Blizzard |
| G1004 | LAPSUS$ | LAPSUS$, DEV-0537, Strawberry Tempest |
| G1005 | POLONIUM | POLONIUM, Plaid Rain |
| G1006 | Earth Lusca | Earth Lusca, TAG-22, Charcoal Typhoon, CHROMIUM, ControlX |
| G1007 | Aoqin Dragon | Aoqin Dragon |
| G1008 | SideCopy | SideCopy |
| G1009 | Moses Staff | Moses Staff, DEV-0500, Marigold Sandstorm |
| G1011 | EXOTIC LILY | EXOTIC LILY |
| G1012 | CURIUM | CURIUM, Crimson Sandstorm, TA456, Tortoise Shell, Yellow Liderc |
| G1013 | Metador | Metador |
| G1014 | LuminousMoth | LuminousMoth |
| G1015 | Scattered Spider | Scattered Spider, Roasted 0ktapus, Octo Tempest, Storm-0875, UNC3944 |
| G1016 | FIN13 | FIN13, Elephant Beetle |
| G1017 | Volt Typhoon | Volt Typhoon, BRONZE SILHOUETTE, Vanguard Panda, DEV-0391, UNC3236 |
| G1018 | TA2541 | TA2541 |
| G1019 | MoustachedBouncer | MoustachedBouncer |
| G1020 | Mustard Tempest | Mustard Tempest, DEV-0206, TA569, GOLD PRELUDE, UNC1543 |
| G1021 | Cinnamon Tempest | Cinnamon Tempest, DEV-0401, Emperor Dragonfly, BRONZE STARLIGHT |
| G1022 | ToddyCat | ToddyCat |
| G1023 | APT5 | APT5, Mulberry Typhoon, MANGANESE, BRONZE FLEETWOOD, Keyhole Panda |
| G1024 | Akira | Akira, GOLD SAHARA, PUNK SPIDER, Howling Scorpius |
| G1026 | Malteiro | Malteiro |
| G1028 | APT-C-23 | APT-C-23, Mantis, Arid Viper, Desert Falcon, TAG-63 |
| G1030 | Agrius | Agrius, Pink Sandstorm, AMERICIUM, Agonizing Serpens, BlackShadow |
| G1031 | Saint Bear | Saint Bear, Storm-0587, TA471, UAC-0056, Lorec53 |
| G1032 | INC Ransom | INC Ransom, GOLD IONIC |
| G1033 | Star Blizzard | Star Blizzard, SEABORGIUM, Callisto Group, TA446, COLDRIVER |
| G1034 | Daggerfly | Daggerfly, Evasive Panda, BRONZE HIGHLAND |
| G1035 | Winter Vivern | Winter Vivern, TA473, UAC-0114 |
| G1036 | Moonstone Sleet | Moonstone Sleet, Storm-1789 |
| G1037 | TA577 | TA577 |
| G1038 | TA578 | TA578 |
| G1039 | RedCurl | RedCurl |
| G1040 | Play | Play |
| G1041 | Sea Turtle | Sea Turtle, Teal Kurma, Marbled Dust, Cosmic Wolf, SILICON |
| G1042 | RedEcho | RedEcho |
| G1043 | BlackByte | BlackByte, Hecamede |
| G1044 | APT42 | APT42 |
| G1045 | Salt Typhoon | Salt Typhoon |
| G1046 | Storm-1811 | Storm-1811 |
| G1047 | Velvet Ant | Velvet Ant |
| G1048 | UNC3886 | UNC3886 |
| G1049 | AppleJeus | AppleJeus, Gleaming Pisces, Citrine Sleet, UNC1720, UNC4736 |
| G1050 | Water Galura | Water Galura, GOLD FEATHER |
| G1051 | Medusa Group | Medusa Group |
| G1052 | Contagious Interview | Contagious Interview, DeceptiveDevelopment, Gwisin Gang, Tenacious Pungsan, DEV#POPPER |
| G1053 | Storm-0501 | Storm-0501 |
| G1054 | MirrorFace | MirrorFace, Earth Kasha |
| G1055 | VOID MANTICORE | VOID MANTICORE, COBALT MYSTIQUE, Handala Hack, Homeland Justice, Karma |
| G1056 | TeamPCP | TeamPCP, PCPCat, ShellForce, DeadCatx3, SHADOW-WATER-058 |
| G1057 | ShinyHunters | ShinyHunters, UNC6240, Bling Libra |

## 4. Techniques & Sub-techniques (All 697)

| ATT&CK ID | Technique Name | Type | Parent ID | Mapped Tactics |
|---|---|---|---|---|
| T1001 | Data Obfuscation | Technique | - | command-and-control |
| T1001.001 | Junk Data | Sub-technique | T1001 | command-and-control |
| T1001.002 | Steganography | Sub-technique | T1001 | command-and-control |
| T1001.003 | Protocol or Service Impersonation | Sub-technique | T1001 | command-and-control |
| T1003 | OS Credential Dumping | Technique | - | credential-access |
| T1003.001 | LSASS Memory | Sub-technique | T1003 | credential-access |
| T1003.002 | Security Account Manager | Sub-technique | T1003 | credential-access |
| T1003.003 | NTDS | Sub-technique | T1003 | credential-access |
| T1003.004 | LSA Secrets | Sub-technique | T1003 | credential-access |
| T1003.005 | Cached Domain Credentials | Sub-technique | T1003 | credential-access |
| T1003.006 | DCSync | Sub-technique | T1003 | credential-access |
| T1003.007 | Proc Filesystem | Sub-technique | T1003 | credential-access |
| T1003.008 | /etc/passwd and /etc/shadow | Sub-technique | T1003 | credential-access |
| T1005 | Data from Local System | Technique | - | collection |
| T1006 | Direct Volume Access | Technique | - | stealth |
| T1007 | System Service Discovery | Technique | - | discovery |
| T1008 | Fallback Channels | Technique | - | command-and-control |
| T1010 | Application Window Discovery | Technique | - | discovery |
| T1011 | Exfiltration Over Other Network Medium | Technique | - | exfiltration |
| T1011.001 | Exfiltration Over Bluetooth | Sub-technique | T1011 | exfiltration |
| T1012 | Query Registry | Technique | - | discovery |
| T1014 | Rootkit | Technique | - | stealth |
| T1016 | System Network Configuration Discovery | Technique | - | discovery |
| T1016.001 | Internet Connection Discovery | Sub-technique | T1016 | discovery |
| T1016.002 | Wi-Fi Discovery | Sub-technique | T1016 | discovery |
| T1018 | Remote System Discovery | Technique | - | discovery |
| T1020 | Automated Exfiltration | Technique | - | exfiltration |
| T1020.001 | Traffic Duplication | Sub-technique | T1020 | exfiltration |
| T1021 | Remote Services | Technique | - | lateral-movement |
| T1021.001 | Remote Desktop Protocol | Sub-technique | T1021 | lateral-movement |
| T1021.002 | SMB/Windows Admin Shares | Sub-technique | T1021 | lateral-movement |
| T1021.003 | Distributed Component Object Model | Sub-technique | T1021 | lateral-movement |
| T1021.004 | SSH | Sub-technique | T1021 | lateral-movement |
| T1021.005 | VNC | Sub-technique | T1021 | lateral-movement |
| T1021.006 | Windows Remote Management | Sub-technique | T1021 | lateral-movement |
| T1021.007 | Cloud Services | Sub-technique | T1021 | lateral-movement |
| T1021.008 | Direct Cloud VM Connections | Sub-technique | T1021 | lateral-movement |
| T1025 | Data from Removable Media | Technique | - | collection |
| T1027 | Obfuscated Files or Information | Technique | - | stealth |
| T1027.001 | Binary Padding | Sub-technique | T1027 | stealth |
| T1027.002 | Software Packing | Sub-technique | T1027 | stealth |
| T1027.003 | Steganography | Sub-technique | T1027 | stealth |
| T1027.004 | Compile After Delivery | Sub-technique | T1027 | stealth |
| T1027.005 | Indicator Removal from Tools | Sub-technique | T1027 | stealth |
| T1027.006 | HTML Smuggling | Sub-technique | T1027 | stealth |
| T1027.007 | Dynamic API Resolution | Sub-technique | T1027 | stealth |
| T1027.008 | Stripped Payloads | Sub-technique | T1027 | stealth |
| T1027.009 | Embedded Payloads | Sub-technique | T1027 | stealth |
| T1027.010 | Command Obfuscation | Sub-technique | T1027 | stealth |
| T1027.011 | Fileless Storage | Sub-technique | T1027 | stealth |
| T1027.012 | LNK Icon Smuggling | Sub-technique | T1027 | stealth |
| T1027.013 | Encrypted/Encoded File | Sub-technique | T1027 | stealth |
| T1027.014 | Polymorphic Code | Sub-technique | T1027 | stealth |
| T1027.015 | Compression | Sub-technique | T1027 | stealth |
| T1027.016 | Junk Code Insertion | Sub-technique | T1027 | stealth |
| T1027.017 | SVG Smuggling | Sub-technique | T1027 | stealth |
| T1027.018 | Invisible Unicode | Sub-technique | T1027 | stealth |
| T1029 | Scheduled Transfer | Technique | - | exfiltration |
| T1030 | Data Transfer Size Limits | Technique | - | exfiltration |
| T1033 | System Owner/User Discovery | Technique | - | discovery |
| T1036 | Masquerading | Technique | - | stealth |
| T1036.001 | Invalid Code Signature | Sub-technique | T1036 | stealth |
| T1036.002 | Right-to-Left Override | Sub-technique | T1036 | stealth |
| T1036.003 | Rename Legitimate Utilities | Sub-technique | T1036 | stealth |
| T1036.004 | Masquerade Task or Service | Sub-technique | T1036 | stealth |
| T1036.005 | Match Legitimate Resource Name or Location | Sub-technique | T1036 | stealth |
| T1036.006 | Space after Filename | Sub-technique | T1036 | stealth |
| T1036.007 | Double File Extension | Sub-technique | T1036 | stealth |
| T1036.008 | Masquerade File Type | Sub-technique | T1036 | stealth |
| T1036.009 | Break Process Trees | Sub-technique | T1036 | stealth |
| T1036.010 | Masquerade Account Name | Sub-technique | T1036 | stealth |
| T1036.011 | Overwrite Process Arguments | Sub-technique | T1036 | stealth |
| T1036.012 | Browser Fingerprint | Sub-technique | T1036 | stealth |
| T1037 | Boot or Logon Initialization Scripts | Technique | - | persistence, privilege-escalation |
| T1037.001 | Logon Script (Windows) | Sub-technique | T1037 | persistence, privilege-escalation |
| T1037.002 | Login Hook | Sub-technique | T1037 | persistence, privilege-escalation |
| T1037.003 | Network Logon Script | Sub-technique | T1037 | persistence, privilege-escalation |
| T1037.004 | RC Scripts | Sub-technique | T1037 | persistence, privilege-escalation |
| T1037.005 | Startup Items | Sub-technique | T1037 | persistence, privilege-escalation |
| T1039 | Data from Network Shared Drive | Technique | - | collection |
| T1040 | Network Sniffing | Technique | - | credential-access, discovery |
| T1041 | Exfiltration Over C2 Channel | Technique | - | exfiltration |
| T1046 | Network Service Discovery | Technique | - | discovery |
| T1047 | Windows Management Instrumentation | Technique | - | execution |
| T1048 | Exfiltration Over Alternative Protocol | Technique | - | exfiltration |
| T1048.001 | Exfiltration Over Symmetric Encrypted Non-C2 Protocol | Sub-technique | T1048 | exfiltration |
| T1048.002 | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | Sub-technique | T1048 | exfiltration |
| T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | Sub-technique | T1048 | exfiltration |
| T1049 | System Network Connections Discovery | Technique | - | discovery |
| T1052 | Exfiltration Over Physical Medium | Technique | - | exfiltration |
| T1052.001 | Exfiltration over USB | Sub-technique | T1052 | exfiltration |
| T1053 | Scheduled Task/Job | Technique | - | execution, persistence, privilege-escalation |
| T1053.002 | At | Sub-technique | T1053 | execution, persistence, privilege-escalation |
| T1053.003 | Cron | Sub-technique | T1053 | execution, persistence, privilege-escalation |
| T1053.005 | Scheduled Task | Sub-technique | T1053 | execution, persistence, privilege-escalation |
| T1053.006 | Systemd Timers | Sub-technique | T1053 | execution, persistence, privilege-escalation |
| T1053.007 | Container Orchestration Job | Sub-technique | T1053 | execution, persistence, privilege-escalation |
| T1055 | Process Injection | Technique | - | stealth, privilege-escalation |
| T1055.001 | Dynamic-link Library Injection | Sub-technique | T1055 | stealth, privilege-escalation |
| T1055.002 | Portable Executable Injection | Sub-technique | T1055 | stealth, privilege-escalation |
| T1055.003 | Thread Execution Hijacking | Sub-technique | T1055 | stealth, privilege-escalation |
| T1055.004 | Asynchronous Procedure Call | Sub-technique | T1055 | stealth, privilege-escalation |
| T1055.005 | Thread Local Storage | Sub-technique | T1055 | stealth, privilege-escalation |
| T1055.008 | Ptrace System Calls | Sub-technique | T1055 | stealth, privilege-escalation |
| T1055.009 | Proc Memory | Sub-technique | T1055 | stealth, privilege-escalation |
| T1055.011 | Extra Window Memory Injection | Sub-technique | T1055 | stealth, privilege-escalation |
| T1055.012 | Process Hollowing | Sub-technique | T1055 | stealth, privilege-escalation |
| T1055.013 | Process Doppelgänging | Sub-technique | T1055 | stealth, privilege-escalation |
| T1055.014 | VDSO Hijacking | Sub-technique | T1055 | stealth, privilege-escalation |
| T1055.015 | ListPlanting | Sub-technique | T1055 | stealth, privilege-escalation |
| T1056 | Input Capture | Technique | - | collection, credential-access |
| T1056.001 | Keylogging | Sub-technique | T1056 | collection, credential-access |
| T1056.002 | GUI Input Capture | Sub-technique | T1056 | collection, credential-access |
| T1056.003 | Web Portal Capture | Sub-technique | T1056 | collection, credential-access |
| T1056.004 | Credential API Hooking | Sub-technique | T1056 | collection, credential-access |
| T1057 | Process Discovery | Technique | - | discovery |
| T1059 | Command and Scripting Interpreter | Technique | - | execution |
| T1059.001 | PowerShell | Sub-technique | T1059 | execution |
| T1059.002 | AppleScript | Sub-technique | T1059 | execution |
| T1059.003 | Windows Command Shell | Sub-technique | T1059 | execution |
| T1059.004 | Unix Shell | Sub-technique | T1059 | execution |
| T1059.005 | Visual Basic | Sub-technique | T1059 | execution |
| T1059.006 | Python | Sub-technique | T1059 | execution |
| T1059.007 | JavaScript | Sub-technique | T1059 | execution |
| T1059.008 | Network Device CLI | Sub-technique | T1059 | execution |
| T1059.009 | Cloud API | Sub-technique | T1059 | execution |
| T1059.010 | AutoHotKey & AutoIT | Sub-technique | T1059 | execution |
| T1059.011 | Lua | Sub-technique | T1059 | execution |
| T1059.012 | Hypervisor CLI | Sub-technique | T1059 | execution |
| T1059.013 | Container CLI/API | Sub-technique | T1059 | execution |
| T1068 | Exploitation for Privilege Escalation | Technique | - | privilege-escalation |
| T1069 | Permission Groups Discovery | Technique | - | discovery |
| T1069.001 | Local Groups | Sub-technique | T1069 | discovery |
| T1069.002 | Domain Groups | Sub-technique | T1069 | discovery |
| T1069.003 | Cloud Groups | Sub-technique | T1069 | discovery |
| T1070 | Indicator Removal | Technique | - | stealth |
| T1070.003 | Clear Command History | Sub-technique | T1070 | stealth |
| T1070.004 | File Deletion | Sub-technique | T1070 | stealth |
| T1070.005 | Network Share Connection Removal | Sub-technique | T1070 | stealth |
| T1070.006 | Timestomp | Sub-technique | T1070 | stealth |
| T1070.007 | Clear Network Connection History and Configurations | Sub-technique | T1070 | stealth |
| T1070.008 | Clear Mailbox Data | Sub-technique | T1070 | stealth |
| T1070.009 | Clear Persistence | Sub-technique | T1070 | stealth |
| T1070.010 | Relocate Malware | Sub-technique | T1070 | stealth |
| T1071 | Application Layer Protocol | Technique | - | command-and-control |
| T1071.001 | Web Protocols | Sub-technique | T1071 | command-and-control |
| T1071.002 | File Transfer Protocols | Sub-technique | T1071 | command-and-control |
| T1071.003 | Mail Protocols | Sub-technique | T1071 | command-and-control |
| T1071.004 | DNS | Sub-technique | T1071 | command-and-control |
| T1071.005 | Publish/Subscribe Protocols | Sub-technique | T1071 | command-and-control |
| T1072 | Software Deployment Tools | Technique | - | execution, lateral-movement |
| T1074 | Data Staged | Technique | - | collection |
| T1074.001 | Local Data Staging | Sub-technique | T1074 | collection |
| T1074.002 | Remote Data Staging | Sub-technique | T1074 | collection |
| T1078 | Valid Accounts | Technique | - | stealth, persistence, privilege-escalation, initial-access |
| T1078.001 | Default Accounts | Sub-technique | T1078 | stealth, persistence, privilege-escalation, initial-access |
| T1078.002 | Domain Accounts | Sub-technique | T1078 | stealth, persistence, privilege-escalation, initial-access |
| T1078.003 | Local Accounts | Sub-technique | T1078 | stealth, persistence, privilege-escalation, initial-access |
| T1078.004 | Cloud Accounts | Sub-technique | T1078 | stealth, persistence, privilege-escalation, initial-access |
| T1080 | Taint Shared Content | Technique | - | lateral-movement |
| T1082 | System Information Discovery | Technique | - | discovery |
| T1083 | File and Directory Discovery | Technique | - | discovery |
| T1087 | Account Discovery | Technique | - | discovery |
| T1087.001 | Local Account | Sub-technique | T1087 | discovery |
| T1087.002 | Domain Account | Sub-technique | T1087 | discovery |
| T1087.003 | Email Account | Sub-technique | T1087 | discovery |
| T1087.004 | Cloud Account | Sub-technique | T1087 | discovery |
| T1090 | Proxy | Technique | - | command-and-control |
| T1090.001 | Internal Proxy | Sub-technique | T1090 | command-and-control |
| T1090.002 | External Proxy | Sub-technique | T1090 | command-and-control |
| T1090.003 | Multi-hop Proxy | Sub-technique | T1090 | command-and-control |
| T1090.004 | Domain Fronting | Sub-technique | T1090 | command-and-control |
| T1091 | Replication Through Removable Media | Technique | - | lateral-movement, initial-access |
| T1092 | Communication Through Removable Media | Technique | - | command-and-control |
| T1095 | Non-Application Layer Protocol | Technique | - | command-and-control |
| T1098 | Account Manipulation | Technique | - | persistence, privilege-escalation |
| T1098.001 | Additional Cloud Credentials | Sub-technique | T1098 | persistence, privilege-escalation |
| T1098.002 | Additional Email Delegate Permissions | Sub-technique | T1098 | persistence, privilege-escalation |
| T1098.003 | Additional Cloud Roles | Sub-technique | T1098 | persistence, privilege-escalation |
| T1098.004 | SSH Authorized Keys | Sub-technique | T1098 | persistence, privilege-escalation |
| T1098.005 | Device Registration | Sub-technique | T1098 | persistence, privilege-escalation |
| T1098.006 | Additional Container Cluster Roles | Sub-technique | T1098 | persistence, privilege-escalation |
| T1098.007 | Additional Local or Domain Groups | Sub-technique | T1098 | persistence, privilege-escalation |
| T1102 | Web Service | Technique | - | command-and-control |
| T1102.001 | Dead Drop Resolver | Sub-technique | T1102 | command-and-control |
| T1102.002 | Bidirectional Communication | Sub-technique | T1102 | command-and-control |
| T1102.003 | One-Way Communication | Sub-technique | T1102 | command-and-control |
| T1104 | Multi-Stage Channels | Technique | - | command-and-control |
| T1105 | Ingress Tool Transfer | Technique | - | command-and-control |
| T1106 | Native API | Technique | - | execution |
| T1110 | Brute Force | Technique | - | credential-access |
| T1110.001 | Password Guessing | Sub-technique | T1110 | credential-access |
| T1110.002 | Password Cracking | Sub-technique | T1110 | credential-access |
| T1110.003 | Password Spraying | Sub-technique | T1110 | credential-access |
| T1110.004 | Credential Stuffing | Sub-technique | T1110 | credential-access |
| T1111 | Multi-Factor Authentication Interception | Technique | - | credential-access |
| T1112 | Modify Registry | Technique | - | defense-impairment, persistence |
| T1113 | Screen Capture | Technique | - | collection |
| T1114 | Email Collection | Technique | - | collection |
| T1114.001 | Local Email Collection | Sub-technique | T1114 | collection |
| T1114.002 | Remote Email Collection | Sub-technique | T1114 | collection |
| T1114.003 | Email Forwarding Rule | Sub-technique | T1114 | collection |
| T1115 | Clipboard Data | Technique | - | collection |
| T1119 | Automated Collection | Technique | - | collection |
| T1120 | Peripheral Device Discovery | Technique | - | discovery |
| T1123 | Audio Capture | Technique | - | collection |
| T1124 | System Time Discovery | Technique | - | discovery |
| T1125 | Video Capture | Technique | - | collection |
| T1127 | Trusted Developer Utilities Proxy Execution | Technique | - | stealth, execution |
| T1127.001 | MSBuild | Sub-technique | T1127 | stealth, execution |
| T1127.002 | ClickOnce | Sub-technique | T1127 | stealth, execution |
| T1127.003 | JamPlus | Sub-technique | T1127 | stealth, execution |
| T1129 | Shared Modules | Technique | - | execution |
| T1132 | Data Encoding | Technique | - | command-and-control |
| T1132.001 | Standard Encoding | Sub-technique | T1132 | command-and-control |
| T1132.002 | Non-Standard Encoding | Sub-technique | T1132 | command-and-control |
| T1133 | External Remote Services | Technique | - | persistence, initial-access |
| T1134 | Access Token Manipulation | Technique | - | stealth, privilege-escalation |
| T1134.001 | Token Impersonation/Theft | Sub-technique | T1134 | stealth, privilege-escalation |
| T1134.002 | Create Process with Token | Sub-technique | T1134 | stealth, privilege-escalation |
| T1134.003 | Make and Impersonate Token | Sub-technique | T1134 | stealth, privilege-escalation |
| T1134.004 | Parent PID Spoofing | Sub-technique | T1134 | stealth, privilege-escalation |
| T1134.005 | SID-History Injection | Sub-technique | T1134 | stealth, privilege-escalation |
| T1135 | Network Share Discovery | Technique | - | discovery |
| T1136 | Create Account | Technique | - | persistence |
| T1136.001 | Local Account | Sub-technique | T1136 | persistence |
| T1136.002 | Domain Account | Sub-technique | T1136 | persistence |
| T1136.003 | Cloud Account | Sub-technique | T1136 | persistence |
| T1137 | Office Application Startup | Technique | - | persistence |
| T1137.001 | Office Template Macros | Sub-technique | T1137 | persistence |
| T1137.002 | Office Test | Sub-technique | T1137 | persistence |
| T1137.003 | Outlook Forms | Sub-technique | T1137 | persistence |
| T1137.004 | Outlook Home Page | Sub-technique | T1137 | persistence |
| T1137.005 | Outlook Rules | Sub-technique | T1137 | persistence |
| T1137.006 | Add-ins | Sub-technique | T1137 | persistence |
| T1140 | Deobfuscate/Decode Files or Information | Technique | - | stealth |
| T1176 | Software Extensions | Technique | - | persistence |
| T1176.001 | Browser Extensions | Sub-technique | T1176 | persistence |
| T1176.002 | IDE Extensions | Sub-technique | T1176 | persistence |
| T1185 | Browser Session Hijacking | Technique | - | collection |
| T1187 | Forced Authentication | Technique | - | credential-access |
| T1189 | Drive-by Compromise | Technique | - | initial-access |
| T1190 | Exploit Public-Facing Application | Technique | - | initial-access |
| T1195 | Supply Chain Compromise | Technique | - | initial-access |
| T1195.001 | Compromise Software Dependencies and Development Tools | Sub-technique | T1195 | initial-access |
| T1195.002 | Compromise Software Supply Chain | Sub-technique | T1195 | initial-access |
| T1195.003 | Compromise Hardware Supply Chain | Sub-technique | T1195 | initial-access |
| T1197 | BITS Jobs | Technique | - | stealth, persistence, execution |
| T1199 | Trusted Relationship | Technique | - | initial-access |
| T1200 | Hardware Additions | Technique | - | initial-access |
| T1201 | Password Policy Discovery | Technique | - | discovery |
| T1202 | Indirect Command Execution | Technique | - | stealth |
| T1203 | Exploitation for Client Execution | Technique | - | execution |
| T1204 | User Execution | Technique | - | execution |
| T1204.001 | Malicious Link | Sub-technique | T1204 | execution |
| T1204.002 | Malicious File | Sub-technique | T1204 | execution |
| T1204.003 | Malicious Image | Sub-technique | T1204 | execution |
| T1204.004 | Malicious Copy and Paste | Sub-technique | T1204 | execution |
| T1204.005 | Malicious Library | Sub-technique | T1204 | execution |
| T1205 | Traffic Signaling | Technique | - | stealth, persistence, command-and-control |
| T1205.001 | Port Knocking | Sub-technique | T1205 | stealth, persistence, command-and-control |
| T1205.002 | Socket Filters | Sub-technique | T1205 | stealth, persistence, command-and-control |
| T1207 | Rogue Domain Controller | Technique | - | defense-impairment |
| T1210 | Exploitation of Remote Services | Technique | - | lateral-movement |
| T1211 | Exploitation for Stealth | Technique | - | stealth |
| T1212 | Exploitation for Credential Access | Technique | - | credential-access |
| T1213 | Data from Information Repositories | Technique | - | collection |
| T1213.001 | Confluence | Sub-technique | T1213 | collection |
| T1213.002 | Sharepoint | Sub-technique | T1213 | collection |
| T1213.003 | Code Repositories | Sub-technique | T1213 | collection |
| T1213.004 | Customer Relationship Management Software | Sub-technique | T1213 | collection |
| T1213.005 | Messaging Applications | Sub-technique | T1213 | collection |
| T1213.006 | Databases | Sub-technique | T1213 | collection |
| T1216 | System Script Proxy Execution | Technique | - | stealth |
| T1216.001 | PubPrn | Sub-technique | T1216 | stealth |
| T1216.002 | SyncAppvPublishingServer | Sub-technique | T1216 | stealth |
| T1217 | Browser Information Discovery | Technique | - | discovery |
| T1218 | System Binary Proxy Execution | Technique | - | stealth |
| T1218.001 | Compiled HTML File | Sub-technique | T1218 | stealth |
| T1218.002 | Control Panel | Sub-technique | T1218 | stealth |
| T1218.003 | CMSTP | Sub-technique | T1218 | stealth |
| T1218.004 | InstallUtil | Sub-technique | T1218 | stealth |
| T1218.005 | Mshta | Sub-technique | T1218 | stealth |
| T1218.007 | Msiexec | Sub-technique | T1218 | stealth |
| T1218.008 | Odbcconf | Sub-technique | T1218 | stealth |
| T1218.009 | Regsvcs/Regasm | Sub-technique | T1218 | stealth |
| T1218.010 | Regsvr32 | Sub-technique | T1218 | stealth |
| T1218.011 | Rundll32 | Sub-technique | T1218 | stealth |
| T1218.012 | Verclsid | Sub-technique | T1218 | stealth |
| T1218.013 | Mavinject | Sub-technique | T1218 | stealth |
| T1218.014 | MMC | Sub-technique | T1218 | stealth |
| T1218.015 | Electron Applications | Sub-technique | T1218 | stealth |
| T1219 | Remote Access Tools | Technique | - | command-and-control |
| T1219.001 | IDE Tunneling | Sub-technique | T1219 | command-and-control |
| T1219.002 | Remote Desktop Software | Sub-technique | T1219 | command-and-control |
| T1219.003 | Remote Access Hardware | Sub-technique | T1219 | command-and-control |
| T1220 | XSL Script Processing | Technique | - | stealth |
| T1221 | Template Injection | Technique | - | stealth |
| T1222 | File and Directory Permissions Modification | Technique | - | defense-impairment |
| T1222.001 | Windows Permissions | Sub-technique | T1222 | defense-impairment |
| T1222.002 | Linux and Mac Permissions | Sub-technique | T1222 | defense-impairment |
| T1480 | Execution Guardrails | Technique | - | stealth |
| T1480.001 | Environmental Keying | Sub-technique | T1480 | stealth |
| T1480.002 | Mutual Exclusion | Sub-technique | T1480 | stealth |
| T1482 | Domain Trust Discovery | Technique | - | discovery |
| T1484 | Domain or Tenant Policy Modification | Technique | - | defense-impairment, privilege-escalation |
| T1484.001 | Group Policy Modification | Sub-technique | T1484 | defense-impairment, privilege-escalation |
| T1484.002 | Trust Modification | Sub-technique | T1484 | defense-impairment, privilege-escalation |
| T1485 | Data Destruction | Technique | - | impact |
| T1485.001 | Lifecycle-Triggered Deletion | Sub-technique | T1485 | impact |
| T1486 | Data Encrypted for Impact | Technique | - | impact |
| T1489 | Service Stop | Technique | - | impact |
| T1490 | Inhibit System Recovery | Technique | - | impact |
| T1491 | Defacement | Technique | - | impact |
| T1491.001 | Internal Defacement | Sub-technique | T1491 | impact |
| T1491.002 | External Defacement | Sub-technique | T1491 | impact |
| T1495 | Firmware Corruption | Technique | - | impact |
| T1496 | Resource Hijacking | Technique | - | impact |
| T1496.001 | Compute Hijacking | Sub-technique | T1496 | impact |
| T1496.002 | Bandwidth Hijacking | Sub-technique | T1496 | impact |
| T1496.003 | SMS Pumping | Sub-technique | T1496 | impact |
| T1496.004 | Cloud Service Hijacking | Sub-technique | T1496 | impact |
| T1497 | Virtualization/Sandbox Evasion | Technique | - | stealth, discovery |
| T1497.001 | System Checks | Sub-technique | T1497 | stealth, discovery |
| T1497.002 | User Activity Based Checks | Sub-technique | T1497 | stealth, discovery |
| T1497.003 | Time Based Checks | Sub-technique | T1497 | stealth, discovery |
| T1498 | Network Denial of Service | Technique | - | impact |
| T1498.001 | Direct Network Flood | Sub-technique | T1498 | impact |
| T1498.002 | Reflection Amplification | Sub-technique | T1498 | impact |
| T1499 | Endpoint Denial of Service | Technique | - | impact |
| T1499.001 | OS Exhaustion Flood | Sub-technique | T1499 | impact |
| T1499.002 | Service Exhaustion Flood | Sub-technique | T1499 | impact |
| T1499.003 | Application Exhaustion Flood | Sub-technique | T1499 | impact |
| T1499.004 | Application or System Exploitation | Sub-technique | T1499 | impact |
| T1505 | Server Software Component | Technique | - | persistence |
| T1505.001 | SQL Stored Procedures | Sub-technique | T1505 | persistence |
| T1505.002 | Transport Agent | Sub-technique | T1505 | persistence |
| T1505.003 | Web Shell | Sub-technique | T1505 | persistence |
| T1505.004 | IIS Components | Sub-technique | T1505 | persistence |
| T1505.005 | Terminal Services DLL | Sub-technique | T1505 | persistence |
| T1505.006 | vSphere Installation Bundles | Sub-technique | T1505 | persistence |
| T1518 | Software Discovery | Technique | - | discovery |
| T1518.001 | Security Software Discovery | Sub-technique | T1518 | discovery |
| T1518.002 | Backup Software Discovery | Sub-technique | T1518 | discovery |
| T1525 | Implant Internal Image | Technique | - | persistence |
| T1526 | Cloud Service Discovery | Technique | - | discovery |
| T1528 | Steal Application Access Token | Technique | - | credential-access |
| T1529 | System Shutdown/Reboot | Technique | - | impact |
| T1530 | Data from Cloud Storage | Technique | - | collection |
| T1531 | Account Access Removal | Technique | - | impact |
| T1534 | Internal Spearphishing | Technique | - | lateral-movement |
| T1535 | Unused/Unsupported Cloud Regions | Technique | - | stealth |
| T1537 | Transfer Data to Cloud Account | Technique | - | exfiltration |
| T1538 | Cloud Service Dashboard | Technique | - | discovery |
| T1539 | Steal Web Session Cookie | Technique | - | credential-access |
| T1542 | Pre-OS Boot | Technique | - | stealth, persistence |
| T1542.001 | System Firmware | Sub-technique | T1542 | stealth, persistence |
| T1542.002 | Component Firmware | Sub-technique | T1542 | stealth, persistence |
| T1542.003 | Bootkit | Sub-technique | T1542 | stealth, persistence |
| T1542.004 | ROMMONkit | Sub-technique | T1542 | stealth, persistence |
| T1542.005 | TFTP Boot | Sub-technique | T1542 | stealth, persistence |
| T1543 | Create or Modify System Process | Technique | - | persistence, privilege-escalation |
| T1543.001 | Launch Agent | Sub-technique | T1543 | persistence, privilege-escalation |
| T1543.002 | Systemd Service | Sub-technique | T1543 | persistence, privilege-escalation |
| T1543.003 | Windows Service | Sub-technique | T1543 | persistence, privilege-escalation |
| T1543.004 | Launch Daemon | Sub-technique | T1543 | persistence, privilege-escalation |
| T1543.005 | Container Service | Sub-technique | T1543 | persistence, privilege-escalation |
| T1546 | Event Triggered Execution | Technique | - | privilege-escalation, persistence |
| T1546.001 | Change Default File Association | Sub-technique | T1546 | privilege-escalation, persistence |
| T1546.002 | Screensaver | Sub-technique | T1546 | privilege-escalation, persistence |
| T1546.003 | Windows Management Instrumentation Event Subscription | Sub-technique | T1546 | privilege-escalation, persistence |
| T1546.004 | Unix Shell Configuration Modification | Sub-technique | T1546 | privilege-escalation, persistence |
| T1546.005 | Trap | Sub-technique | T1546 | privilege-escalation, persistence |
| T1546.006 | LC_LOAD_DYLIB Addition | Sub-technique | T1546 | privilege-escalation, persistence |
| T1546.007 | Netsh Helper DLL | Sub-technique | T1546 | privilege-escalation, persistence |
| T1546.008 | Accessibility Features | Sub-technique | T1546 | privilege-escalation, persistence |
| T1546.009 | AppCert DLLs | Sub-technique | T1546 | privilege-escalation, persistence |
| T1546.010 | AppInit DLLs | Sub-technique | T1546 | privilege-escalation, persistence |
| T1546.011 | Application Shimming | Sub-technique | T1546 | privilege-escalation, persistence |
| T1546.012 | Image File Execution Options Injection | Sub-technique | T1546 | privilege-escalation, persistence |
| T1546.013 | PowerShell Profile | Sub-technique | T1546 | privilege-escalation, persistence |
| T1546.014 | Emond | Sub-technique | T1546 | privilege-escalation, persistence |
| T1546.015 | Component Object Model Hijacking | Sub-technique | T1546 | privilege-escalation, persistence |
| T1546.016 | Installer Packages | Sub-technique | T1546 | privilege-escalation, persistence |
| T1546.017 | Udev Rules | Sub-technique | T1546 | persistence, privilege-escalation |
| T1546.018 | Python Startup Hooks | Sub-technique | T1546 | persistence, privilege-escalation |
| T1547 | Boot or Logon Autostart Execution | Technique | - | persistence, privilege-escalation |
| T1547.001 | Registry Run Keys / Startup Folder | Sub-technique | T1547 | persistence, privilege-escalation |
| T1547.002 | Authentication Package | Sub-technique | T1547 | persistence, privilege-escalation |
| T1547.003 | Time Providers | Sub-technique | T1547 | persistence, privilege-escalation |
| T1547.004 | Winlogon Helper DLL | Sub-technique | T1547 | persistence, privilege-escalation |
| T1547.005 | Security Support Provider | Sub-technique | T1547 | persistence, privilege-escalation |
| T1547.006 | Kernel Modules and Extensions | Sub-technique | T1547 | persistence, privilege-escalation |
| T1547.007 | Re-opened Applications | Sub-technique | T1547 | persistence, privilege-escalation |
| T1547.008 | LSASS Driver | Sub-technique | T1547 | persistence, privilege-escalation |
| T1547.009 | Shortcut Modification | Sub-technique | T1547 | persistence, privilege-escalation |
| T1547.010 | Port Monitors | Sub-technique | T1547 | persistence, privilege-escalation |
| T1547.012 | Print Processors | Sub-technique | T1547 | persistence, privilege-escalation |
| T1547.013 | XDG Autostart Entries | Sub-technique | T1547 | persistence, privilege-escalation |
| T1547.014 | Active Setup | Sub-technique | T1547 | persistence, privilege-escalation |
| T1547.015 | Login Items | Sub-technique | T1547 | persistence, privilege-escalation |
| T1548 | Abuse Elevation Control Mechanism | Technique | - | privilege-escalation |
| T1548.001 | Setuid and Setgid | Sub-technique | T1548 | privilege-escalation |
| T1548.002 | Bypass User Account Control | Sub-technique | T1548 | privilege-escalation |
| T1548.003 | Sudo and Sudo Caching | Sub-technique | T1548 | privilege-escalation |
| T1548.004 | Elevated Execution with Prompt | Sub-technique | T1548 | privilege-escalation |
| T1548.005 | Temporary Elevated Cloud Access | Sub-technique | T1548 | privilege-escalation |
| T1548.006 | TCC Manipulation | Sub-technique | T1548 | privilege-escalation |
| T1550 | Use Alternate Authentication Material | Technique | - | lateral-movement |
| T1550.001 | Application Access Token | Sub-technique | T1550 | lateral-movement |
| T1550.002 | Pass the Hash | Sub-technique | T1550 | lateral-movement |
| T1550.003 | Pass the Ticket | Sub-technique | T1550 | lateral-movement |
| T1550.004 | Web Session Cookie | Sub-technique | T1550 | lateral-movement |
| T1552 | Unsecured Credentials | Technique | - | credential-access |
| T1552.001 | Credentials In Files | Sub-technique | T1552 | credential-access |
| T1552.002 | Credentials in Registry | Sub-technique | T1552 | credential-access |
| T1552.003 | Shell History | Sub-technique | T1552 | credential-access |
| T1552.004 | Private Keys | Sub-technique | T1552 | credential-access |
| T1552.005 | Cloud Instance Metadata API | Sub-technique | T1552 | credential-access |
| T1552.006 | Group Policy Preferences | Sub-technique | T1552 | credential-access |
| T1552.007 | Container API | Sub-technique | T1552 | credential-access |
| T1552.008 | Chat Messages | Sub-technique | T1552 | credential-access |
| T1553 | Subvert Trust Controls | Technique | - | defense-impairment |
| T1553.001 | Gatekeeper Bypass | Sub-technique | T1553 | defense-impairment |
| T1553.002 | Code Signing | Sub-technique | T1553 | defense-impairment |
| T1553.003 | SIP and Trust Provider Hijacking | Sub-technique | T1553 | defense-impairment |
| T1553.004 | Install Root Certificate | Sub-technique | T1553 | defense-impairment |
| T1553.005 | Mark-of-the-Web Bypass | Sub-technique | T1553 | defense-impairment |
| T1553.006 | Code Signing Policy Modification | Sub-technique | T1553 | defense-impairment |
| T1554 | Compromise Host Software Binary | Technique | - | persistence |
| T1555 | Credentials from Password Stores | Technique | - | credential-access |
| T1555.001 | Keychain | Sub-technique | T1555 | credential-access |
| T1555.002 | Securityd Memory | Sub-technique | T1555 | credential-access |
| T1555.003 | Credentials from Web Browsers | Sub-technique | T1555 | credential-access |
| T1555.004 | Windows Credential Manager | Sub-technique | T1555 | credential-access |
| T1555.005 | Password Managers | Sub-technique | T1555 | credential-access |
| T1555.006 | Cloud Secrets Management Stores | Sub-technique | T1555 | credential-access |
| T1556 | Modify Authentication Process | Technique | - | defense-impairment, persistence, credential-access |
| T1556.001 | Domain Controller Authentication | Sub-technique | T1556 | defense-impairment, persistence, credential-access |
| T1556.002 | Password Filter DLL | Sub-technique | T1556 | defense-impairment, persistence, credential-access |
| T1556.003 | Pluggable Authentication Modules | Sub-technique | T1556 | defense-impairment, persistence, credential-access |
| T1556.004 | Network Device Authentication | Sub-technique | T1556 | defense-impairment, persistence, credential-access |
| T1556.005 | Reversible Encryption | Sub-technique | T1556 | defense-impairment, persistence, credential-access |
| T1556.006 | Multi-Factor Authentication | Sub-technique | T1556 | defense-impairment, persistence, credential-access |
| T1556.007 | Hybrid Identity | Sub-technique | T1556 | defense-impairment, persistence, credential-access |
| T1556.008 | Network Provider DLL | Sub-technique | T1556 | defense-impairment, persistence, credential-access |
| T1556.009 | Conditional Access Policies | Sub-technique | T1556 | defense-impairment, persistence, credential-access |
| T1557 | Adversary-in-the-Middle | Technique | - | credential-access, collection |
| T1557.001 | Name Resolution Poisoning and SMB Relay | Sub-technique | T1557 | credential-access, collection |
| T1557.002 | ARP Cache Poisoning | Sub-technique | T1557 | credential-access, collection |
| T1557.003 | DHCP Spoofing | Sub-technique | T1557 | credential-access, collection |
| T1557.004 | Evil Twin | Sub-technique | T1557 | credential-access, collection |
| T1558 | Steal or Forge Kerberos Tickets | Technique | - | credential-access |
| T1558.001 | Golden Ticket | Sub-technique | T1558 | credential-access |
| T1558.002 | Silver Ticket | Sub-technique | T1558 | credential-access |
| T1558.003 | Kerberoasting | Sub-technique | T1558 | credential-access |
| T1558.004 | AS-REP Roasting | Sub-technique | T1558 | credential-access |
| T1558.005 | Ccache Files | Sub-technique | T1558 | credential-access |
| T1559 | Inter-Process Communication | Technique | - | execution |
| T1559.001 | Component Object Model | Sub-technique | T1559 | execution |
| T1559.002 | Dynamic Data Exchange | Sub-technique | T1559 | execution |
| T1559.003 | XPC Services | Sub-technique | T1559 | execution |
| T1560 | Archive Collected Data | Technique | - | collection |
| T1560.001 | Archive via Utility | Sub-technique | T1560 | collection |
| T1560.002 | Archive via Library | Sub-technique | T1560 | collection |
| T1560.003 | Archive via Custom Method | Sub-technique | T1560 | collection |
| T1561 | Disk Wipe | Technique | - | impact |
| T1561.001 | Disk Content Wipe | Sub-technique | T1561 | impact |
| T1561.002 | Disk Structure Wipe | Sub-technique | T1561 | impact |
| T1563 | Remote Service Session Hijacking | Technique | - | lateral-movement |
| T1563.001 | SSH Hijacking | Sub-technique | T1563 | lateral-movement |
| T1563.002 | RDP Hijacking | Sub-technique | T1563 | lateral-movement |
| T1564 | Hide Artifacts | Technique | - | stealth |
| T1564.001 | Hidden Files and Directories | Sub-technique | T1564 | stealth |
| T1564.002 | Hidden Users | Sub-technique | T1564 | stealth |
| T1564.003 | Hidden Window | Sub-technique | T1564 | stealth |
| T1564.004 | NTFS File Attributes | Sub-technique | T1564 | stealth |
| T1564.005 | Hidden File System | Sub-technique | T1564 | stealth |
| T1564.006 | Run Virtual Instance | Sub-technique | T1564 | stealth |
| T1564.007 | VBA Stomping | Sub-technique | T1564 | stealth |
| T1564.008 | Email Hiding Rules | Sub-technique | T1564 | stealth |
| T1564.009 | Resource Forking | Sub-technique | T1564 | stealth |
| T1564.010 | Process Argument Spoofing | Sub-technique | T1564 | stealth |
| T1564.011 | Ignore Process Interrupts | Sub-technique | T1564 | stealth |
| T1564.012 | File/Path Exclusions | Sub-technique | T1564 | stealth |
| T1564.013 | Bind Mounts | Sub-technique | T1564 | stealth |
| T1564.014 | Extended Attributes | Sub-technique | T1564 | stealth |
| T1565 | Data Manipulation | Technique | - | impact |
| T1565.001 | Stored Data Manipulation | Sub-technique | T1565 | impact |
| T1565.002 | Transmitted Data Manipulation | Sub-technique | T1565 | impact |
| T1565.003 | Runtime Data Manipulation | Sub-technique | T1565 | impact |
| T1566 | Phishing | Technique | - | initial-access |
| T1566.001 | Spearphishing Attachment | Sub-technique | T1566 | initial-access |
| T1566.002 | Spearphishing Link | Sub-technique | T1566 | initial-access |
| T1566.003 | Spearphishing via Service | Sub-technique | T1566 | initial-access |
| T1566.004 | Spearphishing Voice | Sub-technique | T1566 | initial-access |
| T1567 | Exfiltration Over Web Service | Technique | - | exfiltration |
| T1567.001 | Exfiltration to Code Repository | Sub-technique | T1567 | exfiltration |
| T1567.002 | Exfiltration to Cloud Storage | Sub-technique | T1567 | exfiltration |
| T1567.003 | Exfiltration to Text Storage Sites | Sub-technique | T1567 | exfiltration |
| T1567.004 | Exfiltration Over Webhook | Sub-technique | T1567 | exfiltration |
| T1568 | Dynamic Resolution | Technique | - | command-and-control |
| T1568.001 | Fast Flux DNS | Sub-technique | T1568 | command-and-control |
| T1568.002 | Domain Generation Algorithms | Sub-technique | T1568 | command-and-control |
| T1568.003 | DNS Calculation | Sub-technique | T1568 | command-and-control |
| T1569 | System Services | Technique | - | execution |
| T1569.001 | Launchctl | Sub-technique | T1569 | execution |
| T1569.002 | Service Execution | Sub-technique | T1569 | execution |
| T1569.003 | Systemctl | Sub-technique | T1569 | execution |
| T1570 | Lateral Tool Transfer | Technique | - | lateral-movement |
| T1571 | Non-Standard Port | Technique | - | command-and-control |
| T1572 | Protocol Tunneling | Technique | - | command-and-control |
| T1573 | Encrypted Channel | Technique | - | command-and-control |
| T1573.001 | Symmetric Cryptography | Sub-technique | T1573 | command-and-control |
| T1573.002 | Asymmetric Cryptography | Sub-technique | T1573 | command-and-control |
| T1574 | Hijack Execution Flow | Technique | - | stealth, execution |
| T1574.001 | DLL | Sub-technique | T1574 | stealth, execution |
| T1574.004 | Dylib Hijacking | Sub-technique | T1574 | stealth, execution |
| T1574.005 | Executable Installer File Permissions Weakness | Sub-technique | T1574 | stealth, execution |
| T1574.006 | Dynamic Linker Hijacking | Sub-technique | T1574 | stealth, execution |
| T1574.007 | Path Interception by PATH Environment Variable | Sub-technique | T1574 | stealth, execution |
| T1574.008 | Path Interception by Search Order Hijacking | Sub-technique | T1574 | stealth, execution |
| T1574.009 | Path Interception by Unquoted Path | Sub-technique | T1574 | stealth, execution |
| T1574.010 | Services File Permissions Weakness | Sub-technique | T1574 | stealth, execution |
| T1574.011 | Services Registry Permissions Weakness | Sub-technique | T1574 | stealth, execution |
| T1574.012 | COR_PROFILER | Sub-technique | T1574 | stealth, execution |
| T1574.013 | KernelCallbackTable | Sub-technique | T1574 | stealth, execution |
| T1574.014 | AppDomainManager | Sub-technique | T1574 | stealth, execution |
| T1578 | Modify Cloud Compute Infrastructure | Technique | - | defense-impairment |
| T1578.001 | Create Snapshot | Sub-technique | T1578 | defense-impairment |
| T1578.002 | Create Cloud Instance | Sub-technique | T1578 | defense-impairment |
| T1578.003 | Delete Cloud Instance | Sub-technique | T1578 | defense-impairment |
| T1578.004 | Revert Cloud Instance | Sub-technique | T1578 | defense-impairment |
| T1578.005 | Modify Cloud Compute Configurations | Sub-technique | T1578 | defense-impairment |
| T1580 | Cloud Infrastructure Discovery | Technique | - | discovery |
| T1583 | Acquire Infrastructure | Technique | - | resource-development |
| T1583.001 | Domains | Sub-technique | T1583 | resource-development |
| T1583.002 | DNS Server | Sub-technique | T1583 | resource-development |
| T1583.003 | Virtual Private Server | Sub-technique | T1583 | resource-development |
| T1583.004 | Server | Sub-technique | T1583 | resource-development |
| T1583.005 | Botnet | Sub-technique | T1583 | resource-development |
| T1583.006 | Web Services | Sub-technique | T1583 | resource-development |
| T1583.007 | Serverless | Sub-technique | T1583 | resource-development |
| T1583.008 | Malvertising | Sub-technique | T1583 | resource-development |
| T1584 | Compromise Infrastructure | Technique | - | resource-development |
| T1584.001 | Domains | Sub-technique | T1584 | resource-development |
| T1584.002 | DNS Server | Sub-technique | T1584 | resource-development |
| T1584.003 | Virtual Private Server | Sub-technique | T1584 | resource-development |
| T1584.004 | Server | Sub-technique | T1584 | resource-development |
| T1584.005 | Botnet | Sub-technique | T1584 | resource-development |
| T1584.006 | Web Services | Sub-technique | T1584 | resource-development |
| T1584.007 | Serverless | Sub-technique | T1584 | resource-development |
| T1584.008 | Network Devices | Sub-technique | T1584 | resource-development |
| T1585 | Establish Accounts | Technique | - | resource-development |
| T1585.001 | Social Media Accounts | Sub-technique | T1585 | resource-development |
| T1585.002 | Email Accounts | Sub-technique | T1585 | resource-development |
| T1585.003 | Cloud Accounts | Sub-technique | T1585 | resource-development |
| T1586 | Compromise Accounts | Technique | - | resource-development |
| T1586.001 | Social Media Accounts | Sub-technique | T1586 | resource-development |
| T1586.002 | Email Accounts | Sub-technique | T1586 | resource-development |
| T1586.003 | Cloud Accounts | Sub-technique | T1586 | resource-development |
| T1587 | Develop Capabilities | Technique | - | resource-development |
| T1587.001 | Malware | Sub-technique | T1587 | resource-development |
| T1587.002 | Code Signing Certificates | Sub-technique | T1587 | resource-development |
| T1587.003 | Digital Certificates | Sub-technique | T1587 | resource-development |
| T1587.004 | Exploits | Sub-technique | T1587 | resource-development |
| T1588 | Obtain Capabilities | Technique | - | resource-development |
| T1588.001 | Malware | Sub-technique | T1588 | resource-development |
| T1588.002 | Tool | Sub-technique | T1588 | resource-development |
| T1588.003 | Code Signing Certificates | Sub-technique | T1588 | resource-development |
| T1588.004 | Digital Certificates | Sub-technique | T1588 | resource-development |
| T1588.005 | Exploits | Sub-technique | T1588 | resource-development |
| T1588.006 | Vulnerabilities | Sub-technique | T1588 | resource-development |
| T1588.007 | Artificial Intelligence | Sub-technique | T1588 | resource-development |
| T1589 | Gather Victim Identity Information | Technique | - | reconnaissance |
| T1589.001 | Credentials | Sub-technique | T1589 | reconnaissance |
| T1589.002 | Email Addresses | Sub-technique | T1589 | reconnaissance |
| T1589.003 | Employee Names | Sub-technique | T1589 | reconnaissance |
| T1590 | Gather Victim Network Information | Technique | - | reconnaissance |
| T1590.001 | Domain Properties | Sub-technique | T1590 | reconnaissance |
| T1590.002 | DNS | Sub-technique | T1590 | reconnaissance |
| T1590.003 | Network Trust Dependencies | Sub-technique | T1590 | reconnaissance |
| T1590.004 | Network Topology | Sub-technique | T1590 | reconnaissance |
| T1590.005 | IP Addresses | Sub-technique | T1590 | reconnaissance |
| T1590.006 | Network Security Appliances | Sub-technique | T1590 | reconnaissance |
| T1591 | Gather Victim Org Information | Technique | - | reconnaissance |
| T1591.001 | Determine Physical Locations | Sub-technique | T1591 | reconnaissance |
| T1591.002 | Business Relationships | Sub-technique | T1591 | reconnaissance |
| T1591.003 | Identify Business Tempo | Sub-technique | T1591 | reconnaissance |
| T1591.004 | Identify Roles | Sub-technique | T1591 | reconnaissance |
| T1592 | Gather Victim Host Information | Technique | - | reconnaissance |
| T1592.001 | Hardware | Sub-technique | T1592 | reconnaissance |
| T1592.002 | Software | Sub-technique | T1592 | reconnaissance |
| T1592.003 | Firmware | Sub-technique | T1592 | reconnaissance |
| T1592.004 | Client Configurations | Sub-technique | T1592 | reconnaissance |
| T1593 | Search Open Websites/Domains | Technique | - | reconnaissance |
| T1593.001 | Social Media | Sub-technique | T1593 | reconnaissance |
| T1593.002 | Search Engines | Sub-technique | T1593 | reconnaissance |
| T1593.003 | Code Repositories | Sub-technique | T1593 | reconnaissance |
| T1594 | Search Victim-Owned Websites | Technique | - | reconnaissance |
| T1595 | Active Scanning | Technique | - | reconnaissance |
| T1595.001 | Scanning IP Blocks | Sub-technique | T1595 | reconnaissance |
| T1595.002 | Vulnerability Scanning | Sub-technique | T1595 | reconnaissance |
| T1595.003 | Wordlist Scanning | Sub-technique | T1595 | reconnaissance |
| T1596 | Search Open Technical Databases | Technique | - | reconnaissance |
| T1596.001 | DNS/Passive DNS | Sub-technique | T1596 | reconnaissance |
| T1596.002 | WHOIS | Sub-technique | T1596 | reconnaissance |
| T1596.003 | Digital Certificates | Sub-technique | T1596 | reconnaissance |
| T1596.004 | CDNs | Sub-technique | T1596 | reconnaissance |
| T1596.005 | Scan Databases | Sub-technique | T1596 | reconnaissance |
| T1597 | Search Closed Sources | Technique | - | reconnaissance |
| T1597.001 | Threat Intel Vendors | Sub-technique | T1597 | reconnaissance |
| T1597.002 | Purchase Technical Data | Sub-technique | T1597 | reconnaissance |
| T1598 | Phishing for Information | Technique | - | reconnaissance |
| T1598.001 | Spearphishing Service | Sub-technique | T1598 | reconnaissance |
| T1598.002 | Spearphishing Attachment | Sub-technique | T1598 | reconnaissance |
| T1598.003 | Spearphishing Link | Sub-technique | T1598 | reconnaissance |
| T1598.004 | Spearphishing Voice | Sub-technique | T1598 | reconnaissance |
| T1599 | Network Boundary Bridging | Technique | - | defense-impairment |
| T1599.001 | Network Address Translation Traversal | Sub-technique | T1599 | defense-impairment |
| T1600 | Weaken Encryption | Technique | - | defense-impairment |
| T1600.001 | Reduce Key Space | Sub-technique | T1600 | defense-impairment |
| T1600.002 | Disable Crypto Hardware | Sub-technique | T1600 | defense-impairment |
| T1601 | Modify System Image | Technique | - | defense-impairment |
| T1601.001 | Patch System Image | Sub-technique | T1601 | defense-impairment |
| T1601.002 | Downgrade System Image | Sub-technique | T1601 | defense-impairment |
| T1602 | Data from Configuration Repository | Technique | - | collection |
| T1602.001 | SNMP (MIB Dump) | Sub-technique | T1602 | collection |
| T1602.002 | Network Device Configuration Dump | Sub-technique | T1602 | collection |
| T1606 | Forge Web Credentials | Technique | - | credential-access |
| T1606.001 | Web Cookies | Sub-technique | T1606 | credential-access |
| T1606.002 | SAML Tokens | Sub-technique | T1606 | credential-access |
| T1608 | Stage Capabilities | Technique | - | resource-development |
| T1608.001 | Upload Malware | Sub-technique | T1608 | resource-development |
| T1608.002 | Upload Tool | Sub-technique | T1608 | resource-development |
| T1608.003 | Install Digital Certificate | Sub-technique | T1608 | resource-development |
| T1608.004 | Drive-by Target | Sub-technique | T1608 | resource-development |
| T1608.005 | Link Target | Sub-technique | T1608 | resource-development |
| T1608.006 | SEO Poisoning | Sub-technique | T1608 | resource-development |
| T1609 | Container Administration Command | Technique | - | execution |
| T1610 | Deploy Container | Technique | - | execution |
| T1611 | Escape to Host | Technique | - | privilege-escalation |
| T1612 | Build Image on Host | Technique | - | stealth |
| T1613 | Container and Resource Discovery | Technique | - | discovery |
| T1614 | System Location Discovery | Technique | - | discovery |
| T1614.001 | System Language Discovery | Sub-technique | T1614 | discovery |
| T1615 | Group Policy Discovery | Technique | - | discovery |
| T1619 | Cloud Storage Object Discovery | Technique | - | discovery |
| T1620 | Reflective Code Loading | Technique | - | stealth |
| T1621 | Multi-Factor Authentication Request Generation | Technique | - | credential-access |
| T1622 | Debugger Evasion | Technique | - | stealth, discovery |
| T1647 | Plist File Modification | Technique | - | defense-impairment |
| T1648 | Serverless Execution | Technique | - | execution |
| T1649 | Steal or Forge Authentication Certificates | Technique | - | credential-access |
| T1650 | Acquire Access | Technique | - | resource-development |
| T1651 | Cloud Administration Command | Technique | - | execution |
| T1652 | Device Driver Discovery | Technique | - | discovery |
| T1653 | Power Settings | Technique | - | persistence |
| T1654 | Log Enumeration | Technique | - | discovery |
| T1657 | Financial Theft | Technique | - | impact |
| T1659 | Content Injection | Technique | - | initial-access, command-and-control |
| T1665 | Hide Infrastructure | Technique | - | command-and-control |
| T1666 | Modify Cloud Resource Hierarchy | Technique | - | defense-impairment |
| T1667 | Email Bombing | Technique | - | impact |
| T1668 | Exclusive Control | Technique | - | persistence |
| T1669 | Wi-Fi Networks | Technique | - | initial-access |
| T1671 | Cloud Application Integration | Technique | - | persistence |
| T1673 | Virtual Machine Discovery | Technique | - | discovery |
| T1674 | Input Injection | Technique | - | execution |
| T1675 | ESXi Administration Command | Technique | - | execution |
| T1677 | Poisoned Pipeline Execution | Technique | - | execution |
| T1678 | Delay Execution | Technique | - | stealth |
| T1679 | Selective Exclusion | Technique | - | stealth |
| T1680 | Local Storage Discovery | Technique | - | discovery |
| T1681 | Search Threat Vendor Data | Technique | - | reconnaissance |
| T1682 | Query Public AI Services | Technique | - | reconnaissance |
| T1683 | Generate Content | Technique | - | resource-development |
| T1683.001 | Written Content | Sub-technique | T1683 | resource-development |
| T1683.002 | Audio-Visual Content | Sub-technique | T1683 | resource-development |
| T1684 | Social Engineering | Technique | - | stealth |
| T1684.001 | Impersonation | Sub-technique | T1684 | stealth |
| T1684.002 | Email Spoofing | Sub-technique | T1684 | stealth |
| T1685 | Disable or Modify Tools | Technique | - | defense-impairment |
| T1685.001 | Disable or Modify Windows Event Log | Sub-technique | T1685 | defense-impairment |
| T1685.002 | Disable or Modify Cloud Log | Sub-technique | T1685 | defense-impairment |
| T1685.003 | Modify or Spoof Tool UI | Sub-technique | T1685 | defense-impairment |
| T1685.004 | Disable or Modify Linux Audit System Log | Sub-technique | T1685 | defense-impairment |
| T1685.005 | Clear Windows Event Logs | Sub-technique | T1685 | defense-impairment |
| T1685.006 | Clear Linux or Mac System Logs | Sub-technique | T1685 | defense-impairment |
| T1686 | Disable or Modify System Firewall | Technique | - | defense-impairment |
| T1686.001 | Cloud Firewall | Sub-technique | T1686 | defense-impairment |
| T1686.002 | Network Device Firewall | Sub-technique | T1686 | defense-impairment |
| T1686.003 | Windows Host Firewall | Sub-technique | T1686 | defense-impairment |
| T1687 | Exploitation for Defense Impairment | Technique | - | defense-impairment |
| T1688 | Safe Mode Boot | Technique | - | defense-impairment |
| T1689 | Downgrade Attack | Technique | - | defense-impairment |
| T1690 | Prevent Command History Logging | Technique | - | defense-impairment |

## 5. Software & Malware Tools (All 825)

| ATT&CK ID | Software / Tool Name | Type |
|---|---|---|
| S0001 | Trojan.Mebromi | malware |
| S0002 | Mimikatz | tool |
| S0003 | RIPTIDE | malware |
| S0004 | TinyZBot | malware |
| S0005 | Windows Credential Editor | tool |
| S0006 | pwdump | tool |
| S0007 | Skeleton Key | malware |
| S0008 | gsecdump | tool |
| S0009 | Hikit | malware |
| S0010 | Lurid | malware |
| S0011 | Taidoor | malware |
| S0012 | PoisonIvy | malware |
| S0013 | PlugX | malware |
| S0014 | BS2005 | malware |
| S0015 | Ixeshe | malware |
| S0016 | P2P ZeuS | malware |
| S0017 | BISCUIT | malware |
| S0018 | Sykipot | malware |
| S0019 | Regin | malware |
| S0020 | China Chopper | malware |
| S0021 | Derusbi | malware |
| S0022 | Uroburos | malware |
| S0023 | CHOPSTICK | malware |
| S0024 | Dyre | malware |
| S0025 | CALENDAR | malware |
| S0026 | GLOOXMAIL | malware |
| S0027 | Zeroaccess | malware |
| S0028 | SHIPSHAPE | malware |
| S0029 | PsExec | tool |
| S0030 | Carbanak | malware |
| S0031 | BACKSPACE | malware |
| S0032 | gh0st RAT | malware |
| S0033 | NetTraveler | malware |
| S0034 | NETEAGLE | malware |
| S0035 | SPACESHIP | malware |
| S0036 | FLASHFLOOD | malware |
| S0037 | HAMMERTOSS | malware |
| S0038 | Duqu | malware |
| S0039 | Net | tool |
| S0040 | HTRAN | tool |
| S0041 | Wiper | malware |
| S0042 | LOWBALL | malware |
| S0043 | BUBBLEWRAP | malware |
| S0044 | JHUHUGIT | malware |
| S0045 | ADVSTORESHELL | malware |
| S0046 | CozyCar | malware |
| S0047 | Hacking Team UEFI Rootkit | malware |
| S0048 | PinchDuke | malware |
| S0049 | GeminiDuke | malware |
| S0050 | CosmicDuke | malware |
| S0051 | MiniDuke | malware |
| S0052 | OnionDuke | malware |
| S0053 | SeaDuke | malware |
| S0054 | CloudDuke | malware |
| S0055 | RARSTONE | malware |
| S0056 | Net Crawler | malware |
| S0057 | Tasklist | tool |
| S0058 | SslMM | malware |
| S0059 | WinMM | malware |
| S0060 | Sys10 | malware |
| S0061 | HDoor | malware |
| S0062 | DustySky | malware |
| S0063 | SHOTPUT | malware |
| S0064 | ELMER | malware |
| S0065 | 4H RAT | malware |
| S0066 | 3PARA RAT | malware |
| S0067 | pngdowner | malware |
| S0068 | httpclient | malware |
| S0069 | BLACKCOFFEE | malware |
| S0070 | HTTPBrowser | malware |
| S0071 | hcdLoader | malware |
| S0072 | OwaAuth | malware |
| S0073 | ASPXSpy | malware |
| S0074 | Sakula | malware |
| S0075 | Reg | tool |
| S0076 | FakeM | malware |
| S0077 | CallMe | malware |
| S0078 | Psylo | malware |
| S0079 | MobileOrder | malware |
| S0080 | Mivast | malware |
| S0081 | Elise | malware |
| S0082 | Emissary | malware |
| S0083 | Misdat | malware |
| S0084 | Mis-Type | malware |
| S0085 | S-Type | malware |
| S0086 | ZLib | malware |
| S0087 | Hi-Zor | malware |
| S0088 | Kasidet | malware |
| S0089 | BlackEnergy | malware |
| S0090 | Rover | malware |
| S0091 | Epic | malware |
| S0092 | Agent.btz | malware |
| S0093 | Backdoor.Oldrea | malware |
| S0094 | Trojan.Karagany | malware |
| S0095 | ftp | tool |
| S0096 | Systeminfo | tool |
| S0097 | Ping | tool |
| S0098 | T9000 | malware |
| S0099 | Arp | tool |
| S0100 | ipconfig | tool |
| S0101 | ifconfig | tool |
| S0102 | nbtstat | tool |
| S0103 | route | tool |
| S0104 | netstat | tool |
| S0105 | dsquery | tool |
| S0106 | cmd | tool |
| S0107 | Cherry Picker | malware |
| S0108 | netsh | tool |
| S0109 | WEBC2 | malware |
| S0110 | at | tool |
| S0111 | schtasks | tool |
| S0112 | ROCKBOOT | malware |
| S0113 | Prikormka | malware |
| S0114 | BOOTRASH | malware |
| S0115 | Crimson | malware |
| S0116 | UACMe | tool |
| S0117 | XTunnel | malware |
| S0118 | Nidiran | malware |
| S0119 | Cachedump | tool |
| S0120 | Fgdump | tool |
| S0121 | Lslsass | tool |
| S0122 | Pass-The-Hash Toolkit | tool |
| S0123 | xCmd | tool |
| S0124 | Pisloader | malware |
| S0125 | Remsec | malware |
| S0126 | ComRAT | malware |
| S0127 | BBSRAT | malware |
| S0128 | BADNEWS | malware |
| S0129 | AutoIt backdoor | malware |
| S0130 | Unknown Logger | malware |
| S0131 | TINYTYPHON | malware |
| S0132 | H1N1 | malware |
| S0133 | Miner-C | malware |
| S0134 | Downdelph | malware |
| S0135 | HIDEDRV | malware |
| S0136 | USBStealer | malware |
| S0137 | CORESHELL | malware |
| S0138 | OLDBAIT | malware |
| S0139 | PowerDuke | malware |
| S0140 | Shamoon | malware |
| S0141 | Winnti for Windows | malware |
| S0142 | StreamEx | malware |
| S0143 | Flame | malware |
| S0144 | ChChes | malware |
| S0145 | POWERSOURCE | malware |
| S0146 | TEXTMATE | malware |
| S0147 | Pteranodon | malware |
| S0148 | RTM | malware |
| S0149 | MoonWind | malware |
| S0150 | POSHSPY | malware |
| S0151 | HALFBAKED | malware |
| S0152 | EvilGrab | malware |
| S0153 | RedLeaves | malware |
| S0154 | Cobalt Strike | malware |
| S0155 | WINDSHIELD | malware |
| S0156 | KOMPROGO | malware |
| S0157 | SOUNDBITE | malware |
| S0158 | PHOREAL | malware |
| S0159 | SNUGRIDE | malware |
| S0160 | certutil | tool |
| S0161 | XAgentOSX | malware |
| S0162 | Komplex | malware |
| S0163 | Janicab | malware |
| S0164 | TDTESS | malware |
| S0165 | OSInfo | malware |
| S0166 | RemoteCMD | malware |
| S0167 | Matryoshka | malware |
| S0168 | Gazer | malware |
| S0169 | RawPOS | malware |
| S0170 | Helminth | malware |
| S0171 | Felismus | malware |
| S0172 | Reaver | malware |
| S0173 | FLIPSIDE | malware |
| S0174 | Responder | tool |
| S0175 | meek | tool |
| S0176 | Wingbird | malware |
| S0177 | Power Loader | malware |
| S0178 | Truvasys | malware |
| S0179 | MimiPenguin | tool |
| S0180 | Volgmer | malware |
| S0181 | FALLCHILL | malware |
| S0182 | FinFisher | malware |
| S0183 | Tor | tool |
| S0184 | POWRUNER | malware |
| S0185 | SEASHARPEE | malware |
| S0186 | DownPaper | malware |
| S0187 | Daserf | malware |
| S0188 | Starloader | malware |
| S0189 | ISMInjector | malware |
| S0190 | BITSAdmin | tool |
| S0191 | Winexe | tool |
| S0192 | Pupy | tool |
| S0193 | Forfiles | tool |
| S0194 | PowerSploit | tool |
| S0195 | SDelete | tool |
| S0196 | PUNCHBUGGY | malware |
| S0197 | PUNCHTRACK | malware |
| S0198 | NETWIRE | malware |
| S0199 | TURNEDUP | malware |
| S0200 | Dipsind | malware |
| S0201 | JPIN | malware |
| S0202 | adbupd | malware |
| S0203 | Hydraq | malware |
| S0204 | Briba | malware |
| S0205 | Naid | malware |
| S0206 | Wiarp | malware |
| S0207 | Vasport | malware |
| S0208 | Pasam | malware |
| S0210 | Nerex | malware |
| S0211 | Linfo | malware |
| S0212 | CORALDECK | malware |
| S0213 | DOGCALL | malware |
| S0214 | HAPPYWORK | malware |
| S0215 | KARAE | malware |
| S0216 | POORAIM | malware |
| S0217 | SHUTTERSPEED | malware |
| S0218 | SLOWDRIFT | malware |
| S0219 | WINERACK | malware |
| S0220 | Chaos | malware |
| S0221 | Umbreon | malware |
| S0222 | CCBkdr | malware |
| S0223 | POWERSTATS | malware |
| S0224 | Havij | tool |
| S0225 | sqlmap | tool |
| S0226 | Smoke Loader | malware |
| S0227 | spwebmember | tool |
| S0228 | NanHaiShu | malware |
| S0229 | Orz | malware |
| S0230 | ZeroT | malware |
| S0231 | Invoke-PSImage | tool |
| S0232 | HOMEFRY | malware |
| S0233 | MURKYTOP | malware |
| S0234 | Bandook | malware |
| S0235 | CrossRAT | malware |
| S0236 | Kwampirs | malware |
| S0237 | GravityRAT | malware |
| S0238 | Proxysvc | malware |
| S0239 | Bankshot | malware |
| S0240 | ROKRAT | malware |
| S0241 | RATANKBA | malware |
| S0242 | SynAck | malware |
| S0243 | DealersChoice | malware |
| S0244 | Comnie | malware |
| S0245 | BADCALL | malware |
| S0246 | HARDRAIN | malware |
| S0247 | NavRAT | malware |
| S0248 | yty | malware |
| S0249 | Gold Dragon | malware |
| S0250 | Koadic | tool |
| S0251 | Zebrocy | malware |
| S0252 | Brave Prince | malware |
| S0253 | RunningRAT | malware |
| S0254 | PLAINTEE | malware |
| S0255 | DDKONG | malware |
| S0256 | Mosquito | malware |
| S0257 | VERMIN | malware |
| S0258 | RGDoor | malware |
| S0259 | InnaputRAT | malware |
| S0260 | InvisiMole | malware |
| S0261 | Catchamas | malware |
| S0262 | QuasarRAT | tool |
| S0263 | TYPEFRAME | malware |
| S0264 | OopsIE | malware |
| S0265 | Kazuar | malware |
| S0266 | TrickBot | malware |
| S0267 | FELIXROOT | malware |
| S0268 | Bisonal | malware |
| S0269 | QUADAGENT | malware |
| S0270 | RogueRobin | malware |
| S0271 | KEYMARBLE | malware |
| S0272 | NDiskMonitor | malware |
| S0273 | Socksbot | malware |
| S0274 | Calisto | malware |
| S0275 | UPPERCUT | malware |
| S0276 | Keydnap | malware |
| S0277 | FruitFly | malware |
| S0278 | iKitten | malware |
| S0279 | Proton | malware |
| S0280 | MirageFox | malware |
| S0281 | Dok | malware |
| S0282 | MacSpy | malware |
| S0283 | jRAT | malware |
| S0284 | More_eggs | malware |
| S0330 | Zeus Panda | malware |
| S0331 | Agent Tesla | malware |
| S0332 | Remcos | tool |
| S0333 | UBoatRAT | malware |
| S0334 | DarkComet | malware |
| S0335 | Carbon | malware |
| S0336 | NanoCore | malware |
| S0337 | BadPatch | malware |
| S0338 | Cobian RAT | malware |
| S0339 | Micropsia | malware |
| S0340 | Octopus | malware |
| S0341 | Xbash | malware |
| S0342 | GreyEnergy | malware |
| S0343 | Exaramel for Windows | malware |
| S0344 | Azorult | malware |
| S0345 | Seasalt | malware |
| S0346 | OceanSalt | malware |
| S0347 | AuditCred | malware |
| S0348 | Cardinal RAT | malware |
| S0349 | LaZagne | tool |
| S0350 | zwShell | malware |
| S0351 | Cannon | malware |
| S0352 | OSX_OCEANLOTUS.D | malware |
| S0353 | NOKKI | malware |
| S0354 | Denis | malware |
| S0355 | Final1stspy | malware |
| S0356 | KONNI | malware |
| S0357 | Impacket | tool |
| S0358 | Ruler | tool |
| S0359 | Nltest | tool |
| S0360 | BONDUPDATER | malware |
| S0361 | Expand | tool |
| S0362 | Linux Rabbit | malware |
| S0363 | Empire | tool |
| S0364 | RawDisk | tool |
| S0365 | Olympic Destroyer | malware |
| S0366 | WannaCry | malware |
| S0367 | Emotet | malware |
| S0368 | NotPetya | malware |
| S0369 | CoinTicker | malware |
| S0370 | SamSam | malware |
| S0371 | POWERTON | malware |
| S0372 | LockerGoga | malware |
| S0373 | Astaroth | malware |
| S0374 | SpeakUp | malware |
| S0375 | Remexi | malware |
| S0376 | HOPLIGHT | malware |
| S0377 | Ebury | malware |
| S0378 | PoshC2 | tool |
| S0379 | Revenge RAT | malware |
| S0380 | StoneDrill | malware |
| S0381 | FlawedAmmyy | malware |
| S0382 | ServHelper | malware |
| S0383 | FlawedGrace | malware |
| S0384 | Dridex | malware |
| S0385 | njRAT | malware |
| S0386 | Ursnif | malware |
| S0387 | KeyBoy | malware |
| S0388 | YAHOYAH | malware |
| S0389 | JCry | malware |
| S0390 | SQLRat | malware |
| S0391 | HAWKBALL | malware |
| S0393 | PowerStallion | malware |
| S0394 | HiddenWasp | malware |
| S0395 | LightNeuron | malware |
| S0396 | EvilBunny | malware |
| S0397 | LoJax | malware |
| S0398 | HyperBro | malware |
| S0400 | RobbinHood | malware |
| S0401 | Exaramel for Linux | malware |
| S0402 | OSX/Shlayer | malware |
| S0404 | esentutl | tool |
| S0409 | Machete | malware |
| S0410 | Fysbis | malware |
| S0412 | ZxShell | malware |
| S0413 | MailSniper | tool |
| S0414 | BabyShark | malware |
| S0415 | BOOSTWRITE | malware |
| S0416 | RDFSNIFFER | malware |
| S0417 | GRIFFON | malware |
| S0428 | PoetRAT | malware |
| S0430 | Winnti for Linux | malware |
| S0431 | HotCroissant | malware |
| S0433 | Rifdoor | malware |
| S0434 | Imminent Monitor | tool |
| S0435 | PLEAD | malware |
| S0436 | TSCookie | malware |
| S0437 | Kivars | malware |
| S0438 | Attor | malware |
| S0439 | Okrum | malware |
| S0441 | PowerShower | malware |
| S0442 | VBShower | malware |
| S0443 | MESSAGETAP | malware |
| S0444 | ShimRat | malware |
| S0445 | ShimRatReporter | tool |
| S0446 | Ryuk | malware |
| S0447 | Lokibot | malware |
| S0448 | Rising Sun | malware |
| S0449 | Maze | malware |
| S0450 | SHARPSTATS | malware |
| S0451 | LoudMiner | malware |
| S0452 | USBferry | malware |
| S0453 | Pony | malware |
| S0454 | Cadelspy | malware |
| S0455 | Metamorfo | malware |
| S0456 | Aria-body | malware |
| S0457 | Netwalker | malware |
| S0458 | Ramsay | malware |
| S0459 | MechaFlounder | malware |
| S0460 | Get2 | malware |
| S0461 | SDBbot | malware |
| S0462 | CARROTBAT | malware |
| S0464 | SYSCON | malware |
| S0465 | CARROTBALL | tool |
| S0466 | WindTail | malware |
| S0467 | TajMahal | malware |
| S0468 | Skidmap | malware |
| S0469 | ABK | malware |
| S0470 | BBK | malware |
| S0471 | build_downer | malware |
| S0472 | down_new | malware |
| S0473 | Avenger | malware |
| S0475 | BackConfig | malware |
| S0476 | Valak | malware |
| S0477 | Goopy | malware |
| S0481 | Ragnar Locker | malware |
| S0482 | Bundlore | malware |
| S0483 | IcedID | malware |
| S0484 | Carberp | malware |
| S0486 | Bonadan | malware |
| S0487 | Kessel | malware |
| S0488 | CrackMapExec | tool |
| S0491 | StrongPity | malware |
| S0492 | CookieMiner | malware |
| S0493 | GoldenSpy | malware |
| S0495 | RDAT | malware |
| S0496 | REvil | malware |
| S0497 | Dacls | malware |
| S0498 | Cryptoistic | malware |
| S0499 | Hancitor | malware |
| S0500 | MCMD | tool |
| S0501 | PipeMon | malware |
| S0502 | Drovorub | malware |
| S0503 | FrameworkPOS | malware |
| S0504 | Anchor | malware |
| S0508 | ngrok | tool |
| S0511 | RegDuke | malware |
| S0512 | FatDuke | malware |
| S0513 | LiteDuke | malware |
| S0514 | WellMess | malware |
| S0515 | WellMail | malware |
| S0516 | SoreFang | malware |
| S0517 | Pillowmint | malware |
| S0518 | PolyglotDuke | malware |
| S0519 | SYNful Knock | malware |
| S0520 | BLINDINGCAN | malware |
| S0521 | BloodHound | tool |
| S0526 | KGH_SPY | malware |
| S0527 | CSPY Downloader | tool |
| S0528 | Javali | malware |
| S0530 | Melcoz | malware |
| S0531 | Grandoreiro | malware |
| S0532 | Lucifer | malware |
| S0533 | SLOTHFULMEDIA | malware |
| S0534 | Bazar | malware |
| S0537 | HyperStack | malware |
| S0538 | Crutch | malware |
| S0543 | Spark | malware |
| S0546 | SharpStage | malware |
| S0547 | DropBook | malware |
| S0552 | AdFind | tool |
| S0553 | MoleNet | malware |
| S0554 | Egregor | malware |
| S0556 | Pay2Key | malware |
| S0559 | SUNBURST | malware |
| S0560 | TEARDROP | malware |
| S0561 | GuLoader | malware |
| S0562 | SUNSPOT | malware |
| S0564 | BlackMould | malware |
| S0565 | Raindrop | malware |
| S0567 | Dtrack | malware |
| S0568 | EVILNUM | malware |
| S0569 | Explosive | malware |
| S0570 | BitPaymer | malware |
| S0572 | Caterpillar WebShell | malware |
| S0574 | BendyBear | malware |
| S0575 | Conti | malware |
| S0576 | MegaCortex | malware |
| S0578 | SUPERNOVA | malware |
| S0579 | Waterbear | malware |
| S0581 | IronNetInjector | tool |
| S0582 | LookBack | malware |
| S0583 | Pysa | malware |
| S0584 | AppleJeus | malware |
| S0585 | Kerrdown | malware |
| S0586 | TAINTEDSCRIBE | malware |
| S0587 | Penquin | malware |
| S0588 | GoldMax | malware |
| S0589 | Sibot | malware |
| S0590 | NBTscan | tool |
| S0591 | ConnectWise | tool |
| S0592 | RemoteUtilities | tool |
| S0593 | ECCENTRICBANDWAGON | malware |
| S0594 | Out1 | tool |
| S0595 | ThiefQuest | malware |
| S0596 | ShadowPad | malware |
| S0597 | GoldFinder | malware |
| S0598 | P.A.S. Webshell | malware |
| S0599 | Kinsing | malware |
| S0600 | Doki | malware |
| S0601 | Hildegard | malware |
| S0603 | Stuxnet | malware |
| S0604 | Industroyer | malware |
| S0605 | EKANS | malware |
| S0606 | Bad Rabbit | malware |
| S0607 | KillDisk | malware |
| S0608 | Conficker | malware |
| S0610 | SideTwist | malware |
| S0611 | Clop | malware |
| S0612 | WastedLocker | malware |
| S0613 | PS1 | malware |
| S0614 | CostaBricks | malware |
| S0615 | SombRAT | malware |
| S0616 | DEATHRANSOM | malware |
| S0617 | HELLOKITTY | malware |
| S0618 | FIVEHANDS | malware |
| S0622 | AppleSeed | malware |
| S0623 | Siloscape | malware |
| S0624 | Ecipekac | malware |
| S0625 | Cuba | malware |
| S0626 | P8RAT | malware |
| S0627 | SodaMaster | malware |
| S0628 | FYAnti | malware |
| S0629 | RainyDay | malware |
| S0630 | Nebulae | malware |
| S0631 | Chaes | malware |
| S0632 | GrimAgent | malware |
| S0633 | Sliver | tool |
| S0634 | EnvyScout | malware |
| S0635 | BoomBox | malware |
| S0636 | VaporRage | malware |
| S0637 | NativeZone | malware |
| S0638 | Babuk | malware |
| S0639 | Seth-Locker | malware |
| S0640 | Avaddon | malware |
| S0641 | Kobalos | malware |
| S0642 | BADFLICK | malware |
| S0643 | Peppy | malware |
| S0644 | ObliqueRAT | malware |
| S0645 | Wevtutil | tool |
| S0646 | SpicyOmelette | malware |
| S0647 | Turian | malware |
| S0648 | JSS Loader | malware |
| S0649 | SMOKEDHAM | malware |
| S0650 | QakBot | malware |
| S0651 | BoxCaon | malware |
| S0652 | MarkiRAT | malware |
| S0653 | xCaon | malware |
| S0654 | ProLock | malware |
| S0657 | BLUELIGHT | malware |
| S0658 | XCSSET | malware |
| S0659 | Diavol | malware |
| S0660 | Clambling | malware |
| S0661 | FoggyWeb | malware |
| S0662 | RCSession | malware |
| S0663 | SysUpdate | malware |
| S0664 | Pandora | malware |
| S0665 | ThreatNeedle | malware |
| S0666 | Gelsemium | malware |
| S0667 | Chrommme | malware |
| S0668 | TinyTurla | malware |
| S0669 | KOCTOPUS | malware |
| S0670 | WarzoneRAT | malware |
| S0671 | Tomiris | malware |
| S0672 | Zox | malware |
| S0673 | DarkWatchman | malware |
| S0674 | CharmPower | malware |
| S0677 | AADInternals | tool |
| S0678 | Torisma | malware |
| S0679 | Ferocious | malware |
| S0680 | LitePower | malware |
| S0681 | Lizar | malware |
| S0682 | TrailBlazer | malware |
| S0683 | Peirates | tool |
| S0684 | ROADTools | tool |
| S0685 | PowerPunch | malware |
| S0686 | QuietSieve | malware |
| S0687 | Cyclops Blink | malware |
| S0688 | Meteor | malware |
| S0689 | WhisperGate | malware |
| S0690 | Green Lambert | malware |
| S0691 | Neoichor | malware |
| S0692 | SILENTTRINITY | tool |
| S0693 | CaddyWiper | malware |
| S0694 | DRATzarus | malware |
| S0695 | Donut | tool |
| S0696 | Flagpro | malware |
| S0697 | HermeticWiper | malware |
| S0698 | HermeticWizard | malware |
| S0699 | Mythic | tool |
| S1010 | VPNFilter | malware |
| S1011 | Tarrask | malware |
| S1012 | PowerLess | malware |
| S1013 | ZxxZ | malware |
| S1014 | DanBot | malware |
| S1015 | Milan | malware |
| S1016 | MacMa | malware |
| S1017 | OutSteel | malware |
| S1018 | Saint Bot | malware |
| S1019 | Shark | malware |
| S1020 | Kevin | malware |
| S1021 | DnsSystem | malware |
| S1022 | IceApple | malware |
| S1023 | CreepyDrive | malware |
| S1024 | CreepySnail | malware |
| S1025 | Amadey | malware |
| S1026 | Mongall | malware |
| S1027 | Heyoka Backdoor | malware |
| S1028 | Action RAT | malware |
| S1029 | AuTo Stealer | malware |
| S1030 | Squirrelwaffle | malware |
| S1031 | PingPull | malware |
| S1032 | PyDCrypt | malware |
| S1033 | DCSrv | malware |
| S1034 | StrifeWater | malware |
| S1035 | Small Sieve | malware |
| S1037 | STARWHALE | malware |
| S1039 | Bumblebee | malware |
| S1040 | Rclone | tool |
| S1041 | Chinoxy | malware |
| S1042 | SUGARDUMP | malware |
| S1043 | ccf32 | malware |
| S1044 | FunnyDream | malware |
| S1046 | PowGoop | malware |
| S1047 | Mori | malware |
| S1048 | macOS.OSAMiner | malware |
| S1049 | SUGARUSH | malware |
| S1050 | PcShare | tool |
| S1051 | KEYPLUG | malware |
| S1052 | DEADEYE | malware |
| S1053 | AvosLocker | malware |
| S1058 | Prestige | malware |
| S1059 | metaMain | malware |
| S1060 | Mafalda | malware |
| S1063 | Brute Ratel C4 | tool |
| S1064 | SVCReady | malware |
| S1065 | Woody RAT | malware |
| S1066 | DarkTortilla | malware |
| S1068 | BlackCat | malware |
| S1070 | Black Basta | malware |
| S1071 | Rubeus | tool |
| S1072 | Industroyer2 | malware |
| S1073 | Royal | malware |
| S1074 | ANDROMEDA | malware |
| S1075 | KOPILUWAK | malware |
| S1076 | QUIETCANARY | malware |
| S1078 | RotaJakiro | malware |
| S1081 | BADHATCH | malware |
| S1084 | QUIETEXIT | malware |
| S1085 | Sardonic | malware |
| S1086 | Snip3 | malware |
| S1087 | AsyncRAT | tool |
| S1088 | Disco | malware |
| S1089 | SharpDisco | malware |
| S1090 | NightClub | malware |
| S1091 | Pacu | tool |
| S1096 | Cheerscrypt | malware |
| S1097 | HUI Loader | malware |
| S1099 | Samurai | malware |
| S1100 | Ninja | malware |
| S1101 | LoFiSe | malware |
| S1102 | Pcexter | malware |
| S1104 | SLOWPULSE | malware |
| S1105 | COATHANGER | malware |
| S1106 | NGLite | malware |
| S1107 | NKAbuse | malware |
| S1108 | PULSECHECK | malware |
| S1109 | PACEMAKER | malware |
| S1110 | SLIGHTPULSE | malware |
| S1111 | DarkGate | malware |
| S1112 | STEADYPULSE | malware |
| S1113 | RAPIDPULSE | malware |
| S1114 | ZIPLINE | malware |
| S1115 | WIREFIRE | malware |
| S1116 | WARPWIRE | malware |
| S1117 | GLASSTOKEN | malware |
| S1118 | BUSHWALK | malware |
| S1119 | LIGHTWIRE | malware |
| S1120 | FRAMESTING | malware |
| S1121 | LITTLELAMB.WOOLTEA | malware |
| S1122 | Mispadu | malware |
| S1123 | PITSTOP | malware |
| S1124 | SocGholish | malware |
| S1125 | AcidRain | malware |
| S1129 | Akira | malware |
| S1130 | Raspberry Robin | malware |
| S1131 | NPPSPY | tool |
| S1132 | IPsec Helper | malware |
| S1133 | Apostle | malware |
| S1134 | DEADWOOD | malware |
| S1135 | MultiLayer Wiper | malware |
| S1136 | BFG Agonizer | malware |
| S1137 | Moneybird | malware |
| S1138 | Gootloader | malware |
| S1139 | INC Ransomware | malware |
| S1140 | Spica | malware |
| S1141 | LunarWeb | malware |
| S1142 | LunarMail | malware |
| S1143 | LunarLoader | malware |
| S1144 | FRP | tool |
| S1145 | Pikabot | malware |
| S1146 | MgBot | malware |
| S1147 | Nightdoor | malware |
| S1148 | Raccoon Stealer | malware |
| S1149 | CHIMNEYSWEEP | malware |
| S1150 | ROADSWEEP | malware |
| S1151 | ZeroCleare | malware |
| S1152 | IMAPLoader | malware |
| S1153 | Cuckoo Stealer | malware |
| S1154 | VersaMem | malware |
| S1155 | Covenant | tool |
| S1156 | Manjusaka | malware |
| S1158 | DUSTPAN | malware |
| S1159 | DUSTTRAP | malware |
| S1160 | Latrodectus | malware |
| S1161 | BPFDoor | malware |
| S1162 | Playcrypt | malware |
| S1163 | SnappyTCP | malware |
| S1164 | UPSTYLE | malware |
| S1166 | Solar | malware |
| S1167 | AcidPour | malware |
| S1168 | SampleCheck5000 | malware |
| S1169 | Mango | malware |
| S1170 | ODAgent | malware |
| S1171 | OilCheck | malware |
| S1172 | OilBooster | malware |
| S1173 | PowerExchange | malware |
| S1176 | attrib | tool |
| S1178 | ShrinkLocker | malware |
| S1179 | Exbyte | malware |
| S1180 | BlackByte Ransomware | malware |
| S1181 | BlackByte 2.0 Ransomware | malware |
| S1182 | MagicRAT | malware |
| S1183 | StrelaStealer | malware |
| S1184 | BOLDMOVE | malware |
| S1185 | LightSpy | malware |
| S1186 | Line Dancer | malware |
| S1187 | reGeorg | malware |
| S1188 | Line Runner | malware |
| S1189 | Neo-reGeorg | malware |
| S1190 | Kapeka | malware |
| S1191 | Megazord | malware |
| S1192 | NICECURL | malware |
| S1193 | TAMECAT | malware |
| S1194 | Akira _v2 | malware |
| S1196 | Troll Stealer | malware |
| S1197 | GoBear | malware |
| S1198 | Gomir | malware |
| S1199 | LockBit 2.0 | malware |
| S1200 | StealBit | malware |
| S1201 | TRANSLATEXT | malware |
| S1202 | LockBit 3.0 | malware |
| S1203 | J-magic | malware |
| S1204 | cd00r | malware |
| S1205 | cipher.exe | tool |
| S1206 | JumbledPath | malware |
| S1207 | XLoader | malware |
| S1209 | Quick Assist | tool |
| S1210 | Sagerunex | malware |
| S1211 | Hannotog | malware |
| S1212 | RansomHub | malware |
| S1213 | Lumma Stealer | malware |
| S1217 | VIRTUALPITA | malware |
| S1218 | VIRTUALPIE | malware |
| S1219 | REPTILE | malware |
| S1220 | MEDUSA | malware |
| S1221 | MOPSLED | malware |
| S1222 | RIFLESPINE | malware |
| S1223 | THINCRUST | malware |
| S1224 | CASTLETAP | malware |
| S1226 | BOOKWORM | malware |
| S1227 | StarProxy | malware |
| S1228 | PUBLOAD | malware |
| S1229 | Havoc | malware |
| S1230 | HIUPAN | malware |
| S1232 | SplatDropper | malware |
| S1233 | PAKLOG | malware |
| S1234 | SplatCloak | malware |
| S1235 | CorKLOG | malware |
| S1236 | CLAIMLOADER | malware |
| S1237 | CANONSTAGER | malware |
| S1238 | STATICPLUGIN | malware |
| S1239 | TONESHELL | malware |
| S1240 | RedLine Stealer | malware |
| S1242 | Qilin | malware |
| S1244 | Medusa Ransomware | malware |
| S1245 | InvisibleFerret | malware |
| S1246 | BeaverTail | malware |
| S1247 | Embargo | malware |
| S1248 | XORIndex Loader | malware |
| S1249 | HexEval Loader | malware |
| S9001 | SystemBC | malware |
| S9002 | Diskpart | tool |
| S9003 | evilginx2 | tool |
| S9004 | Crocodilus | malware |
| S9007 | HTTPTroy | malware |
| S9008 | Shai-Hulud | malware |
| S9009 | TruffleHog | tool |
| S9010 | GlassWorm | malware |
| S9011 | BRUSHFIRE | malware |
| S9012 | TRAILBLAZE | malware |
| S9013 | DRYHOOK | malware |
| S9014 | PHASEJAM | malware |
| S9015 | BRICKSTORM | malware |
| S9016 | Caminho | malware |
| S9017 | DCRAT | tool |
| S9018 | HeartCrypt | malware |
| S9019 | PureCrypter | malware |
| S9020 | LODEINFO | malware |
| S9021 | DOWNIISSA | malware |
| S9022 | MirrorStealer | malware |
| S9023 | HiddenFace | malware |
| S9024 | SPAWNCHIMERA | malware |
| S9025 | NOOPLDR | malware |
| S9026 | ROAMINGHOUSE | malware |
| S9027 | ANELLDR | malware |
| S9028 | PHPsert | malware |
| S9029 | IronWind | malware |
| S9030 | SameCoin | malware |
| S9031 | AshTag | malware |
| S9032 | MuddyViper | malware |
| S9033 | Fooder | malware |
| S9034 | Tsundere Botnet | malware |
| S9035 | LAMEHUG | malware |
| S9036 | LP-Notes | malware |
| S9037 | RustyWater | malware |
| S9038 | DynoWiper | malware |
| S9039 | LazyWiper | malware |
| S9041 | TeamPCP Cloud Stealer | malware |
| S9042 | CanisterWorm | malware |
| S9043 | Mini Shai-Hulud | malware |
| S9044 | Kali365 | malware |

import json
import datetime

# ── 1. OSINT Intelligence Database (25 Threat Actors) ──
osint_data = [
    {
        "real_name": "Maksim Galochkin", "surface_alias": "Bentley", "platform": "Conti Jabber",
        "known_wallets": ["1BentJeyCryptABC123DEF456GH789JK"], "known_emails": ["bentley_crypter@protonmail.com"],
        "known_comms": ["bentley@exploit.in"], "known_onions": ["contileaks7j27464y6g26.onion"],
        "stylometry_markers": ["privnote", "jabber"]
    },
    {
        "real_name": "Mikhail Matveev", "surface_alias": "Wazawaka", "platform": "XSS / Twitter",
        "known_wallets": ["1WazawakaEscrow123456789ABCDEFGH", "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"], 
        "known_emails": ["wazawaka@exploit.in"], "known_comms": ["@waza_support"], 
        "known_onions": [], "stylometry_markers": ["bro", "vouch"]
    },
    {
        "real_name": "Dmitry Khoroshev", "surface_alias": "LockBitSupp", "platform": "LockBit Operations",
        "known_wallets": ["1LockBitSuppAddress99281746283748"], "known_emails": ["supp_admin@lockbit.io"],
        "known_comms": ["A1B2C3D4E5F678901234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890AB"], 
        "known_onions": ["lockbitapt6vx57t3eeqjofwgcglmutr3a35nyzyvhdp3qq4weewrvqd.onion"], "stylometry_markers": ["negotiator", "onionmail"]
    },
    {
        "real_name": "Maksim Yakubets", "surface_alias": "Aqua", "platform": "Evil Corp",
        "known_wallets": ["1AquabotnetMaster99384719284728A", "TAquaBotnetMaster99384719284728A"], 
        "known_emails": ["drider_ops@protonmail.com"], "known_comms": ["aqua_admin@jabber.ru"], 
        "known_onions": [], "stylometry_markers": ["drider", "banker"]
    },
    {
        "real_name": "Park Jin Hyok", "surface_alias": "Crypton", "platform": "Lazarus Group",
        "known_wallets": ["1LazarusVauJtBtcAddress99281746"], "known_emails": ["crypto_heist@tutanota.com"],
        "known_comms": ["t.me/dprk_recon"], "known_onions": [], "stylometry_markers": ["heist", "swap", "recon"]
    },
    {
        "real_name": "Dmytro Rashevskyi", "surface_alias": "FirstVPN_Admin", "platform": "Infrastructure Provider",
        "known_wallets": ["1FirstVPNHostingAdminAddress992"], "known_emails": ["admin@firstvpn.net"],
        "known_comms": ["B2C3D4E5F678901234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABC"], 
        "known_onions": ["bulletproofvpngy27464y6g26.onion"], "stylometry_markers": ["bulletproof", "anonymizer", "no logs", "opsec"]
    },
    {
        "real_name": "Yevgeniy Silayev", "surface_alias": "Obfuscation_Master", "platform": "Cryptor Vendor",
        "known_wallets": ["1SiJayevCryptorVendor8829104829"], "known_emails": ["silayev_crypt@yandex.ru"],
        "known_comms": ["@obfuscator_ru"], "known_onions": [], "stylometry_markers": ["obfuscator", "stub", "runtime"]
    },
    {
        "real_name": "Yaroslav Vasinskyi", "surface_alias": "Rabotnik", "platform": "Sodinokibi RaaS",
        "known_wallets": ["1VasinskyiRansomShare8829104829"], "known_emails": ["vasinskyi_raas@protonmail.com"],
        "known_comms": ["rabotnik@thesecure.biz"], "known_onions": ["revilcorp7j27464y6g26.onion"], "stylometry_markers": ["kaseya", "split"]
    },
    {
        "real_name": "Elena Rostova", "surface_alias": "root_admin", "platform": "Exploit.in",
        "known_wallets": ["1EJenaBrokerCoJdWaJJet882910482"], "known_emails": ["admin_root@tutanota.com"],
        "known_comms": [], "known_onions": ["exploitindb7j27464y6g26.onion"], "stylometry_markers": ["mirror", "database", "sql injection"]
    },
    {
        "real_name": "Evgeniy Bogachev", "surface_alias": "Slavik", "platform": "Zeus Botnet",
        "known_wallets": ["1ZeusMasterControJJerAddr992817"], "known_emails": ["slavik_zeus@inbox.ru"],
        "known_comms": ["slavik@xmpp.jp"], "known_onions": [], "stylometry_markers": ["inject", "builder", "license key"]
    },
    {
        "real_name": "Roman Semenov", "surface_alias": "MixerLead", "platform": "Tornado Cash Dev",
        "known_wallets": ["1MixerObfuscationNode9928174628"], "known_emails": ["semenov_dev@protonmail.com"],
        "known_comms": ["@mixer_admin"], "known_onions": ["tornadocashvpngy27464y6g26.onion"], "stylometry_markers": ["relayer", "privacy pool"]
    },
    {
        "real_name": "Armando Ojeda Aviles", "surface_alias": "Cartel_Launderer", "platform": "Sinaloa Crypto Cell",
        "known_wallets": ["1SinaJoaJaunderNetwork993847192", "TCartelLaunderer99384719284728A"], "known_emails": ["ojeda_conversion@countermail.com"],
        "known_comms": ["C3D4E5F678901234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCD"], 
        "known_onions": [], "stylometry_markers": ["bulk cash", "conversion", "laundering", "p2p"]
    },
    {
        "real_name": "Aleksandr Sikerin", "surface_alias": "Bravo", "platform": "ALPHV BlackCat",
        "known_wallets": ["1A1phvB1ackCatRansomNet9938471"], "known_emails": ["bravo_alphv@protonmail.com"],
        "known_comms": ["@alphv_support"], "known_onions": ["alphvleaksvpngy27464y6g26.onion"], "stylometry_markers": ["rust", "extortion"]
    },
    {
        "real_name": "Vitaly Kovalev", "surface_alias": "Bentley_Ops", "platform": "Trickbot Gang",
        "known_wallets": ["1TrickbotOpsWallet993847192847"], "known_emails": ["trickbot_ops@tutanota.com"],
        "known_comms": ["trickbot@exploit.in"], "known_onions": [], "stylometry_markers": ["banking trojan", "lateral movement"]
    },
    {
        "real_name": "Denis Kulkov", "surface_alias": "Try2Check", "platform": "Carding Validator",
        "known_wallets": ["1Try2CheckCardingVault99384719"], "known_emails": ["admin@try2check.com"],
        "known_comms": ["@try2check_admin"], "known_onions": ["try2checkvpngy27464y6g26.onion"], "stylometry_markers": ["cvv", "validity rate"]
    },
    {
        "real_name": "Igor Turashev", "surface_alias": "Enki", "platform": "Dridex Core",
        "known_wallets": ["1DridexDevVault99384719284728A"], "known_emails": ["enki_dev@protonmail.com"],
        "known_comms": ["enki_dridex@jabber.ru"], "known_onions": [], "stylometry_markers": ["macros", "maldoc"]
    },
    {
        "real_name": "Rinat Zandiev", "surface_alias": "Garnet", "platform": "DarkSide Affiliate",
        "known_wallets": ["1DarkSideGarnetWallet993847192"], "known_emails": ["garnet_darkside@tutanota.com"],
        "known_comms": ["D4E5F678901234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDE"], 
        "known_onions": [], "stylometry_markers": ["double extortion", "pipeline"]
    },
    {
        "real_name": "Alexey Bilyuchenko", "surface_alias": "Admin_WEX", "platform": "BTC-e Exchange",
        "known_wallets": ["1WexExchangeColdWallet99384719"], "known_emails": ["admin@btce.com"],
        "known_comms": ["@wex_admin"], "known_onions": [], "stylometry_markers": ["liquidation", "fiat gateway"]
    },
    {
        "real_name": "Sandu Diaconu", "surface_alias": "Bulldozer", "platform": "RedLine Stealer",
        "known_wallets": ["1RedLineStealerVault9938471928"], "known_emails": ["bulldozer_redline@protonmail.com"],
        "known_comms": ["bulldozer@exploit.in"], "known_onions": ["redlinelogsgy27464y6g26.onion"], "stylometry_markers": ["browser logs", "cookies"]
    },
    {
        "real_name": "Danil Potekhin", "surface_alias": "PhishKing", "platform": "Crypto Phisher",
        "known_wallets": ["1PhishKingLootVault99384719284"], "known_emails": ["phishking@tutanota.com"],
        "known_comms": ["@phishking_official"], "known_onions": [], "stylometry_markers": ["seed phrase", "drainer"]
    },
    {
        "real_name": "Sergey Zolotarev", "surface_alias": "Kasper", "platform": "Royal Ransomware",
        "known_wallets": ["1Roya1RansomwareVau1t99384719"], "known_emails": ["kasper_royal@protonmail.com"],
        "known_comms": ["kasper@thesecure.biz"], "known_onions": ["royalransomvpngy27464y6g26.onion"], "stylometry_markers": ["callback", "partial encryption"]
    },
    {
        "real_name": "Oleg Koshkin", "surface_alias": "Cryptoboy", "platform": "Crypting Service",
        "known_wallets": ["1CryptoboyFUDWallet99384719284"], "known_emails": ["cryptoboy@exploit.in"],
        "known_comms": ["E5F678901234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1"], 
        "known_onions": [], "stylometry_markers": ["scantime", "memory injection"]
    },
    {
        "real_name": "Boris Chen", "surface_alias": "PandaBroker", "platform": "Volt Typhoon IAB",
        "known_wallets": ["1PandaBrokerIABWallet993847192"], "known_emails": ["panda_broker@tutanota.com"],
        "known_comms": ["t.me/panda_iab"], "known_onions": [], "stylometry_markers": ["citrix", "fortinet", "living off the land"]
    },
    {
        "real_name": "Tariq Al-Mansoor", "surface_alias": "ZeroTrace", "platform": "Bulletproof XMPP",
        "known_wallets": ["1ZeroTraceHostingWallet9938471"], "known_emails": ["admin@zerotrace.net"],
        "known_comms": ["admin@jabber.ru"], "known_onions": ["zerotracexmppgy27464y6g26.onion"], "stylometry_markers": ["offshore", "dmca ignored"]
    },
    {
        "real_name": "Ilya Sachkov", "surface_alias": "IntelBroker_Shadow", "platform": "Exploit Broker",
        "known_wallets": ["1IntelBrokerShadowVault9938471"], "known_emails": ["intelbroker@protonmail.com"],
        "known_comms": ["@intelbroker_shadow"], "known_onions": ["intelbrokerdbgy27464y6g26.onion"], "stylometry_markers": ["0day", "poc"]
    }
]

# ── 2. Mock Dark Web Intercepts (30 Posts) ──
mock_feed = [
    {"post_id": "dw_001", "author": "boriselcin", "content": "Need a FUD crypter. AV bypass must be 100%. Escrow accepted. Hit my jabber or email bentley_crypter@protonmail.com. Payment to 1BentJeyCryptABC123DEF456GH789JK."},
    {"post_id": "dw_002", "author": "Uhodiransomwar", "content": "Vouch for this access, bro. Send funds to escrow wallet 1WazawakaEscrow123456789ABCDEFGH."},
    {"post_id": "dw_003", "author": "LockBit_Representative", "content": "LockBit affiliate program. Bug bounty rewards active. Tox ID: A1B2C3D4E5F678901234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890AB. Visit our leak site lockbitapt6vx57t3eeqjofwgcglmutr3a35nyzyvhdp3qq4weewrvqd.onion."},
    {"post_id": "dw_004", "author": "drider_operator", "content": "Financial traffic dumps available. Deposit to USDT TRC20 wallet TAquaBotnetMaster99384719284728A or jabber aqua_admin@jabber.ru."},
    {"post_id": "dw_005", "author": "korea_recon_99", "content": "Operational issues email crypto_heist@tutanota.com. Looking to swap funds from the latest heist."},
    {"post_id": "dw_006", "author": "vpn_provider_ru", "content": "We offer bulletproof hosting and anonymizer services. Strict no logs policy for high opsec. Visit bulletproofvpngy27464y6g26.onion."},
    {"post_id": "dw_007", "author": "crypt_vendor_1", "content": "Selling a new obfuscator stub. Can bypass EDR instantly in runtime. Contact @obfuscator_ru on TG."},
    {"post_id": "dw_008", "author": "rabotnik_core", "content": "RaaS payload update deployed. Affiliate split is 70/30. Email vasinskyi_raas@protonmail.com. Jabber rabotnik@thesecure.biz."},
    {"post_id": "dw_009", "author": "data_broker_ru", "content": "Government employee database mirror. Full dump available via sql injection. Inquiries to admin_root@tutanota.com."},
    {"post_id": "dw_010", "author": "zeus_master", "content": "Banking inject builder v3. Contact slavik@xmpp.jp. License key wallet 1ZeusMasterControJJerAddr992817."},
    {"post_id": "dw_011", "author": "anonymity_pool", "content": "Relayer node up. Deposit to 1MixerObfuscationNode9928174628. Privacy pool is fully operational."},
    {"post_id": "dw_012", "author": "cartel_ops", "content": "Need bulk cash conversion. Send to TCartelLaunderer99384719284728A. P2P laundering only."},
    {"post_id": "dw_013", "author": "alphv_admin", "content": "ALPHV ransomware leak mirror updated. Check alphvleaksvpngy27464y6g26.onion. Rust payloads available for extortion."},
    {"post_id": "dw_014", "author": "trick_dev", "content": "Banking trojan update. Lateral movement features enabled. Contact trickbot@exploit.in."},
    {"post_id": "dw_015", "author": "carder_pro", "content": "High validity rate CVV dumps. Try2check service active. Email admin@try2check.com."},
    {"post_id": "dw_016", "author": "maldoc_master", "content": "New maldoc macros for initial access. Contact enki_dridex@jabber.ru."},
    {"post_id": "dw_017", "author": "pipeline_hacker", "content": "Double extortion methods implemented. Send cuts to 1DarkSideGarnetWallet993847192."},
    {"post_id": "dw_018", "author": "fiat_gate", "content": "Liquidation and fiat gateway services. Reach out to @wex_admin on Telegram."},
    {"post_id": "dw_019", "author": "stealer_logs", "content": "Fresh browser logs and cookies available on redlinelogsgy27464y6g26.onion. Reach bulldozer@exploit.in."},
    {"post_id": "dw_020", "author": "crypto_drainer", "content": "Looking for seed phrase extraction tools. Contact @phishking_official."},
    {"post_id": "dw_021", "author": "royal_affil", "content": "Partial encryption callback successful. Royal ransomware group. Pay to 1Roya1RansomwareVau1t99384719."},
    {"post_id": "dw_022", "author": "memory_inj", "content": "Memory injection scantime bypass tool. Tox E5F678901234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1."},
    {"post_id": "dw_023", "author": "living_land", "content": "Fortinet and Citrix access. Living off the land techniques. Email panda_broker@tutanota.com."},
    {"post_id": "dw_024", "author": "dmca_ignore", "content": "Offshore hosting. DMCA ignored. XMPP services at zerotracexmppgy27464y6g26.onion."},
    {"post_id": "dw_025", "author": "poc_0day", "content": "Selling zero-day POC for major firewall. Contact @intelbroker_shadow or visit intelbrokerdbgy27464y6g26.onion."},
    {"post_id": "dw_026", "author": "clean_user", "content": "Hey guys, just looking for some Python networking tutorials. Nothing illegal here. Can someone link me a guide?"},
    {"post_id": "dw_027", "author": "paranoid_opsec", "content": "I need a bulletproof server with no logs and high opsec to host my personal blog. I only pay in XMR: 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A."},
    {"post_id": "dw_028", "author": "generic_hacker", "content": "Selling cheap RDP access. DM me on forums. Escrow is a must."},
    {"post_id": "dw_029", "author": "ghost_bot", "content": "Looking for a botnet for DDoS. Will pay 1000 USD to any wallet."},
    {"post_id": "dw_030", "author": "random_trader", "content": "Buying bulk Giftcards. Send me your offers. Cash only."}
]

with open("osint_db.json", "w") as f: json.dump(osint_data, f, indent=2)
with open("mock_feed.json", "w") as f: json.dump(mock_feed, f, indent=2)

print("✅ Successfully generated 25 profiles in osint_db.json and 30 posts in mock_feed.json!")

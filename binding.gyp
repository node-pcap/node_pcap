{
    "targets": [
        {
            "target_name": "pcap_binding",
            "sources": [ "pcap_binding.cc", "pcap_session.cc" ],
            "include_dirs": [
                "<!(node -e \"require('nan')\")"
            ],
            'conditions': [
                ['OS=="win"', {
                    'include_dirs': [
                        "C:\\dev\\src\\WpdPack-4.1.2\\Include"
                    ],
                    'conditions': [
                        ['target_arch == "x64"', {
                            'link_settings': {
                                'libraries': [
                                    '-l$(WINPCAP_DIR)\\Lib\\x64\\wpcap',
                                    '-l$(WINPCAP_DIR)\\Lib\\x64\\Packet',
                                    '-lws2_32'
                                ]
                            }
                        }, { # target_arch != "x64"
                            'link_settings': {
                                'libraries': [
                                    '-l$(WINPCAP_DIR)\\Lib\\wpcap',
                                    '-l$(WINPCAP_DIR)\\Lib\\Packet',
                                    '-lws2_32'
                                ]
                            }
                        }]
                    ]
                }, { # OS != "win"
                    "link_settings": {
                        "libraries": [
                            "-lpcap"
                        ]
                    },
                }]
            ]
        }
    ]
}

{
  "targets": [
    {
      "target_name": "pcap_binding",
      "sources": [ "src/pcap_binding.cc", "src/pcap_session.cc" ],
      "include_dirs": [
        "<!(node -e \"require('nan')\")"
      ],
      "link_settings": {
          "libraries": [
              "-lpcap"
          ]
      }
    }
  ]
}

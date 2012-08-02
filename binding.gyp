{
  "targets": [
    {
      "target_name": "pcap_binding",
      "sources": [ "pcap_binding.cc" ],
      'link_settings': {
          'libraries': [
              '-lpcap'
          ]
      }
    }
  ]
}

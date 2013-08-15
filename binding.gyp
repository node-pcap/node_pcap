{
  "targets": [
    {
      "target_name": "pcap_binding",
      "sources": [ "pcap_binding.cc", "pcap_session.cc" ],
      'link_settings': {
          'libraries': [
              '-lpcap'
          ]
      }
    }
  ]
}

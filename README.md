node_pcap
=========

This is not done yet.  If you want to see how awesome it will be, check this out:

Run the test program as root to be able to open the capture device:

    mjr:~/work/node_pcap$ sudo node test.js

## Usage

    var pcap = require("./pcap");

    session = pcap.createSession("en0", "port 22");
    session.addListener('packet', function (pcap_header, raw_packet) {
        decoded = decode_packet(pcap_header, raw_packet);
        sys.puts((pcap_header.time - start_time) + "ms len: " + pcap_header.len + " " + 
            decoded.ethernet.shost + " " + decoded.ethernet.dhost + " " +
            sys.inspect(decoded.ip) + sys.inspect(decoded.tcp)
        );
    });

## Output from `findalldevs`:

    [ { name: 'en0'
      , addresses: 
         [ { addr: '10.51.2.183'
           , netmask: '255.255.255.0'
           , broadaddr: '10.51.2.255'
           }
         ]
      }
    , { name: 'fw0', addresses: [] }
    , { name: 'en1', addresses: [] }
    , { name: 'lo0'
      , addresses: [ { addr: '127.0.0.1', netmask: '255.0.0.0' } ]
      , flags: 'PCAP_IF_LOOPBACK'
      }
    ]

## Ethernet, IP, and TCP decode:

    5060ms len: 78 00:17:f2:0f:49:a6 00:1e:c9:45:e8:30 { version: 4
    , header_length: 5
    , diffserv: 0
    , total_length: 64
    , identification: 21049
    , flag_reserved: 0
    , flag_df: 1
    , flag_mf: 0
    , fragment_offset: 0
    , ttl: 64
    , protocol: 6
    , header_checksum: 0
    , saddr: '10.51.2;183'
    , daddr: '184.72.56;14'
    , protocol_name: 'TCP'
    }{ sport: 56051
    , dport: 22
    , seqno: 2449256658
    , ackno: 0
    , data_offset: 11
    , reserved: 0
    , flag_cwr: 0
    , flag_ece: 0
    , flag_urg: 0
    , flag_ack: 0
    , flag_psh: 0
    , flag_rst: 0
    , flag_syn: 1
    , flag_fin: 0
    , window_size: 65535
    , checksum: 64882
    , urgent_pointer: 0
    }
    5066ms len: 78 00:1e:c9:45:e8:30 00:17:f2:0f:49:a6 { version: 4
    , header_length: 5
    , diffserv: 0
    , total_length: 60
    , identification: 0
    , flag_reserved: 0
    , flag_df: 1
    , flag_mf: 0
    , fragment_offset: 0
    , ttl: 49
    , protocol: 6
    , header_checksum: 19580
    , saddr: '184.72.56;14'
    , daddr: '10.51.2;183'
    , protocol_name: 'TCP'
    }{ sport: 22
    , dport: 56051
    , seqno: 2268319228
    , ackno: 2449256659
    , data_offset: 10
    , reserved: 0
    , flag_cwr: 0
    , flag_ece: 0
    , flag_urg: 0
    , flag_ack: 1
    , flag_psh: 0
    , flag_rst: 0
    , flag_syn: 1
    , flag_fin: 0
    , window_size: 5792
    , checksum: 28115
    , urgent_pointer: 0
    }
  
## Output from `pcap_stats`:
    
    { ps_recv: 17, ps_drop: 0, ps_ifdrop: 1606411320 }


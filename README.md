node_pcap
=========

This is not done yet.  If you want to see how awesome it will be, check this out:

Run the test program as root to be able to open the capture device:

    mjr:~/work/node_pcap$ sudo node test.js

## Usage

    session = pcap.createSession("en1", "port 6667");

    session.addListener('packet', function (pcap_header, raw_packet) {
        decoded = pcap.decode_packet(pcap_header, raw_packet);
        sys.puts(pcap_header.len + " " + 
            decoded.ip.saddr + ":" + decoded.tcp.sport + " -> " +
            decoded.ip.daddr + ":" + decoded.tcp.dport + " " +
            decoded.payload
        );
        sys.puts(sys.inspect(session.stats()));
    });

## Raw TCP payload dump:

Capturing port 6667 (irc) and issuing `/whois _ry`:

    rv-mjr2:~/work/node_pcap$ sudo node_g test.js 
    77 10.240.0.133:64303 -> 213.92.8.4:6667 whois _ry

    { ps_recv: 5, ps_drop: 0, ps_ifdrop: 1606408464 }
    DEBUG: readWatcher callback fired and dispatch read 0 packets instead of 1
    129 213.92.8.4:6667 -> 10.240.0.133:64303 :calvino.freenode.net 311 mjr_ _ry ~ry tinyclouds.org * :hayr

    { ps_recv: 8, ps_drop: 0, ps_ifdrop: 1606408592 }
    66 10.240.0.133:64303 -> 213.92.8.4:6667 
    { ps_recv: 10, ps_drop: 0, ps_ifdrop: 1606407888 }
    303 213.92.8.4:6667 -> 10.240.0.133:64303 :calvino.freenode.net 319 mjr_ _ry :#Node.js 
    :calvino.freenode.net 312 mjr_ _ry wolfe.freenode.net :Manchester, England
    :calvino.freenode.net 330 mjr_ _ry _ry :is logged in as
    :calvino.freenode.net 318 mjr_ _ry :End of /WHOIS list.

    { ps_recv: 10, ps_drop: 0, ps_ifdrop: 1606407888 }

## Output from `session.findalldevs`:

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

## LICENSE - "MIT License"

Copyright (c) 2010 Matthew Ranney, http://ranney.com/

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

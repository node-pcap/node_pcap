node_pcap
=========

This is not done yet, and patches are welcome.  If you want to see how awesome it will be, check this out:

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

### Running `curl nodejs.org`:

First packet, TCP SYN:

    { ethernet: 
       { dhost: '00:18:39:ff:f9:1c'
       , shost: '00:1f:5b:ce:3e:29'
       , ethertype: 2048
       , ip: 
          { version: 4
          , header_length: 5
          , diffserv: 0
          , total_length: 64
          , identification: 49042
          , flags: { reserved: 0, df: 1, mf: 0 }
          , fragment_offset: 0
          , ttl: 64
          , protocol: 6
          , header_checksum: 35325
          , saddr: '10.240.0.133'
          , daddr: '97.107.132.72'
          , protocol_name: 'TCP'
          , tcp: 
             { sport: 57230
             , dport: 80
             , seqno: 4179361823
             , ackno: 1540242985
             , data_offset: 11
             , reserved: 0
             , flags: 
                { cwr: 0
                , ece: 0
                , urg: 0
                , ack: 0
                , psh: 0
                , rst: 0
                , syn: 1
                , fin: 0
                }
             , window_size: 65535
             , checksum: 2601
             , urgent_pointer: 0
             , payload_offset: 78
             , payload: { length: 0 }
             }
          }
       }
    , pcap_header: 
       { time: Sat, 22 May 2010 07:48:40 GMT
       , tv_sec: 1274514520
       , tv_usec: 820479
       , caplen: 78
       , len: 78
       , link_type: 'LINKTYPE_ETHERNET'
       }
    }
    
Second packet, TCP SYN+ACK:

    { ethernet: 
       { dhost: '00:1f:5b:ce:3e:29'
       , shost: '00:18:39:ff:f9:1c'
       , ethertype: 2048
       , ip: 
          { version: 4
          , header_length: 5
          , diffserv: 32
          , total_length: 60
          , identification: 0
          , flags: { reserved: 0, df: 1, mf: 0 }
          , fragment_offset: 0
          , ttl: 48
          , protocol: 6
          , header_checksum: 22900
          , saddr: '97.107.132.72'
          , daddr: '10.240.0.133'
          , protocol_name: 'TCP'
          , tcp: 
             { sport: 80
             , dport: 57230
             , seqno: 1042874392
             , ackno: 973076764
             , data_offset: 10
             , reserved: 0
             , flags: 
                { cwr: 0
                , ece: 0
                , urg: 0
                , ack: 1
                , psh: 0
                , rst: 0
                , syn: 1
                , fin: 0
                }
             , window_size: 5792
             , checksum: 35930
             , urgent_pointer: 0
             , payload_offset: 74
             , payload: { length: 0 }
             }
          }
       }
    , pcap_header: 
       { time: Sat, 22 May 2010 07:48:40 GMT
       , tv_sec: 1274514520
       , tv_usec: 915980
       , caplen: 74
       , len: 74
       , link_type: 'LINKTYPE_ETHERNET'
       }
    }

Third packet, TCP ACK, 3-way handshake is now complete:

    { ethernet: 
       { dhost: '00:18:39:ff:f9:1c'
       , shost: '00:1f:5b:ce:3e:29'
       , ethertype: 2048
       , ip: 
          { version: 4
          , header_length: 5
          , diffserv: 0
          , total_length: 52
          , identification: 39874
          , flags: { reserved: 0, df: 1, mf: 0 }
          , fragment_offset: 0
          , ttl: 64
          , protocol: 6
          , header_checksum: 44505
          , saddr: '10.240.0.133'
          , daddr: '97.107.132.72'
          , protocol_name: 'TCP'
          , tcp: 
             { sport: 57230
             , dport: 80
             , seqno: 4179361823
             , ackno: 1540242985
             , data_offset: 8
             , reserved: 0
             , flags: 
                { cwr: 0
                , ece: 0
                , urg: 0
                , ack: 1
                , psh: 0
                , rst: 0
                , syn: 0
                , fin: 0
                }
             , window_size: 65535
             , checksum: 53698
             , urgent_pointer: 0
             , payload_offset: 66
             , payload: { length: 0 }
             }
          }
       }
    , pcap_header: 
       { time: Sat, 22 May 2010 07:48:40 GMT
       , tv_sec: 1274514520
       , tv_usec: 916054
       , caplen: 66
       , len: 66
       , link_type: 'LINKTYPE_ETHERNET'
       }
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

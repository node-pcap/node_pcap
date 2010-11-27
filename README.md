node_pcap
=========

This is a set of bindings from `libpcap` to node as well as some useful libraries to decode, print, and
analyze packets.  `libpcap` is a packet capture library used by programs like `tcpdump` and `wireshark`.
It has been tested on OSX and Linux.

`node_pcap` is useful for many things, but it does not yet understand all common protocols.  A popular reason
to use this package is `examples/http_trace`, described below.

Another great reason to use `node_pcap` is 
[htracr](https://github.com/mnot/htracr), written by Mark Nottingham.

## Why capture packets in JavaScript?

There are already many tools for capturing, decoding, and analyzing packets.  Many of them are thoroughly
tested and very fast.  Why would anybody want to do such low level things like packet capture and analysis
in JavaScript?  A few reasons:

* JavaScript makes writing event-based programs very natural.  Each packet that is captured generates an
event, and as higher level protocols are decoded, they might generate events as well.  Writing code to handle
these events is much easier and more readable with anonymous functions and closures.

* node makes handling binary data in JavaScript fast and efficient with its Buffer class.  Decoding packets involves
a lot of binary slicing and dicing which can be awkward with JavaScript strings.

* Writing servers that capture packets, process them somehow, and then serve the processed data up in some way is
very straightforward in node.

* Node has a very good HTTP parser that is used to progressively decode HTTP sessions.

## Installation

You will need `libpcap` installed.  Most OSX machines seem to have it.  All major Linux distributions have it available
either by default or with a package like `libpcap-dev`.

The easiest way to get `node_pcap` and its tools is with `npm`:

    npm install pcap

If you want to hack on the source code, you can get it from github.  Clone the repo like this:

    git clone git://github.com/mranney/node_pcap.git

To compile the native code bindings, do this:

    cd node_pcap
    node-waf configure build

Assuming it built without errors, you should be able to run the examples and then write your own packet
capture programs.


## Usage

There are several example programs that show how to use `node_pcap`.  These examples are best documentation.
Try them out and see what they do.

To use this library in your own program, `pcap.js` and `pcap_binding.node` must be in `NODE_PATH`.  `npm` 
takes care of this automatically.

### Starting a capture session

To start a capture session, call `pcap.createSession` with an interface name and a pcap filter string:

    var pcap = require('pcap'),
        pcap_session = pcap.createSession(interface, filter);

`interface` is the name of the interface on which to capture packets.  If passed an empty string, `libpcap`
will try to pick a "default" interface, which is often just the first one in some list and not what you want.

`fitler` is a pcap filter expression, see `pcap-filter(7)` for more information.  An empty string will capture
all packets visible on the interface.

Note that `node_pcap` always opens the interface in promiscuous mode, which generally requires running as root.
Unless you are recklessly roaming about as root already, you'll probably want to start your node program like this:

    sudo node test.js

`pcap_session` is an `EventEmitter` that emits a `packet` event.  The only argument to the callback will be a
`Buffer` object with the raw bytes returned by `libpcap`.

Listening for packets:

    pcap_session.on('packet', function (raw_packet) {
        // do some stuff with a raw packet
    });

To convert `raw_packet` into a JavaScript object that is easy to work with, decode it:
    
    var packet = pcap.decode.packet(raw_packet);

The protocol stack is exposed as a nested set of objects.  For example, the TCP destination port is part of TCP
which is encapsulated within IP, which is encapsulated within a link layer.  Access it like this:

    packet.link.ip.tcp.dport

This structure is easy to explore with `sys.inspect`.

### TCP Analysis

TCP can be analyzed by feeding the packets into a `TCP_tracker` and then listening for `start` and `end` events.

    var pcap = require('pcap'),
        tcp_tracker = new pcap.TCP_tracker(),
        pcap_session = pcap.createSession(interface, "ip proto \tcp");

    tcp_tracker.on('start', function (session) {
        console.log("Start of TCP session between " + session.src_name + " and " + session.dst_name);
    });

    tcp_tracker.on('end', function (session) {
        console.log("End of TCP session between " + session.src_name + " and " + session.dst_name);
    });

    pcap_session.on('packet', function (raw_packet) {
        var packet = pcap.decode.packet(raw_packet);
        tcp_tracker.track_packet(packet);
    });

You must only send IPv4 TCP packets to the TCP tracker.  Explore the `session` object with `sys.inspect` to
see the wonderful things it can do for you.  Hopefully the names of the properties are self-explanatory:

    { src: '10.51.2.130:55965'
    , dst: '75.119.207.0:80'
    , syn_time: 1280425738896.771
    , state: 'ESTAB'
    , key: '10.51.2.130:55965-75.119.207.0:80'
    , send_isn: 2869922608
    , send_window_scale: 8
    , send_packets: { '2869922609': 1280425738896.771 }
    , send_acks: { '1063203923': 1280425738911.618 }
    , send_retrans: {}
    , send_next_seq: 2869922609
    , send_acked_seq: null
    , send_bytes_ip: 60
    , send_bytes_tcp: 108
    , send_bytes_payload: 144
    , recv_isn: 1063203922
    , recv_window_scale: 128
    , recv_packets: { '1063203923': 1280425738911.536 }
    , recv_acks: { '2869922609': 1280425738911.536 }
    , recv_retrans: {}
    , recv_next_seq: null
    , recv_acked_seq: null
    , recv_bytes_ip: 20
    , recv_bytes_tcp: 40
    , recv_bytes_payload: 0
    , src_name: '10.51.2.130:55965'
    , dst_name: '75.119.207.0:80'
    , current_cap_time: 1280425738911.65

### HTTP Analysis

The `TCP_tracker` also detects and decodes HTTP on all streams it receives.  If HTTP is detected, several
new events will be emitted: 

* `http_request`: function(session, http)
* `http_request_body`: function(session, http, data)

    Note that `data` is a node Buffer object sliced from the original packet.  If you want to use it past the
    current tick, you'll need to make a copy somehow.

* `http_request_complete`: function(session, http)
* `http_response`: function(session, http)
* `http_response_body`: function(session, http, data)

    `data` is a Buffer slice.  See above.

* `http_response_complete`: function(session, http)

See `examples/http_trace` for an example of how to use these events to decode HTTP.

### WebSocket Analysis

The `TCP_tracker` further detects and decodes WebSocket traffic on all streams it receives.

* `websocket_upgrade`: function(session, http)
* `websocket_message`: function(session, dir, message)

See `examples/http_trace` for an example of how to use these events to decode WebSocket.

    
## Some Common Problems

### TCP Segmentation Offload - TSO

TSO is a technique that modern operating systems use to offload the burden of IP/TCP header computation to 
the network hardware.  It also reduces the number of times that data is moved data between the kernel and the
network hardware.  TSO saves CPU when sending data that is larger than a single IP packet.

This is amazing and wonderful, but it does make some kinds of packet sniffing more difficult.  In many cases,
it is important to see the exact packets that are sent, but if the network hardware is sending the packets, 
these are not available to `libpcap`.  The solution is to disable TSO.

OSX:

    sudo sysctl -w net.inet.tcp.tso=0
    
Linux (substitute correct interface name):

    sudo ethtool -K eth0 tso off

The symptoms of needing to disable TSO are messages like, "Received ACK for packet we didn't see get sent".

### IPv6

Sadly, `node_pcap` does not know how to decode IPv6 packets yet.  Often when capturing traffic to `localhost`, IPv6 traffic
will arrive surprisingly, even though you were expecting IPv4.  A common case is the hostname `localhost`, which many client programs will
resolve to the IPv6 address `::1` and then will try `127.0.0.1`.  Until we get IPv6 decode support, a `libpcap` filter can be
set to only see IPv4 traffic:

    sudo http_trace lo0 "ip proto \tcp"
    
The backslash is important.  The pcap filter language has an ambiguity with the word "tcp", so by escaping it,
you'll get the correct interpretation for this case.

### Dropped packets

There are several levels of buffering involved in capturing packets.  Sometimes these buffers fill up, and
you'll drop packets.  If this happens, it becomes difficult to reconstruct higher level protocols.  The best
way to keep the buffers from filling up is to use pcap filters to only consider traffic that you need to decode.
The pcap filters are very efficient and run close to the kernel where they can process high packet rates.

If the pcap filters are set correctly and `libpcap` still drops packets, it is possible to increase `libpcap`'s
buffer size.  At the moment, this requires changing `pcap_binding.cc`.  Look for `pcap_set_buffer_size()` and
set to a larger value.

## examples/http_trace

This is a handy standalone program that can help diagnose HTTP and WebSocket traffic.

The TCP tracker looks for HTTP at the beginning of every TCP connection.  If found, all captured on this connection
will be fed to node's HTTP parser and events will be generated.  `http_trace` has listeners for these events and will
print out some helpful information.

If a WebSocket upgrade is detected, `http_trace` will start looking for WebSocket messages on that connection.

![http_trace screenshot](http://ranney.com/httptrace.jpg)


## examples/simple_capture

This program captures packets and prints them using the built in simple printer.  Here's a sample of it's output.
In another window I ran `curl nodejs.org`.

    mjr:~/work/node_pcap$ sudo node examples/simple_capture.js en1 ""
    libpcap version 1.0.0
    en0 no address
    * en1 10.240.0.133/255.255.255.0
    lo0 127.0.0.1/255.0.0.0
    00:18:39:ff:f9:1c -> 00:1f:5b:ce:3e:29 10.240.0.1 ARP request 10.240.0.133
    00:1f:5b:ce:3e:29 -> 00:18:39:ff:f9:1c 10.240.0.133 ARP reply 10.240.0.1 hwaddr 00:18:39:ff:f9:1c
    00:1f:5b:ce:3e:29 -> 00:18:39:ff:f9:1c 10.240.0.133:53808 -> 97.107.132.72:80 TCP len 64
    00:1f:5b:ce:3e:29 -> 00:18:39:ff:f9:1c 10.240.0.133:57052 -> 10.240.0.1:53 DNS question 133.0.240.10.in-addr.arpa PTR
    00:1f:5b:ce:3e:29 -> 00:18:39:ff:f9:1c 10.240.0.133:57052 -> 10.240.0.1:53 DNS question 72.132.107.97.in-addr.arpa PTR
    00:1f:5b:ce:3e:29 -> 00:18:39:ff:f9:1c 10.240.0.133:57052 -> 10.240.0.1:53 DNS question 1.0.240.10.in-addr.arpa PTR
    00:18:39:ff:f9:1c -> 00:1f:5b:ce:3e:29 10.240.0.1:53 -> 10.240.0.133:57052 DNS answer 133.0.240.10.in-addr.arpa PTR
    00:18:39:ff:f9:1c -> 00:1f:5b:ce:3e:29 10.240.0.1:53 -> rv-mjr2.ranney.com:57052 DNS answer 72.132.107.97.in-addr.arpa PTR
    00:18:39:ff:f9:1c -> 00:1f:5b:ce:3e:29 10.240.0.1:53 -> rv-mjr2.ranney.com:57052 DNS answer 1.0.240.10.in-addr.arpa PTR
    00:18:39:ff:f9:1c -> 00:1f:5b:ce:3e:29 tinyclouds.org:80 -> rv-mjr2.ranney.com:53808 TCP len 60
    00:1f:5b:ce:3e:29 -> 00:18:39:ff:f9:1c rv-mjr2.ranney.com:53808 -> tinyclouds.org:80 TCP len 52
    00:1f:5b:ce:3e:29 -> 00:18:39:ff:f9:1c rv-mjr2.ranney.com:53808 -> tinyclouds.org:80 TCP len 196
    00:18:39:ff:f9:1c -> 00:1f:5b:ce:3e:29 tinyclouds.org:80 -> rv-mjr2.ranney.com:53808 TCP len 52
    00:18:39:ff:f9:1c -> 00:1f:5b:ce:3e:29 tinyclouds.org:80 -> rv-mjr2.ranney.com:53808 TCP len 1500
    00:18:39:ff:f9:1c -> 00:1f:5b:ce:3e:29 tinyclouds.org:80 -> rv-mjr2.ranney.com:53808 TCP len 1500
    00:1f:5b:ce:3e:29 -> 00:18:39:ff:f9:1c rv-mjr2.ranney.com:53808 -> tinyclouds.org:80 TCP len 52
    00:18:39:ff:f9:1c -> 00:1f:5b:ce:3e:29 tinyclouds.org:80 -> rv-mjr2.ranney.com:53808 TCP len 1500
    00:1f:5b:ce:3e:29 -> 00:18:39:ff:f9:1c rv-mjr2.ranney.com:53808 -> tinyclouds.org:80 TCP len 52
    00:18:39:ff:f9:1c -> 00:1f:5b:ce:3e:29 tinyclouds.org:80 -> rv-mjr2.ranney.com:53808 TCP len 1500
    00:18:39:ff:f9:1c -> 00:1f:5b:ce:3e:29 tinyclouds.org:80 -> rv-mjr2.ranney.com:53808 TCP len 1500
    00:1f:5b:ce:3e:29 -> 00:18:39:ff:f9:1c rv-mjr2.ranney.com:53808 -> tinyclouds.org:80 TCP len 52
    00:18:39:ff:f9:1c -> 00:1f:5b:ce:3e:29 tinyclouds.org:80 -> rv-mjr2.ranney.com:53808 TCP len 1500
    00:1f:5b:ce:3e:29 -> 00:18:39:ff:f9:1c rv-mjr2.ranney.com:53808 -> tinyclouds.org:80 TCP len 52
    00:18:39:ff:f9:1c -> 00:1f:5b:ce:3e:29 tinyclouds.org:80 -> rv-mjr2.ranney.com:53808 TCP len 1500
    00:18:39:ff:f9:1c -> 00:1f:5b:ce:3e:29 tinyclouds.org:80 -> rv-mjr2.ranney.com:53808 TCP len 337
    00:1f:5b:ce:3e:29 -> 00:18:39:ff:f9:1c rv-mjr2.ranney.com:53808 -> tinyclouds.org:80 TCP len 52
    00:1f:5b:ce:3e:29 -> 00:18:39:ff:f9:1c rv-mjr2.ranney.com:53808 -> tinyclouds.org:80 TCP len 52
    00:1f:5b:ce:3e:29 -> 00:18:39:ff:f9:1c rv-mjr2.ranney.com:53808 -> tinyclouds.org:80 TCP len 52
    00:18:39:ff:f9:1c -> 00:1f:5b:ce:3e:29 tinyclouds.org:80 -> rv-mjr2.ranney.com:53808 TCP len 52
    00:1f:5b:ce:3e:29 -> 00:18:39:ff:f9:1c rv-mjr2.ranney.com:53808 -> tinyclouds.org:80 TCP len 52


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


### Deep decode of `curl nodejs.org`:

Running `sys.inspect` on the first three decoded packets of this TCP session.

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

## Help Wanted

I want to build up decoders and printers for all popular protocols.  Patches are welcome.


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

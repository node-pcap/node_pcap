node_pcap
=========

This is a set of bindings from `libpcap` to node as well as some useful libraries to decode, print, and
analyze packets.  `libpcap` is a packet capture library used by programs like `tcpdump` and `wireshark`.
It has been tested on OSX and Linux.

Sadly, `node_pcap` is _not done_ yet.  While it is incomplete, it is still already useful for capturing
and manipulating packets in JavaScript.

## Why?

There are already many tools for capturing, decoding, and analyzing packets.  Many of them are thoroughly
tested and very fast.  Why would anybody want to capture and manipulate packets in JavaScript?  A few reasons:

* JavaScript makes writing event-based programs very natural.  Each packet that is captured generates an
event, and as higher level protocols are decoded, they might generate events as well.  Writing code to handle
these events is much easier and more readable with anonymous functions and closures.

* node makes handling binary data in JavaScript fast and efficient with its Buffer class.  Decoding packets involves
a lot of binary slicing and dicing which can be awkward with JavaScript strings.

* Writing servers that capture packets, process them somehow, and then serve the processed data up in some way is
very straightforward in node.

## Help Wanted

I want to build up decoders and printers for all popular protocols.  I'm already working on HTTP, DNS,
and 802.11 "monitor" mode.  If you want to write a decoder or printer for another protocol, let me know,
or just send me a patch.

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

To start a pcap session:

    var pcap = require('./pcap'),
        pcap_session = pcap.createSession(interface, filter);

`interface` is the name of the interface on which to capture packets.  If passed an empty string, `libpcap`
will try to pick a "default" interface, which is often just the first one in some list.

`fitler` is a pcap filter expression, see `pcap-filter(7)` for more information.  An empty string will capture
all packets visible on the interface.

`pcap_session` is an `EventEmitter` that emits a `packet` event.  The only argument to the callback will be a
`Buffer` object with the raw bytes returned by `libpcap`.

Listening for packets:

    pcap_session.addListener('packet', function (raw_packet) {
        // do some stuff with a raw packet
    });

To convert the raw packet into a JavaScript object that is easy to work with, decode it:
    
    var packet = pcap.decode.packet(raw_packet);

The protocol stack is exposed as a nested set of objects.  For example, the TCP destination port is part of TCP
which is encapsulated within IP, which is encapsulated within a link layer.  Access it like this:

    packet.link.ip.tcp.dport

This structure is easy to explore with `sys.inspect`.


Note that `node_pcap` always opens the interface in promiscuous mode, which generally requires running as root.
Unless you are root already, you'll probably want to start your node program like this:

    sudo node test.js

## examples/http_trace

This is a handy standalone program that can help diagnose HTTP traffic.

The TCP tracker looks for HTTP at the beginning of every TCP connection.  If found, all captured on this connection
will be fed to node's HTTP parser and events will be generated.  `http_trace` has listeners for these events and will
print out some helpful information.

![http_trace screenshot](http://ranney.com/httptrace.jpg)


## examples/simple_capture

This program captures packets and prints them as best it can.  Here's a sample of it's output.
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

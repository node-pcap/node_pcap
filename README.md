##Disclaimer
node_pcap is currently being heavily refactored much of the documentation is out of date. If you installed node_pcap from npm go to [v2.0.1](https://github.com/mranney/node_pcap/commit/6e4d56671c54e0cf690f72b92554a538244bd1b6). Thanks for your patience and contributions as we work on the next major version of node_pcap.

node_pcap
=========

[![Join the chat at https://gitter.im/mranney/node_pcap](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/mranney/node_pcap?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Build Status](https://travis-ci.org/mranney/node_pcap.svg?branch=master)](https://travis-ci.org/mranney/node_pcap)[![Coverage Status](https://coveralls.io/repos/mranney/node_pcap/badge.svg)](https://coveralls.io/r/mranney/node_pcap)

This is a set of bindings from `libpcap` to node as well as some useful libraries to decode, print, and
analyze packets.  `libpcap` is a packet capture library used by programs like `tcpdump` and `wireshark`.
It has been tested on OSX and Linux.

`node_pcap` is useful for many things, but it does not yet understand all common protocols.  Common reasons
to use this package are
[http_trace](https://github.com/mranney/http_trace) (works only on node 4), and
[htracr](https://github.com/mnot/htracr).

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
    node-gyp configure build

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

`filter` is a pcap filter expression, see `pcap-filter(7)` for more information.  An empty string will capture
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

TCP can be analyzed by feeding the packets into a `TCPTracker` and then listening for `session` and `end` events.

```javascript
var pcap = require('./pcap'),
    tcp_tracker = new pcap.TCPTracker(),
    pcap_session = pcap.createSession('en0', "ip proto \\tcp");

tcp_tracker.on('session', function (session) {
  console.log("Start of session between " + session.src_name + " and " + session.dst_name);
  session.on('end', function (session) {
      console.log("End of TCP session between " + session.src_name + " and " + session.dst_name);
  });
});

pcap_session.on('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet);
    tcp_tracker.track_packet(packet);
});
```

You must only send IPv4 TCP packets to the TCP tracker.  Explore the `session` object with `sys.inspect` to
see the wonderful things it can do for you.  Hopefully the names of the properties are self-explanatory:

See [http_trace](https://github.com/mranney/http_trace) for an example of how to use these events to decode HTTP (Works only on node 4).

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

## Examples

[redis_trace](https://github.com/mranney/redis_trace)

[http_trace](https://github.com/mranney/http_trace) (Node 4 only)

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

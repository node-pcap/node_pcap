node-pcap
=========

[![npm version badge](https://img.shields.io/npm/v/pcap2.svg)](https://www.npmjs.org/package/pcap2)

This is a set of bindings from `libpcap` to node as well as some useful libraries to decode, print, and
analyze packets.  `libpcap` is a packet capture library used by programs like `tcpdump` and `wireshark`.
It has been tested on OSX and Linux.

`node-pcap` is useful for many things, but it does not yet understand all common protocols.  Common reasons
to use this package are
[http_trace](https://github.com/mranney/http_trace), and
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

The easiest way to get `node-pcap` and its tools is with `npm`:

```shell
npm install pcap2
```

If you want to hack on the source code, you can get it from github.  Clone the repo like this:

```shell
git clone git://github.com/andygreenegrass/node-pcap.git
```

To compile the native code bindings, do this:

```shell
cd node-pcap
node-gyp configure build
```

Assuming it built without errors, you should be able to run the examples and then write your own packet
capture programs.


## Usage

There are several example programs that show how to use `node-pcap`.  These examples are best documentation.
Try them out and see what they do.

To use this library in your own program, `index.js` and `pcap_binding.node` must be in `NODE_PATH`.  `npm`
takes care of this automatically.

### Starting a capture session

To start a capture session, create a new `pcap.Session` object with an interface name and desired options:

```javascript
var pcap = require('pcap2'),
    pcapSession = new pcap.Session(interface, options);
```

`interface` is the name of the interface on which to capture packets.  If passed an empty string, `libpcap`
will try to pick a "default" interface, which is often just the first one in some list and not what you want.

Note that `node-pcap` always opens the interface in promiscuous mode, which generally requires running as root.
Unless you are recklessly roaming about as root already, you'll probably want to start your node program like this:

```shell
sudo node test.js
```

`pcap.Session` is an `EventEmitter` that emits a `packet` event.  The only argument to the callback will be a
`Buffer` object with the raw bytes returned by `libpcap`.

Listening for packets:

```js
pcapSession.on('packet', function (rawPacket) {
    // do some stuff with a raw packet
});
```

To convert `rawPacket` into a JavaScript object that is easy to work with, decode it:

```js
var packet = pcap.decode.packet(rawPacket);
```

The protocol stack is exposed as a nested set of objects.  For example, the TCP destination port is part of TCP
which is encapsulated within IP, which is encapsulated within a link layer.  Access it like this:

    packet.link.ip.tcp.dport

This structure is easy to explore with `sys.inspect`.

### TCP Analysis

TCP can be analyzed by feeding the packets into a `TCPTracker` and then listening for `session` and `end` events.

```js
var pcap = require('pcap2'),
    tcpTracker = new pcap.TCPTracker(),
    pcapSession = new pcap.Session('en0', {
        filter: 'ip proto \\tcp'
    });

tcpTracker.on('session', function (session) {
  console.log('Start of session between ' + session.src_name + ' and ' + session.dst_name);
  session.on('end', function (session) {
      console.log('End of TCP session between ' + session.src_name + ' and ' + session.dst_name);
  });
});

pcapSession.on('packet', function (rawPacket) {
    var packet = pcap.decode.packet(rawPacket);
    tcpTracker.track_packet(packet);
});
```

You must only send IPv4 TCP packets to the TCP tracker.  Explore the `session` object with `sys.inspect` to
see the wonderful things it can do for you.  Hopefully the names of the properties are self-explanatory:

## Some Common Problems

### TCP Segmentation Offload - TSO

TSO is a technique that modern operating systems use to offload the burden of IP/TCP header computation to
the network hardware.  It also reduces the number of times that data is moved data between the kernel and the
network hardware.  TSO saves CPU when sending data that is larger than a single IP packet.

This is amazing and wonderful, but it does make some kinds of packet sniffing more difficult.  In many cases,
it is important to see the exact packets that are sent, but if the network hardware is sending the packets,
these are not available to `libpcap`.  The solution is to disable TSO.

OSX:

```shell
sudo sysctl -w net.inet.tcp.tso=0
```

Linux (substitute correct interface name):

```shell
sudo ethtool -K eth0 tso off
```

The symptoms of needing to disable TSO are messages like, "Received ACK for packet we didn't see get sent".

### IPv6

Sadly, `node-pcap` does not know how to decode IPv6 packets yet.  Often when capturing traffic to `localhost`, IPv6 traffic
will arrive surprisingly, even though you were expecting IPv4.  A common case is the hostname `localhost`, which many client programs will
resolve to the IPv6 address `::1` and then will try `127.0.0.1`.  Until we get IPv6 decode support, a `libpcap` filter can be
set to only see IPv4 traffic:

```shell
sudo http_trace lo0 "ip proto \tcp"
```

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

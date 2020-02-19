**Disclaimer:**
There's been some API changes between v2 and v3; the `createSession` and `createOfflineSession` arguments
now accept an `options` object. Also, if you're capturing on monitor wifi interfaces, the Radiotap
header now has different fields.

---

node_pcap
=========

[![Join the chat at https://gitter.im/mranney/node_pcap](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/mranney/node_pcap?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Build Status](https://travis-ci.org/node-pcap/node_pcap.svg?branch=master)](https://travis-ci.org/node-pcap/node_pcap)[![Coverage Status](https://coveralls.io/repos/mranney/node_pcap/badge.svg)](https://coveralls.io/r/mranney/node_pcap)

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

    git clone git://github.com/node-pcap/node_pcap.git

To compile the native code bindings, do this:

    cd node_pcap
    node-gyp configure build

Assuming it built without errors, you should be able to run the examples and then write your own packet
capture programs.


## Usage

There are several example programs that show how to use `node_pcap`.  These examples are best documentation.
Try them out and see what they do.

### Starting a capture session

To start a capture session, call `pcap.createSession` with an interface name and a pcap filter string:

```javascript
var pcap = require('pcap'),
    pcap_session = pcap.createSession(device_name, options);
```

`device_name` is the name of the network interface on which to capture packets.  If passed an empty string, `libpcap`
will try to pick a "default" interface, which is often just the first one in some list and not what you want.

The `options` object accepts the following properties:

 - `filter` (string) is a pcap filter expression, see `pcap-filter(7)` for more information. (default: no filter,
   all packets visible on the interface will be captured)

 - `promiscuous` (boolean) specifies if the interface is opened in promiscuous mode (default: true)

   > On broadcast LANs such as Ethernet, if the network isn't switched, or if the adapter is connected to a "mirror port" on a switch to which all packets passing through the switch are sent, a network adapter receives all packets on the LAN, including unicast or multicast packets not sent to a network address that the network adapter isn't configured to recognize.
   > 
   > Normally, the adapter will discard those packets; however, many network adapters support "promiscuous mode", which is a mode in which all packets, even if they are not sent to an address that the adapter recognizes, are provided to the host. This is useful for passively capturing traffic between two or more other hosts for analysis.
   > 
   > Note that even if an application does not set promiscuous mode, the adapter could well be in promiscuous mode for some other reason.
   > 
   > For now, this doesn't work on the "any" device; if an argument of "any" or NULL is supplied, the setting of promiscuous mode is ignored.

 - `buffer_size` (number) specifies size of the ringbuffer where packets are stored until delivered to your code, in bytes (default: 10MB)

   > Packets that arrive for a capture are stored in a buffer, so that they do not have to be read by the application as soon as they arrive. On some platforms, the buffer's size can be set; a size that's too small could mean that, if too many packets are being captured and the snapshot length doesn't limit the amount of data that's buffered, packets could be dropped if the buffer fills up before the application can read packets from it, while a size that's too large could use more non-pageable operating system memory than is necessary to prevent packets from being dropped.

 - `buffer_timeout` (number) specifies the packet buffer timeout in milliseconds (default: 1000)

   > If, when capturing, packets are delivered as soon as they arrive, the application capturing the packets will be woken up for each packet as it arrives, and might have to make one or more calls to the operating system to fetch each packet.
   >
   > If, instead, packets are not delivered as soon as they arrive, but are delivered after a short delay (called a "packet buffer timeout"), more than one packet can be accumulated before the packets are delivered, so that a single wakeup would be done for multiple packets, and each set of calls made to the operating system would supply multiple packets, rather than a single packet. This reduces the per-packet CPU overhead if packets are arriving at a high rate, increasing the number of packets per second that can be captured.
   >
   > The packet buffer timeout is required so that an application won't wait for the operating system's capture buffer to fill up before packets are delivered; if packets are arriving slowly, that wait could take an arbitrarily long period of time.
   >
   > Not all platforms support a packet buffer timeout; on platforms that don't, the packet buffer timeout is ignored. A zero value for the timeout, on platforms that support a packet buffer timeout, will cause a read to wait forever to allow enough packets to arrive, with no timeout. A negative value is invalid; the result of setting the timeout to a negative value is unpredictable.
   >
   > **NOTE:** the packet buffer timeout cannot be used to cause calls that read packets to return within a limited period of time, because, on some platforms, the packet buffer timeout isn't supported, and, on other platforms, the timer doesn't start until at least one packet arrives. This means that the packet buffer timeout should **NOT** be used, for example, in an interactive application to allow the packet capture loop to 'poll' for user input periodically, as there's no guarantee that a call reading packets will return after the timeout expires even if no packets have arrived.

   If set to zero or negative, then instead immediate mode is enabled:

   > In immediate mode, packets are always delivered as soon as they arrive, with no buffering.

 - `monitor` (boolean) specifies if monitor mode is enabled (default: false)

   > On IEEE 802.11 wireless LANs, even if an adapter is in promiscuous mode, it will supply to the host only frames for the network with which it's associated. It might also supply only data frames, not management or control frames, and might not provide the 802.11 header or radio information pseudo-header for those frames.
   >
   > In "monitor mode", sometimes also called "rfmon mode" (for "Radio Frequency MONitor"), the adapter will supply all frames that it receives, with 802.11 headers, and might supply a pseudo-header with radio information about the frame as well.
   >
   > Note that in monitor mode the adapter might disassociate from the network with which it's associated, so that you will not be able to use any wireless networks with that adapter. This could prevent accessing files on a network server, or resolving host names or network addresses, if you are capturing in monitor mode and are not connected to another network with another adapter.

 - `snap_length` (number) specifies the snapshot length in bytes (default: 65535)

   > If, when capturing, you capture the entire contents of the packet, that requires more CPU time to copy the packet to your application, more disk and possibly network bandwidth to write the packet data to a file, and more disk space to save the packet. If you don't need the entire contents of the packet - for example, if you are only interested in the TCP headers of packets - you can set the "snapshot length" for the capture to an appropriate value. If the snapshot length is set to snaplen, and snaplen is less than the size of a packet that is captured, only the first snaplen bytes of that packet will be captured and provided as packet data.
   >
   > A snapshot length of 65535 should be sufficient, on most if not all networks, to capture all the data available from the packet.


Note that by default `node_pcap` opens the interface in promiscuous mode, which generally requires running as root.
Unless you are recklessly roaming about as root already, you'll probably want to start your node program like this:

    sudo node test.js

### Listening for packets

`pcap_session` is an `EventEmitter` that emits a `packet` event.  The only argument to the callback will be a
`PacketWithHeader` object containing the raw bytes returned by `libpcap`:

```javascript
pcap_session.on('packet', function (raw_packet) {
    // do some stuff with a raw packet
});
```

This `raw_packet` contains `buf` and `header` (`Buffer`s) and `link_type`.

To convert `raw_packet` into a JavaScript object that is easy to work with, decode it:

```javascript
var packet = pcap.decode.packet(raw_packet);
```

The protocol stack is exposed as a nested set of objects.  For example, the TCP destination port is part of TCP
which is encapsulated within IP, which is encapsulated within a link layer.  Each layer is contained within the
`payload` attribute of the upper layer (or the packet itself):

```javascript
packet.payload.payload.payload.dport
```

This structure is easy to explore with `util.inspect`.

However, if you decide to parse `raw_packet.buf` yourself, make sure to truncate it to the first `caplen` bytes first.

### TCP Analysis

TCP can be analyzed by feeding the packets into a `TCPTracker` and then listening for `session` and `end` events.

```javascript
var pcap = require('pcap'),
    tcp_tracker = new pcap.TCPTracker(),
    pcap_session = pcap.createSession('en0', { filter: "ip proto \\tcp" });

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

### Other operations

To know the format of the link-layer headers, use `pcap_session.link_type` or `raw_packet.link_type`.
The property is a `LINKTYPE_<...>` string, see [this list](https://www.tcpdump.org/linktypes.html).

To get current capture statistics, use `pcap_session.stats()`. This returns an object with the following properties:

 - `ps_recv`: number of packets received
 - `ps_ifdrop`: number of packets dropped by the network interface or its driver
 - `ps_drop`: number of packets dropped because there was no room in the operating system's buffer when they arrived, because packets weren't being read fast enough

For more info, see [`pcap_stats`](https://www.tcpdump.org/manpages/pcap_stats.3pcap.html).

If you no longer need to receive packets, you can use `pcap_session.close()`.

To read packets from a file instead of from a live interface, use `createOfflineSession` instead:

```javascript
pcap.createOfflineSession('/path/to/capture.pcap', options);
```

Where `options` only accepts the `filter` property.

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

### Handling warnings

libpcap may sometimes emit warnings (for instance, when an interface has no address). By default these
are printed to the console, but you can override the warning handler with your own function:

```js
pcap.warningHandler = function (text) {
    // ...
}
```

## Examples

[redis_trace](https://github.com/mranney/redis_trace)

[http_trace](https://github.com/mranney/http_trace) (Node 4 only)

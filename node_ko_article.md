# Capturing Packets in JavaScript

OK, I hear you.  Capturing packets is hard and best left to kernel hackers, assembly language programmers,
and black hat security researches.  If you just want to make things for the web using node.js, why should you 
care?

Pulling packets off the network can show you what your computers are saying to each other without disrupting
the flow of or changing any applications.  Packet capture is a fantastic debugging tool that will remove a lot
of the mystery from writing and running network programs.  The point of `node_pcap` is to provide a good HTTP
debugging tool and a framework for doing your own network analysis.

There are plenty of ways to do packet inspection these days, but none of them let you interact with your
network traffic the way that node lets you write network programs: by writing a few event handlers in
JavaScript.  `node_pcap` not only
let's you capture and process packets in JavaScript, but since it is built on node.js, data from the packets
can be easily routed around to web browsers, databases, or whatever else you can think of.

Here's an example of capturing packets and sending them back to a web browser using WebSocket:

[http://pcap.ranney.com:81/](http://pcap.ranney.com:81/ "Packet Capture WebSocket demo")

If you still aren't convinced, check out how easy it is to write a simple "network grep" type of program using
`node_pcap`:

<script src="http://gist.github.com/548175.js?file=network_grep.js"></script>

This program will look at all TCP packets that flow past the default network interface and run the regular
expression `matcher` against the data section of the packet.  If it matches, the data section will be printed.

Still not convinced?  I understand.  This packet business can be astonishingly low level compared to the abstractions
you are comfortable working with.  If this doesn't seem awesome yet, it probably won't until you actually need it.
When you can't figure out what your program is doing by just adding log messages, come back and check out what
packet capture can do for you.

`node_pcap` exposes packets as JavaScript objects, but it also comes with a few examples that are useful on their
own.  If you do nothing else, check out `http_trace` and `simple_capture`.  Look at the source
code and see how they work.  It's really easy.


## Installation

Anyway, if you are still here, let's get this sucker installed.  The first thing you'll need is `libpcap`.
If you are on OSX 10.6, you already have it.  If you are on a Linux system that uses `apt-get` to install 
things, you can get it like this:

    sudo apt-get install libpcap-dev
    
If you are on some other kind of system, I don't know the exact command to install `libpcap-dev`,
but it is a very common library that's widely available.

Once you have `libpcap` and node, you just need `npm`.  Install `node_pcap` with `npm` like this:

    npm install pcap
    
This will install the pcap libraries and three executable.

If you want to hack on the code, and I encourage you to do so, use `git` to clone the repository on github:

    git clone git://github.com/mranney/node_pcap.git
    
You'll still need to use `npm` to build and install the files where they need to go:

    mjr:~/work/node_pcap$ npm install .

To verify that things are working, run:

    sudo simple_capture
    
It should look something like this:

    mjr:~$ sudo simple_capture
    libpcap version 1.0.0
    * en0 10.51.2.125/255.255.255.0
    fw0 no address
    en1 no address
    lo0 127.0.0.1/255.0.0.0
    00:1c:23:b9:e8:b5 -> ff:ff:ff:ff:ff:ff 10.51.2.10 ARP request 10.51.2.4
    00:1e:c9:45:e8:30 -> ff:ff:ff:ff:ff:ff 10.51.2.1 ARP request 10.51.2.45
    00:1a:92:c4:32:d1 -> ff:ff:ff:ff:ff:ff 10.51.2.179 ARP request 10.51.2.126

Your traffic might not be ARP requests, but some packets should be flowing, and you should see one line per packet.

Opening the capture interface on most operating systems requires root access, so most of the time that you run a
program using `node_pcap` you'll need to use sudo.


## http_trace

`http_trace` is a tool that distills the packets involved in an HTTP session into higher level events.  There
are command line options to adjust the output and select different requests.  Here's a simple example of looking
for any requests that have "favicon" in the URL and showing request and response headers:

![pcap screenshot](http://pcap.ranney.com/http_trace_1.jpg)

To see the full list of options do:

    http_trace --help
    
With no arguments, `http_trace` will listen on the default interface for any IPv4 TCP traffic on any port.
If it finds HTTP on any TCP connection, it'll start decoding it.  You might be surprised by how many HTTP
connections your computer is making that you didn't know about, especially if you run OSX.  Fire it up and
see what you find.

### Solving Problems

Here's why you need all of this.  Let's say you have a node program that makes an outgoing connection, but
the outgoing connection doesn't seem like it is working.  This reason in this case is that a
firewall rule is filtering the traffic.  Here's how to detect it:

![pcap screenshot](http://pcap.ranney.com/http_trace_2.jpg)

The `--tcp-verbose` option will expose events for TCP connection setup, close, and reset.  It'll also let you 
know about SYN retries and packets retransmissions.  SYN retry happens when a new TCP connection is getting set
up, but the other side isn't responding.
Retransmissions occur when packets are dropped by the network, and TCP on either end of the connection resends data
that has already sent.  If data is moving slowly, but you don't appear to be out of CPU, turn on 
`--tcp-verbose` and see if you are getting retransmissions or SYN retries.  If so, you can blame the network and
not your node program.

Another common case is when the data going over the network isn't quite the data you were expecting.  Here's a 
simple example using curl from the command line.  Let's say you wanted to send some JSON to your local CouchDB,
but CouchDB keeps rejecting it.

    mjr:~$ curl -X POST 'http://localhost:5984/test' -H "Content-Type: application/json" -d {"foo": "bar"}
    {"error":"bad_request","reason":"invalid UTF-8 JSON"}

That looks like pretty well-formed JSON, so what's going on here?  Run `http_trace` with the --bodies option
to dump the request and response body.  Since this is a connection to `localhost`, we need to explicitly listen
on the loopback interface.

![pcap screenshot](http://pcap.ranney.com/http_trace_3.jpg)

Here we can see that the request body was simply, "{foo:", which is clearly not valid JSON.  The problem in 
this case is that the shell and curl couldn't figure out what part of the command line arguments to use for
the POST body, and they got it wrong.  This works if quoted properly:

    mjr:~$ curl -X POST 'http://localhost:5984/test' -H "Content-Type: application/json" -d '{"foo": "bar"}'
    {"ok":true,"id":"b4385e0de2e74df4cdbf21cf6c0009d0","rev":"1-4c6114c65e295552ab1019e2b046b10e"}


## Understanding Higher Level Protocols

`node_pcap` can piece back together a TCP session from individual packets as long as it sees them all go by.
It will emit events at TCP connection setup, teardown, and reset.

On top of TCP, it can decode HTTP and WebSocket messages, emitting events for request, response, upgrade, data, etc.

It looks sort of like this:

![pcap architecture](http://pcap.ranney.com/pcap_boxes.png)

You set up `node_pcap` to capture the packets you want, and then you can work with the captured data in
JavaScript at whatever level is the most useful.

## Work in Progress

There are a lot of cases that `node_pcap` doesn't handle, and for these you'll need a more complete packet decoder
like Wireshark.  I'm trying to handle the common case of OSX/Linux, IPv4, TCP, HTTP, and WebSocket first, and then
add support for other variants of the protocol stack.

If you like this kind of stuff and want to help expand the protocols that `node_pcap` understands, patches are
certainly welcome.

I hope this software is useful and fun.  Thanks for reading.

# Capturing Packets in JavaScript

OK, I hear you.  Capturing packets is hard and best left to kernel hackers, assembly language programmers,
and black hat security researches.  If you want to make things for the web using node.js, why should you care?
Pulling packets off the network can show you what your computers are saying to each other without disrupting
the flow of the applications.  Packet capture is a fantastic debugging tool that will remove a lot of the 
mystery from writing and running network programs.

There are plenty of ways to do packet inspection these days, but none of them let you interact with them the
way node lets you write network programs: by writing a few event handlers in JavaScript.  node_pcap not only
let's you capture and process packets in JavaScript, but since it is built on node.js, data from the packets
can be easily routed around to web browsers, databases, or whatever else you can think of.

If you still aren't convinced, check out how easy it is to write a simple "network grep" type of program using
node_pcap:

<script src="http://gist.github.com/548175.js?file=network_grep.js"></script>

This program will look at all TCP packets that flow past the default network interface, and run the regular
expression `matcher` against the data section of the packet.  If it matches, the data section will be printed.

Still not convinced?  I understand.  This packet business is all astonishingly low level compared to the abstractions
you are comfortable working with.  If this doesn't seem awesome yet, it probably won't until you actually need it.
When you can't figure out what your program is doing by just adding log messages, come back and check out what
packet capture can do for you.

node_pcap exposes packets as JavaScript objects, but it also comes with a few examples that are useful on their
own.  If you do nothing else, check out `examples/http_trace` and `examples/simple_capture`.  Look at the source
code and see what they can do.

## Installation

Anyway, if you are still here, let's get this sucker installed.  The first thing you'll need is `libpcap`.
If you are on OSX 10.6, you already have it.  If you are on a Linux system that uses `apt-get` to install 
things, you can get it like this:

    sudo apt-get install libpcap-dev
    
If you are on some other kind of system, I don't know the exact command to install `libpcap-dev`,
but it is a very common library that's widely available.

Once you have `libpcap`, you'll obviously need `node`.  To install `node_pcap`, you need `npm`.
Install `node_pcap` like this:

    npm install pcap
    
This will install the pcap libraries and three executable.

If you want to hack on the code, and I encourage you to do so, use git to clone the repository on github:

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


## Understanding HTTP

The world is increasingly made out of HTTP.  


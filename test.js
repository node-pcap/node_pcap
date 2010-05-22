"use strict";
/*global process require exports */

var sys = require("sys"),
    pcap = require("./pcap"),
    count = 0,
    start_time = new Date(),
    session = pcap.createSession("", "port 80");

sys.puts("All devices: ");
sys.puts(sys.inspect(session.findalldevs(), false, 4));

session.addListener('packet', function (pcap_header, raw_packet) {
    var p = pcap.decode_packet(pcap_header, raw_packet);
    if (p.ip && p.tcp) {
        sys.puts(p.ip.saddr + ":" + p.tcp.sport + " > " + p.ip.daddr + ":" + p.tcp.dport + " length " + pcap_header.len);
    }
    else {
        sys.puts(sys.inspect(p));
    }
});

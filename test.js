"use strict";
/*global process require exports */

var sys = require("sys"),
    pcap = require("./pcap"),
    count = 0,
    start_time = new Date(),
    pcap_session = pcap.createSession("en1", "tcp"),
    dns_cache = pcap.dns_cache,
    tcp_tracker = pcap.tcp_tracker;

sys.puts("All devices: ");
sys.puts(sys.inspect(pcap_session.findalldevs(), false, 4));

pcap_session.addListener('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet),
        link = packet.ethernet,
        ip, tcp;

    if (link && link.ip) {
        ip = link.ip;
        if (ip.tcp) {
            tcp = ip.tcp;
            sys.puts(dns_cache.ptr(ip.saddr) + ":" + tcp.sport + " > " + 
                dns_cache.ptr(ip.daddr) + ":" + tcp.dport + " TCP length " + raw_packet.pcap_header.len);
            tcp_tracker.track(packet);
        } else {
            sys.puts(dns_cache.ptr(ip.saddr) + " > " + dns_cache.ptr(ip.daddr) + 
                " " + ip.protocol_name + " length " + raw_packet.pcap_header.len);
        }
    } else {
        sys.puts("Non IP: " + sys.inspect(p));
    }
    sys.puts(sys.inspect(pcap_session.stats()));
});

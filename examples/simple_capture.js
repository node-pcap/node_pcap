"use strict";
/*global process require exports */

var sys = require("sys"),
    pcap = require("../pcap"), pcap_session;

if (process.argv.length !== 4) {
    throw new Error("usage: " + process.argv[1] + " interface filter");
}

pcap_session = pcap.createSession(process.argv[2], process.argv[3]);

// Print all devices, currently listening device prefixed with an asterisk
pcap_session.findalldevs().forEach(function (dev) {
    if (pcap_session.device_name === dev.name) {
        sys.print("* ");
    }
    sys.print(dev.name + " ");
    if (dev.addresses.length > 0) {
        dev.addresses.forEach(function (address) {
            sys.print(address.addr + "/" + address.netmask);
        });
        sys.print("\n");
    } else {
        sys.print("no address\n");
    }
});

// listen for packets, decode them, and feed the simple printer
pcap_session.addListener('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet);
    sys.puts(pcap.print_oneline(packet));
});

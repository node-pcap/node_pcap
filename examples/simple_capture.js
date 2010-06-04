"use strict";
/*global process require exports */

var sys = require("sys"),
    pcap = require("../pcap"), pcap_session;
    
if (process.argv.length !== 4) {
    sys.error("usage: " + process.argv[1] + " interface filter");
    sys.error("Examples: ");
    sys.error('  sudo node simple_capture.js en0 "tcp port 80"');
    sys.error('  sudo node simple_capture.js eth1 ""');
    sys.error('  sudo node simple_capture.js lo0 "ip proto \\tcp and tcp port 80"');
    process.exit(1);
}

pcap_session = pcap.createSession(process.argv[2], process.argv[3]);

// libpcap's internal version numnber
sys.puts(pcap.lib_version);

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
    sys.puts(pcap.print.packet(packet));
});

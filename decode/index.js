// convert binary capture data into objects with friendly names

exports.EthernetPacket = require("./ethernet_packet");
exports.IPv4Packet = require("./ipv4");
exports.IPv6Packet = require("./ipv6");
exports.ArpPacket = require("./arp");
exports.PcapPacket = require("./pcap_packet");
var PcapPacket = exports.PcapPacket;

function decode(packet, emitter, logger) {
    if (typeof logger === "undefined") {
        logger = console;
    }
    return new PcapPacket(emitter, logger).decode(packet);
}

exports.decode = decode;
exports.decode.packet = decode;

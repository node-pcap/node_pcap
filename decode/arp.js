var EthernetAddr = require("./ethernet_addr");
var IPv4Addr = require("./ipv4_addr");

function Arp() {
    this.htype = null;
    this.ptype = null;
    this.heln = null;
    this.plen = null;
    this.operation = null;
    this.sender_ha = null;
    this.sender_pa = null;
    this.target_ha = null;
    this.target_pa = null;
}

// http://en.wikipedia.org/wiki/Address_Resolution_Protocol
Arp.prototype.decode = function (raw_packet, offset) {
    this.htype = raw_packet.readUInt16BE(offset);
    this.ptype = raw_packet.readUInt16BE(offset + 2);
    this.hlen = raw_packet[offset + 4];
    this.plen = raw_packet[offset + 5];
    this.operation = raw_packet.readUInt16BE(offset + 6); // 6, 7
    if (this.hlen === 6 && this.plen === 4) { // ethernet + IPv4
        this.sender_ha = new EthernetAddr(raw_packet, offset + 8); // 8, 9, 10, 11, 12, 13
        this.sender_pa = new IPv4Addr(raw_packet, offset + 14); // 14, 15, 16, 17
        this.target_ha = new EthernetAddr(raw_packet, offset + 18); // 18, 19, 20, 21, 22, 23
        this.target_pa = new IPv4Addr(raw_packet, offset + 24); // 24, 25, 26, 27
    }
    // don't know how to decode more exotic ARP types yet, but please add them

    return this;
};

Arp.prototype.toString = function () {
    var ret = "";
    if (this.operation === 1) {
        ret += "request";
    } else if (this.operation === 2) {
        ret += "reply";
    } else {
        ret += "unknown";
    }

    if (this.sender_ha && this.sender_pa) {
        ret += " sender " + this.sender_ha + " " + this.sender_pa + " target " + this.target_ha +
            " " + this.target_pa;
    }

    return ret;
};

module.exports = Arp;
var hex = require("../lib/util").int8_to_hex;

function IPv6Addr() {
    this.addr = new Array(16);
}

IPv6Addr.prototype.decode = function decode(raw_packet, offset) {
    this.addr[0]  = raw_packet[offset + 0];
    this.addr[1]  = raw_packet[offset + 1];
    this.addr[2]  = raw_packet[offset + 2];
    this.addr[3]  = raw_packet[offset + 3];
    this.addr[4]  = raw_packet[offset + 4];
    this.addr[5]  = raw_packet[offset + 5];
    this.addr[6]  = raw_packet[offset + 6];
    this.addr[7]  = raw_packet[offset + 7];
    this.addr[8]  = raw_packet[offset + 8];
    this.addr[9]  = raw_packet[offset + 9];
    this.addr[10] = raw_packet[offset + 10];
    this.addr[11] = raw_packet[offset + 11];
    this.addr[12] = raw_packet[offset + 12];
    this.addr[13] = raw_packet[offset + 13];
    this.addr[14] = raw_packet[offset + 14];
    this.addr[15] = raw_packet[offset + 15];

    return this;
};

IPv6Addr.prototype.decoderName = "ipv6-addr";
IPv6Addr.prototype.eventsOnDecode = false;

IPv6Addr.prototype.toString = function () {
    //There are some rules one can follow to
    //shorten the string representation of an
    //ipv6 address, but the long hand version
    //is both simple and valid.

    return hex[this.addr[0]] + hex[this.addr[1]] + ":" + hex[this.addr[2]] + hex[this.addr[3]] + ":" +
           hex[this.addr[4]] + hex[this.addr[5]] + ":" + hex[this.addr[6]] + hex[this.addr[7]] + ":" +
           hex[this.addr[8]] + hex[this.addr[9]] + ":" + hex[this.addr[10]] + hex[this.addr[11]] + ":" +
           hex[this.addr[12]] + hex[this.addr[13]] + ":" + hex[this.addr[14]] + hex[this.addr[15]];
};

module.exports = IPv6Addr;

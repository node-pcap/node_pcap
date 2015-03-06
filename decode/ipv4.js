var ICMP = require("./icmp");
var IGMP = require("./igmp");
var TCP = require("./tcp");
var UDP = require("./udp");
var IPv6 = require("./ipv6");
var IPv4Addr = require("./ipv4_addr");

function IPFlags() {
    this.reserved = null;
    this.df = null;
    this.mf = null;
}

IPFlags.prototype.toString = function () {
    var ret = "[";
    if (this.reserved) {
        ret += "r";
    }
    if (this.df) {
        ret += "d";
    }
    if (this.mf) {
        ret += "m";
    }
    ret += "]";
    return ret;
};

function IPv4() {
    this.version = null;
    this.header_length = null;
    this.header_bytes = null; // not part of packet, but handy
    this.diffserv = null;
    this.total_length = null;
    this.identification = null;
    this.flags = new IPFlags();
    this.fragment_offset = null;
    this.ttl = null;
    this.protocol = null;
    this.header_checksum = null;
    this.saddr = null;
    this.daddr = null;
    this.protocol_name = null;
    this.payload = null;
}

// http://en.wikipedia.org/wiki/IPv4
IPv4.prototype.decode = function (raw_packet, offset) {
    var orig_offset = offset;

    this.version = (raw_packet[offset] & 240) >> 4; // first 4 bits
    this.header_length = raw_packet[offset] & 15; // second 4 bits
    this.header_bytes = this.header_length * 4;
    offset += 1;
    this.diffserv = raw_packet[offset];
    offset += 1;
    this.total_length = raw_packet.readUInt16BE(offset, true);
    offset += 2;
    this.identification = raw_packet.readUInt16BE(offset, true);
    offset += 2;
    this.flags.reserved = (raw_packet[offset] & 128) >> 7;
    this.flags.df = (raw_packet[offset] & 64) >> 6;
    this.flags.mf = (raw_packet[offset] & 32) >> 5;
    this.fragment_offset = ((raw_packet[offset] & 31) * 256) + raw_packet[offset + 1]; // 13-bits from 6, 7
    offset += 2;
    this.ttl = raw_packet[offset];
    offset += 1;
    this.protocol = raw_packet[offset];
    offset += 1;
    this.header_checksum = raw_packet.readUInt16BE(offset, true);
    offset += 2;
    this.saddr = new IPv4Addr.decode(raw_packet, offset);
    offset += 4;
    this.daddr = new IPv4Addr.decode(raw_packet, offset);
    offset += 4;

    // TODO - parse IP "options" if header_length > 5

    offset = orig_offset + (this.header_length * 4);

    switch (this.protocol) {
    case 1:
        this.payload = new ICMP();
        this.payload.decode(raw_packet, offset);
        break;
    case 2:
        this.payload = new IGMP().decode(raw_packet, offset);
        break;
    case 4:
        this.payload = new IPv4().decode(raw_packet, offset);
        break;
    case 6:
        this.payload = new TCP().decode(raw_packet, offset, this.total_length - this.header_bytes);
        break;
    case 17:
        this.payload = new UDP().decode(raw_packet, offset);
        break;
    case 41:
        this.payload = new IPv6().decode(raw_packet, offset);
        break;
    default:
        this.protocol_name = "Unknown";
    }

    return this;
};

IPv4.prototype.toString = function () {
    var ret = this.saddr + " -> " + this.daddr;
    var flags = this.flags.toString();
    if (flags.length > 2) {
        ret += " flags " + flags;
    }

    switch (this.protocol) {
    case 1:
        ret += " ICMP";
        break;
    case 2:
        ret += " IGMP";
        break;
    case 4:
        ret += " IPv4_in_IPv4"; // IPv4 encapsulation, RFC2003
        break;
    case 6:
        ret += " TCP";
        break;
    case 17:
        ret += " UDP";
        break;
    case 41:
        ret += " IPv6_in_IP4"; // IPv6 encapsulation, RFC2473
        break;
    default:
        ret += " proto " + this.protocol;
    }

    return ret + " " + this.payload;
};

module.exports = IPv4;

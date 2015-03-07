var ICMP = require("./icmp");
var IGMP = require("./igmp");
var TCP = require("./tcp");
var UDP = require("./udp");
var IPv6 = require("./ipv6");
var IPv4Addr = require("./ipv4_addr");

function IPFlags() {
    this.reserved = undefined;
    this.doNotFragment = undefined;
    this.moreFragments = undefined;
}

IPFlags.prototype.decode = function (raw_flags) {
    this.reserved = Boolean((raw_flags & 0x80) >> 7);
    this.doNotFragment = Boolean((raw_flags & 0x40) > 0);
    this.moreFragments = Boolean((raw_flags & 0x20) > 0);
    return this;
};

IPFlags.prototype.toString = function () {
    var ret = "[";
    if (this.reserved) {
        ret += "r";
    }
    if (this.doNotFragment) {
        ret += "d";
    }
    if (this.moreFragments) {
        ret += "m";
    }
    ret += "]";
    return ret;
};

function IPv4() {
    this.version = undefined;
    this.headerLength = undefined;
    this.diffserv = undefined;
    this.length = undefined;
    this.identification = undefined;
    this.flags = undefined;
    this.fragmentOffset = undefined;
    this.ttl = undefined;
    this.protocol = undefined;
    this.headerChecksum = undefined;
    this.saddr = undefined;
    this.daddr = undefined;
    this.protocolName = undefined;
    this.payload = undefined;
}

// http://en.wikipedia.org/wiki/IPv4
IPv4.prototype.decode = function (raw_packet, offset) {
    var orig_offset = offset;

    this.version = (raw_packet[offset] & 0xf0) >> 4;
    this.headerLength = (raw_packet[offset] & 0x0f) << 2;
    offset += 1;

    this.diffserv = raw_packet[offset];
    offset += 1;

    this.length = raw_packet.readUInt16BE(offset, true);
    offset += 2;

    this.identification = raw_packet.readUInt16BE(offset, true);
    offset += 2;

    this.flags = new IPFlags().decode(raw_packet[offset]);
    // flags only uses the top 3 bits of offset so don't advance yet
    this.fragmentOffset = ((raw_packet.readUInt16BE(offset) & 0x1fff) << 3); // 13-bits from 6, 7
    offset += 2;

    this.ttl = raw_packet[offset];
    offset += 1;

    this.protocol = raw_packet[offset];
    offset += 1;

    this.headerChecksum = raw_packet.readUInt16BE(offset, true);
    offset += 2;

    this.saddr = new IPv4Addr().decode(raw_packet, offset);
    offset += 4;

    this.daddr = new IPv4Addr().decode(raw_packet, offset);
    offset += 4;

    // TODO - parse IP "options" if header_length > 5

    offset = orig_offset + this.headerLength;

    //https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
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
        this.payload = new TCP().decode(raw_packet, offset, this.length - this.headerLength);
        break;
    case 17:
        this.payload = new UDP().decode(raw_packet, offset);
        break;
    case 41:
        this.payload = new IPv6().decode(raw_packet, offset);
        break;
    default:
        this.protocolName = "Unknown";
    }

    return this;
};

IPv4.prototype.toString = function () {
    var ret = this.saddr + " -> " + this.daddr + " ";
    var flags = this.flags.toString();
    if (flags.length > 2) {
        ret += "flags " + flags + " ";
    }

    if(this.payload === undefined || this.payload === null ){
        ret += "proto " + this.protocol;
    } else {
        ret += this.payload.constructor.name;
    }
    

    return ret + " " + this.payload;
};

module.exports = IPv4;

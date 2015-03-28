var IPv4Addr = require("./ipv4_addr");
var protocols = require("./ip_protocols");


function IPFlags(emitter) {
    this.emitter = emitter;
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

function IPv4(emitter) {
    this.emitter = emitter; 
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

    this.saddr = new IPv4Addr(this.emitter).decode(raw_packet, offset);
    offset += 4;

    this.daddr = new IPv4Addr(this.emitter).decode(raw_packet, offset);
    offset += 4;

    // TODO - parse IP "options" if header_length > 5

    offset = orig_offset + this.headerLength;

    var ProtocolDecoder = protocols[this.protocol];
    if(ProtocolDecoder === undefined) {
        this.protocolName = "Unknown";
    } else {
        this.payload = new ProtocolDecoder(this.emitter).decode(raw_packet, offset, this.length - this.headerLength);
    }

    if(this.emitter) { this.emitter.emit("ipv4", this); }
    return this;
};

IPv4.prototype.decoderName = "ipv4";
IPv4.prototype.eventsOnDecode = true;

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

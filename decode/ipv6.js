var IPv6Addr = require("./ipv6_addr");
var protocols = require("./ip_protocols");

function IPv6() {
    this.version = undefined;
    this.trafficClass = undefined;
    this.flowLabel = undefined;
    this.payloadLength = undefined;
    this.nextHeader = undefined;
    this.hopLimit = undefined;
    this.saddr = undefined;
    this.daddr = undefined;
    this.payload = undefined;
}

IPv6.prototype.decode = function (raw_packet, offset) {
    // http://en.wikipedia.org/wiki/IPv6
    this.version = ((raw_packet[offset] & 0xf0) >> 4); // first 4 bits
    this.trafficClass = ((raw_packet[offset] & 0x0f) << 4) | ((raw_packet[offset+1] & 0xf0) >> 4);
    this.flowLabel = ((raw_packet[offset + 1] & 0x0f) << 16) +
        (raw_packet[offset + 2] << 8) +
        raw_packet[offset + 3];
    this.payloadLength = raw_packet.readUInt16BE(offset+4, true);
    this.nextHeader = raw_packet[offset+6];
    this.hopLimit = raw_packet[offset+7];
    this.saddr = new IPv6Addr().decode(raw_packet, offset+8);
    this.daddr = new IPv6Addr().decode(raw_packet, offset+24);

    /*
     http://tools.ietf.org/html/rfc2780
     * 5.3 IPv6 Next Header field
     *
     * The IPv6 Next Header field carries values from the same name space as
     * the IPv4 Protocol name space. 
    */
    var ProtocolDecoder = protocols[this.protocol];
    if(ProtocolDecoder === undefined) {
        this.protocolName = "Unknown";
    } else {
        this.payload = new ProtocolDecoder().decode(raw_packet, offset, this.length - this.headerLength);
    }
    return this;
};

IPv6.prototype.toString = function () {
    var ret = this.saddr + " -> " + this.daddr;

    if(this.payload === undefined || this.payload === null ){
        ret += "proto " + this.protocol;
    } else {
        ret += this.payload.constructor.name;
    }

    return ret + " " + this.payload;
};

module.exports = IPv6;

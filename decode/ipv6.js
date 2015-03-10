var ICMP = require("./icmp");
var IGMP = require("./igmp");
var TCP = require("./tcp");
var UDP = require("./udp");
var IPv4 = require("./ipv4");
var IPv6Addr = require("./ipv6_addr");

function IPv6Header() {

}

IPv6Header.prototype.decode = function (raw_packet, next_header, ip, offset) {
    switch (next_header) {
    case 1:
        ip.payload = new ICMP().decode(raw_packet, offset);
        break;
    case 2:
        ip.payload = new IGMP().decode(raw_packet, offset);
        break;
    case 4:
        ip.payload = new IPv4().decode(raw_packet, offset); // IPv4 encapsulation, RFC2003
        break;
    case 6:
        ip.payload = new TCP().decode(raw_packet, offset, ip);
        break;
    case 17:
        ip.payload = new UDP().decode(raw_packet, offset);
        break;
    case 41:
        ip.payload = new IPv6().decode(raw_packet, offset); // IPv6 encapsulation, RFC2473
        break;
    /* Please follow numbers and RFC in http://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#extension-header
     * Not all next protocols follow this rule (and we can have unsuported upper protocols here too).
     *  */
    case 0: //Hop-by-Hop
    case 60: //Destination Options
    case 43: //Routing
    case 135: //Mobility
    case 139: //Host Identity Protocol. //Discussion: rfc5201 support only No Next Header/trailing data, but future documents May do.
    case 140: //Shim6 Protocol
        new IPv6Header().decode(raw_packet, raw_packet[offset], ip, offset + 8*raw_packet[offset+1] + 8);
        break;
    case 51: //Authentication Header
        new IPv6Header().decode(raw_packet, raw_packet[offset], ip, offset + 4*raw_packet[offset+1] + 8);
        break;
    default:
        // 59 - No next Header, and unknowed upper layer protocols, do nothing.
    }
};

function IPv6() {
    this.version = undefined;
    this.trafficClass = undefined;
    this.flowLabel = undefined;
    this.payloadLength = undefined;
    this.nextHeader = undefined;
    this.hopLimit = undefined;
    this.saddr = undefined;
    this.daddr = undefined;
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

    new IPv6Header().decode(raw_packet, this.next_header, this, offset+40);
    return this;
};

IPv6.prototype.toString = function () {
    var ret = this.saddr + " -> " + this.daddr;

    switch (this.next_header) {
    case 1:
        ret += " ICMP";
        break;
    case 2:
        ret += " IGMP";
        break;
    case 4:
        ret += " IPv4_in_IPv6"; // IPv4 encapsulation, RFC2003
        break;
    case 6:
        ret += " TCP";
        break;
    case 17:
        ret += " UDP";
        break;
    case 41:
        ret += " IPv6_in_IPv6"; // IPv6 encapsulation, RFC2473
        break;
    default:
        ret += " proto " + this.next_header;
    }

    return ret + " " + this.payload;
};

module.exports = IPv6;

// Synthetic Link Layer used by Linux to support the "any" pseudo device
// http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html

var SLLAddr = require("./sll_addr");
var IPv4 = require("./ipv4");
var IPv6 = require("./ipv6");
var Arp = require("./arp");

function SLLPacket (emitter) {
    this.emitter = emitter;
    this.packet_type = null;
    this.address_type = null;
    this.address_len = null;
    this.address = null;
    this.ethertype = null;
    this.payload = null;
}

SLLPacket.prototype.decode = function (raw_packet, offset) {
    this.packet_type = raw_packet.readUInt16BE(offset);
    offset += 2;
    this.address_type = raw_packet.readUInt16BE(offset);
    offset += 2;
    this.address_len = raw_packet.readUInt16BE(offset);
    offset += 2;
    this.address = new SLLAddr(raw_packet, offset, this.address_len);
    offset += 8; // address uses 8 bytes in frame, but only address_len bytes are significant
    this.ethertype = raw_packet.readUInt16BE(offset);
    offset += 2;

    if (this.ethertype < 1536) {
        // this packet is actually some 802.3 type without an ethertype
        this.ethertype = 0;
    } else {
        // http://en.wikipedia.org/wiki/EtherType
        switch (this.ethertype) {
        case 0x800: // IPv4
            this.payload = new IPv4(this.emitter).decode(raw_packet, offset);
            break;
        case 0x806: // ARP
            this.payload = new Arp(this.emitter).decode(raw_packet, offset);
            break;
        case 0x86dd: // IPv6 - http://en.wikipedia.org/wiki/IPv6
            this.payload = new IPv6(this.emitter).decode(raw_packet, offset);
            break;
        case 0x88cc: // LLDP - http://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol
            this.payload = "need to implement LLDP";
            break;
        default:
            console.log("node_pcap: SLLPacket() - Don't know how to decode ethertype " + this.ethertype);
        }
    }

    return this;
};

SLLPacket.prototype.decoderName = "ssl-packet";
SLLPacket.prototype.eventsOnDecode = false;

SLLPacket.prototype.toString = function () {
    var ret = "";

    switch (this.packet_type) {
    case 0:
        ret += "recv_us";
        break;
    case 1:
        ret += "broadcast";
        break;
    case 2:
        ret += "multicast";
        break;
    case 3:
        ret += "remote_remote";
        break;
    case 4:
        ret += "sent_us";
        break;
    }

    ret += " addrtype " + this.address_type;

    ret += " " + this.address;

    switch (this.ethertype) {
    case 0x800:
        ret += " IPv4";
        break;
    case 0x806:
        ret += " ARP";
        break;
    case 0x86dd:
        ret += " IPv6";
        break;
    case 0x88cc:
        ret += " LLDP";
        break;
    default:
        ret += " ethertype " + this.ethertype;
    }

    return ret + " " + this.payload.toString();
};

module.exports = SLLPacket;

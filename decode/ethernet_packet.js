var EthernetAddr = require("./ethernet_addr");
var IPv4 = require("./ipv4");
var IPv6 = require("./ipv6");
var Arp = require("./arp");
var Vlan = require("./vlan");

function EthernetPacket(emitter) {
    this.emitter = emitter;
    this.dhost = null;
    this.shost = null;
    this.ethertype = null;
    this.vlan = null;
    this.payload = null;
}

EthernetPacket.prototype.decode = function (raw_packet, offset) {
    this.dhost = new EthernetAddr(raw_packet, offset);
    offset += 6;
    this.shost = new EthernetAddr(raw_packet, offset);
    offset += 6;
    this.ethertype = raw_packet.readUInt16BE(offset, true);
    offset += 2;

    if (this.ethertype === 0x8100) { // VLAN-tagged (802.1Q)
        this.vlan = new Vlan().decode(raw_packet, offset);
        offset += 2;

        // Update the ethertype
        this.ethertype = raw_packet.readUInt16BE(offset, true);
        offset += 2;
    }

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
            console.log("node_pcap: EthernetFrame() - Don't know how to decode ethertype " + this.ethertype);
        }
    }

    return this;
};

EthernetPacket.prototype.decoderName = "ethernet-packet";
EthernetPacket.prototype.eventsOnDecode = false;

EthernetPacket.prototype.toString = function () {
    var ret = this.shost + " -> " + this.dhost;
    if (this.vlan) {
        ret += " vlan " + this.vlan;
    }
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

module.exports = EthernetPacket;

var EthernetPacket = require("./ethernet_packet");
var NullPacket = require("./null_packet");
var RawPacket = require("./raw_packet");
var RadioPacket = require("./ieee802.11/radio_packet");
var SLLPacket = require("./sll_packet");

// Setting properties from the C++ side is very slow, so we send in a shared Buffer.
// The C++ side does this:
//   memcpy(session->header_data, &(pkthdr->ts.tv_sec), 4);
//   memcpy(session->header_data + 4, &(pkthdr->ts.tv_usec), 4);
//   memcpy(session->header_data + 8, &(pkthdr->caplen), 4);
//   memcpy(session->header_data + 12, &(pkthdr->len), 4);
// And here we unpack those 4 ints from the buffer.

function PcapHeader(raw_header) {
    this.tv_sec = raw_header.readUInt32LE(0, true);
    this.tv_usec = raw_header.readUInt32LE(4, true);
    this.caplen = raw_header.readUInt32LE(8, true);
    this.len = raw_header.readUInt32LE(12, true);
}

function PcapPacket() {
    this.link_type = null;
    this.pcap_header = null;
    this.payload = null;
}

PcapPacket.prototype.decode = function (packet_with_header) {
    this.link_type = packet_with_header.link_type;
    this.pcap_header = new PcapHeader(packet_with_header.header);

    var buf = packet_with_header.buf;

    switch (this.link_type) {
    case "LINKTYPE_ETHERNET":
        this.payload = new EthernetPacket().decode(buf, 0);
        break;
    case "LINKTYPE_NULL":
        this.payload = new NullPacket().decode(buf, 0);
        break;
    case "LINKTYPE_RAW":
        this.payload = new RawPacket().decode(buf, 0);
        break;
    case "LINKTYPE_IEEE802_11_RADIO":
        this.payload = new RadioPacket().decode(buf, 0);
        break;
    case "LINKTYPE_LINUX_SLL":
        this.payload = new SLLPacket().decode(buf, 0);
        break;
    default:
        console.log("node_pcap: PcapPacket.decode - Don't yet know how to decode link type " + this.link_type);
    }

    return this;
};

PcapPacket.prototype.toString = function () {
    return this.link_type + " " + this.payload;
};

module.exports = PcapPacket;

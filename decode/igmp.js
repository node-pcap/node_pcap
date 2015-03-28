var IPv4Addr = require("./ipv4_addr");

function IGMP(emitter) {
    this.emitter = emitter;
    this.type = undefined;
    this.version = undefined;
    this.maxResponseTime = undefined;
    this.checksum = undefined;
    this.groupAddress = undefined;
}

// http://en.wikipedia.org/wiki/Internet_Group_Management_Protocol
// This is an implementation of V3
// https://tools.ietf.org/html/rfc3376
IGMP.prototype.decode = function (raw_packet, offset) {
    this.type = raw_packet[offset];

    // units are 1/10s
    // if value < 128 this is an int, else it is a float
    // right now we don't handle the float version
    this.maxResponseTime =raw_packet[offset + 1];

    this.checksum = raw_packet.readUInt16BE(offset + 2); // 2, 3
    this.groupAddress = new IPv4Addr().decode(raw_packet, offset + 4); // 4, 5, 6, 7

    //Membership Query (0x11)
    //Membership Report (IGMPv1: 0x12, IGMPv2: 0x16, IGMPv3: 0x22)
    //Leave Group (0x17)
    switch (this.type) {
    case 0x11:
        this.version = 3;
        break;
    case 0x12:
        this.version = 1;
        break;
    case 0x16:
    case 0x17:
        this.version = 2;
        break;
    case 0x22:
        this.version = 3;
        break;
    }

    if(this.emitter) { this.emitter.emit("igmp", this); }
    return this;
};

IGMP.prototype.decoderName = "igmp";
IGMP.prototype.eventsOnDecode = true;

IGMP.prototype.toString = function () {
    var ret;

    switch (this.type) {
    case 0x11:
        ret = "Membership Query";
        break;
    case 0x12:
        ret = "Membership Report";
        break;
    case 0x16:
        ret = "Membership Report";
        break;
    case 0x17:
        ret = "Leave Group";
        break;
    case 0x22:
        ret = "Membership Report";
        // TODO: Decode v3 message
        break;
    default:
        ret = "type " + this.type;
        break;
    }

    return ret;
};

module.exports = IGMP;

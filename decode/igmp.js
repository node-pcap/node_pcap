function IGMP() {
    this.type = null;
    this.version = null;
    this.max_response_time = null;
    this.checksum = null;
    this.group_address = null;
}

var IPV4Addr = require("./ipv4_addr");

// http://en.wikipedia.org/wiki/Internet_Group_Management_Protocol
IGMP.prototype.decode = function (raw_packet, offset) {
    this.type = raw_packet[offset];
    this.max_response_time = raw_packet[offset + 1];
    this.checksum = raw_packet.readUInt16BE(offset + 2); // 2, 3
    this.group_address = new IPV4Addr(raw_packet, offset + 4); // 4, 5, 6, 7

    switch (this.type) {
    case 0x11:
        this.version = this.max_response_time > 0 ? 2 : 1;
        break;
    case 0x12:
        this.version = 1;
        break;
    case 0x16:
        this.version = 2;
        break;
    case 0x17:
        this.version = 2;
        break;
    case 0x22:
        this.version = 3;
        break;
    default:
        break;
    }

    return this;
};

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

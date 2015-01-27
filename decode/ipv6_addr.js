var map = require("../util").int8_to_hex_nopad;

function IPv6Addr() {
    this.o1 = null;
    this.o2 = null;
    this.o3 = null;
    this.o4 = null;
    this.o5 = null;
    this.o6 = null;
    this.o7 = null;
    this.o8 = null;
}

IPv6Addr.prototype.decode = function (raw_packet, offset) {
    this.o1 = raw_packet.readUInt16LE[offset];
    this.o2 = raw_packet.readUInt16LE[offset + 2];
    this.o3 = raw_packet.readUInt16LE[offset + 4];
    this.o4 = raw_packet.readUInt16LE[offset + 6];
    this.o5 = raw_packet.readUInt16LE[offset + 8];
    this.o6 = raw_packet.readUInt16LE[offset + 10];
    this.o7 = raw_packet.readUInt16LE[offset + 12];
    this.o8 = raw_packet.readUInt16LE[offset + 14];

    return this;
};

function format(num) {
    var p1 = (num & 0xff00) >> 8;
    var p2 = num & 0x00ff;
    if (p1 === 0) {
        return map[p2];
    } else {
        return map[p1] + map[p2];
    }
}

IPv6Addr.prototype.toString = function () {
    return format(this.o1) + ":" + format(this.o2) + ":" + format(this.o3) + ":" + format(this.o4) + ":" +
        format(this.o5) + ":" + format(this.o6) + ":" + format(this.o7) + ":" + format(this.o8);
};

module.exports = IPv6Addr;

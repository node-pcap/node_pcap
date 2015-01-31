var map = require("../util").int8_to_dec;

function IPv4Addr(raw_packet, offset) {
	this.o1	= raw_packet[offset];
	this.o2	= raw_packet[offset + 1];
	this.o3	= raw_packet[offset + 2];
	this.o4	= raw_packet[offset + 3];
}

// Don't use Array.prototype.join here, because string concat is much faster
IPv4Addr.prototype.toString = function () {
    return map[this.o1] + "." + map[this.o2] + "." + map[this.o3] + "." + map[this.o4];
};

module.exports = IPv4Addr;

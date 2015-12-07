var dec = require("../lib/util").int8_to_dec;

function IPv4Addr() {
	this.addr = new Array(4);
}

IPv4Addr.prototype.decode = function decode(raw_packet, offset) {
	this.addr[0] = raw_packet[offset];
	this.addr[1] = raw_packet[offset + 1];
	this.addr[2] = raw_packet[offset + 2];
	this.addr[3] = raw_packet[offset + 3];
	return this;
};

IPv4Addr.prototype.decoderName = "ipv4-addr";
IPv4Addr.prototype.eventsOnDecode = false;

// Don't use Array.prototype.join here, because string concat is much faster
IPv4Addr.prototype.toString = function () {
    return dec[this.addr[0]] + "." + dec[this.addr[1]] + "." + dec[this.addr[2]] + "." + dec[this.addr[3]];
};

module.exports = IPv4Addr;

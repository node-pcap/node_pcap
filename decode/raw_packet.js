var IPv4 = require("./ipv4");

function RawPacket(emitter) {
	this.emitter = emitter;
	this.payload = null;
}

RawPacket.prototype.decode = function (raw_packet, offset) {
	this.payload = new IPv4().decode(raw_packet, offset);
	return this;
};

module.exports = RawPacket;

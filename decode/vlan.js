function Vlan() {
	this.priority = null;
	this.canonical_format = null;
	this.id = null;
}

// http://en.wikipedia.org/wiki/IEEE_802.1Q
Vlan.prototype.decode = function (raw_packet, offset) {
    this.priority = (raw_packet[offset] & 0xE0) >> 5;
    this.canonical_format = (raw_packet[offset] & 0x10) >> 4;
    this.id = ((raw_packet[offset] & 0x0F) << 8) | raw_packet[offset + 1];

    return this;
};

Vlan.prototype.decoderName = "vlan";
Vlan.prototype.eventsOnDecode = false;

Vlan.prototype.toString = function () {
	return this.priority + " " + this.canonical_format + " " + this.id;
};

module.exports = Vlan;

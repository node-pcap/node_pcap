var IPv4 = require("./ipv4");

function LogicalLinkControl(emitter) {
    this.emitter = emitter;
    this.dsap = undefined;
    this.ssap = undefined;
    this.controlField = undefined;
    this.orgCode = undefined;
    this.type = undefined;
    this._error = undefined;
}

LogicalLinkControl.prototype.decode = function (raw_packet, offset) {
    this.dsap = raw_packet[offset++];
    this.ssap = raw_packet[offset++];

    // https://en.wikipedia.org/wiki/IEEE_802.2#LSAP_Values
    // http://tools.ietf.org/html/rfc1700
    // 0xaa is SNAP
    // 0x00 is NULL LSAP
    if (((this.dsap === 0xaa) && (this.ssap === 0xaa)) ||
        ((this.dsap === 0x00) && (this.ssap === 0x00))) {
        this.controlField = raw_packet[offset++];
        this.orgCode = [
            raw_packet[offset++],
            raw_packet[offset++],
            raw_packet[offset++]
        ];
        this.type = raw_packet.readUInt16BE(offset); offset += 2;

        switch (this.type) {
        case 0x0800: // IPv4
            this.payload = new IPv4(this.emitter).decode(raw_packet, offset);
            break;
        }
    } else {
        this._error = "Unknown LLC types: DSAP: " + this.dsap + ", SSAP: " + this.ssap;
    }

    if(this.emitter) { this.emitter.emit("llc", this); }
    return this;
};

LogicalLinkControl.prototype.decoderName = "llc";
LogicalLinkControl.prototype.eventsOnDecode = true;

module.exports = LogicalLinkControl;

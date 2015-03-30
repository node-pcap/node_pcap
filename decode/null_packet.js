var IPv4 = require("./ipv4");
var IPv6 = require("./ipv6");

function NullPacket(emitter) {
    this.emitter = emitter;
    this.pftype = undefined;
    this.payload = undefined;
    this._error = undefined;
}

// an oddity about nulltype is that it starts with a 4 byte header, but I can't find a
// way to tell which byte order is used.  The good news is that all address family
// values are 8 bits or less.
NullPacket.prototype.decode = function (raw_packet, offset) {
    if (raw_packet[offset] === 0 && raw_packet[offset + 1] === 0) { // must be one of the endians
        this.pftype = raw_packet[offset + 3];
    } else {                                          // and this is the other one
        this.pftype = raw_packet[offset];
    }

    if (this.pftype === 2) {         // AF_INET, at least on my Linux and OSX machines right now
        this.payload = new IPv4(this.emitter).decode(raw_packet, offset + 4);
    } else if (this.pftype === 30) { // AF_INET6, often
        this.payload = new IPv6(this.emitter).decode(raw_packet, offset + 4);
    } else {
        this._error = "unknown protocol family " + this.pftype;
    }

    return this;
};

NullPacket.prototype.decoderName = "null-packet";
NullPacket.prototype.eventsOnDecode = false;

NullPacket.prototype.toString = function () {
    return this.pftype + " " + this.payload;
};

module.exports = NullPacket;

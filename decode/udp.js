var DNS = require("./dns");

function UDP(emitter) {
    this.emitter = emitter;
    this.sport = undefined;
    this.dport = undefined;
    this.length = undefined;
    this.checksum = undefined;
    this.data = undefined;
}

// http://en.wikipedia.org/wiki/User_Datagram_Protocol
UDP.prototype.decode = function (raw_packet, offset) {
    this.sport = raw_packet.readUInt16BE(offset, true);
    offset += 2;
    this.dport = raw_packet.readUInt16BE(offset, true);
    offset += 2;
    this.length = raw_packet.readUInt16BE(offset, true);
    offset += 2;
    this.checksum = raw_packet.readUInt16BE(offset, true);
    offset += 2;

    this.data = raw_packet.slice(offset, offset + (this.length - 8));

    if(this.emitter) { this.emitter.emit("udp", this); }
    return this;
};

UDP.prototype.decoderName = "udp";
UDP.prototype.eventsOnDecode = true;

UDP.prototype.toString = function () {
    var ret = "UDP " + this.sport + "->" + this.dport + " len " + this.length;
    if (this.sport === 53 || this.dport === 53) {
        ret += (new DNS().decode(this.data, 0, this.data.length).toString());
    }
    return ret;
};

module.exports = UDP;

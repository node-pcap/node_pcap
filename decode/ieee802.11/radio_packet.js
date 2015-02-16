var RadioFrame = require("./radio_frame");

function RadioPacket() {

}

RadioPacket.prototype.decode = function (raw_packet, offset) {
    var ret = {};
    var original_offset = offset;

    ret.headerRevision = raw_packet[offset++];
    ret.headerPad = raw_packet[offset++];
    ret.headerLength = raw_packet.readUInt16LE(offset); offset += 2;

    //Preset Flags
    offset += 4;

    //MAC timestamp
    offset += 8;

    //Flags
    offset += 2;

    //Frequency
    ret.frequency = raw_packet.readUInt16LE(offset); offset += 2;

    //Channel type
    offset += 2;

    //SSI in DBI
    ret.strength = -256 + raw_packet[offset++];

    //Antenna
    ret.antenna = raw_packet[offset++];

    offset = original_offset + ret.headerLength;

    ret.ieee802_11Frame = new RadioFrame().decode(raw_packet, offset);

    if(ret.ieee802_11Frame && ret.ieee802_11Frame.llc && ret.ieee802_11Frame.llc.ip) {
        ret.ip = ret.ieee802_11Frame.llc.ip;
        delete ret.ieee802_11Frame.llc.ip;
        ret.shost = ret.ieee802_11Frame.shost;
        delete ret.ieee802_11Frame.shost;
        ret.dhost = ret.ieee802_11Frame.dhost;
        delete ret.ieee802_11Frame.dhost;
    }

    return ret;
};

module.exports = RadioPacket;

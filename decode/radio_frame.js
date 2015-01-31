function RadioFrame() {

}

RadioFrame.prototype.decode = function (raw_packet, offset) {
    var ret = {};

    ret.frameControl = unpack.uint16_be(raw_packet, offset); offset += 2;
    ret.type = (ret.frameControl >> 2) & 0x0003;
    ret.subType = (ret.frameControl >> 4) & 0x000f;
    ret.flags = (ret.frameControl >> 8) & 0xff;
    ret.duration = unpack.uint16_be(raw_packet, offset); offset += 2;
    ret.bssid = unpack.ethernet_addr(raw_packet, offset); offset += 6;
    ret.shost = unpack.ethernet_addr(raw_packet, offset); offset += 6;
    ret.dhost = unpack.ethernet_addr(raw_packet, offset); offset += 6;
    ret.fragSeq = unpack.uint16_be(raw_packet, offset); offset += 2;

    var strength = raw_packet[22];
    ret.strength = -Math.abs(265 - strength);


    switch(ret.subType) {
        case 8: // QoS Data
            ret.qosPriority = raw_packet[offset++];
            ret.txop = raw_packet[offset++];
            break;
    }

    if (ret.type == 2 && ret.subType == 4) {
        // skip this is Null function (No data)
    } else if (ret.type == 2 && ret.subType == 12) {
        // skip this is QoS Null function (No data)
    } else if (ret.type == 2 && ret.subType == 7) {
        // skip this is CF-Ack/Poll
    } else if (ret.type == 2 && ret.subType == 6) {
        // skip this is CF-Poll (No data)
    } else if (ret.type == 2) { // data
        ret.llc = decode.logicalLinkControl(raw_packet, offset);
    }

    return ret;
};

module.exports = RadioFrame;

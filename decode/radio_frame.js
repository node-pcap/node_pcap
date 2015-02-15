var EthernetAddr = require('./ethernet_addr');
var LogicalLinkControl = require('./llc_packet');
var RadioBeaconFrame = require('./radio_beacon_frame');
function RadioFrame() {

}

RadioFrame.prototype.decode = function (raw_packet, offset) {
    var ret = {};
    ret.frameControl = raw_packet.readUInt16LE(offset, true); offset += 2;
    ret.version = ret.frameControl & 0x0003;
    ret.type = (ret.frameControl >> 2) & 0x0003;
    ret.subType = (ret.frameControl >> 4) & 0x000f;
    var flags = (ret.frameControl >> 8) & 0xff;
    ret.flags = { raw:flags };
    ret.flags.moreFragments = Boolean((flags >> 2) & 0x0001);
    ret.flags.isRetry = Boolean((flags >> 3) & 0x0001);
    ret.flags.moreData = Boolean((flags >> 5) & 0x0001);
    ret.flags.encrypted = Boolean((flags >> 6) & 0x0001);
    ret.flags.ordered = Boolean((flags >> 7) & 0x0001);

    ret.duration = raw_packet.readUInt16BE(offset, true); offset += 2;
    ret.bssid = new EthernetAddr(raw_packet, offset); offset += 6;
    ret.shost = new EthernetAddr(raw_packet, offset); offset += 6;
    ret.dhost = new EthernetAddr(raw_packet, offset); offset += 6;
    ret.fragSeq = raw_packet.readUInt16BE(offset, true); offset += 2;

    if (ret.type == 0) {
        if(ret.subType == 8) { // Beacon
            var beacon = new RadioBeaconFrame();
            ret.beacon = beacon.decode(raw_packet, offset);
        }
    } else if (ret.type == 1) { //Control Frame

    } else if (ret.type == 2) { // Data Frame
        if (ret.flags.encrypted) {
            //Just skip encrypted data for now.
        } else if (ret.subType != 36) { // subType 36 is a null data frame
            ret.llc = new LogicalLinkControl().decode(raw_packet, offset);
        }
    }

    return ret;
};

module.exports = RadioFrame;

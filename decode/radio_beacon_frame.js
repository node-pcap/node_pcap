function RadioBeaconFrame () {
}

RadioBeaconFrame.prototype.decode = function (raw_packet, offset) {
    var ret = {};
    //first 8 bytes a time stamp
    offset += 8;

    //2 bytes of defining the beacon interval
    offset +=2;

    //2 bytes of misc compatibility info
    offset +=2;

    /*
     * knowing where the end of the packet is
     * would be really useful here. However,
     * since we don't have it at the moment
     * let's just try to read the ssid tag.
     *
     * When we get the packet length,
     * turn this into a loop and read all
     * the tags.
     */
    ret.tags = [];
    var tag = {};

    //tag id
    tag.typeId = raw_packet[offset++];

    //tag value length
    tag.length = raw_packet[offset++];

    if(tag.typeId == 0) {
        tag.type == 'ssid';

        //tag value
        tag.ssid = raw_packet.toString('utf8', offset, offset + tag.length);
    }
    ret.tags.push(tag);
    return ret;
};

module.exports = RadioBeaconFrame;
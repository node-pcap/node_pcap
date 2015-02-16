var RadioManagementFrameTag = require('./radio_management_frame_tag');
function RadioBeaconFrame () {
    this.tags = [];
}

RadioBeaconFrame.prototype.decode = function decode(raw_packet, offset) {
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
    var tag = new RadioManagementFrameTag().decode(raw_packet, offset);
    if (tag.typeId != undefined) {
        this.tags.push(tag);
        offset += tag.length + 2;
    }
    return this;
};

module.exports = RadioBeaconFrame;
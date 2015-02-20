var RadioManagementFrameTag = require("./radio_management_frame_tag");
function RadioProbeFrame () {
    this.tags = [];
}

RadioProbeFrame.prototype.decode = function decode(raw_packet, offset) {
    var tag;
    //This overlaps with beacons, extract it.
    // Tags are at least 2 bytes long
    // and there is 4 bytes following
    // the list of tags.
    while(raw_packet.length - offset >= 6) {
        tag = new RadioManagementFrameTag().decode(raw_packet, offset);
        if (tag.typeId !== undefined && tag.typeId !== null) {
            this.tags.push(tag);
            offset += tag.length + 2;
        }
    }
    return this;
};

module.exports = RadioProbeFrame;
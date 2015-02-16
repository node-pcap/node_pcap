var RadioManagementFrameTag = require('./radio_management_frame_tag');
function RadioProbeFrame () {
    this.tags = [];
}

RadioProbeFrame.prototype.decode = function decode(raw_packet, offset) {
    //This overlaps with beacons, extract it.
    var tag = new RadioManagementFrameTag().decode(raw_packet, offset);
    if (tag.typeId != undefined) {
        this.tags.push(tag);
        offset += tag.length + 2;
    }
    return this;
};

module.exports = RadioProbeFrame;
var radioUtils = require("./radio_utils");
function RadioProbeFrame () {
    this.tags = undefined;
}

RadioProbeFrame.prototype.decode = function decode(raw_packet, offset) {
    this.tags = radioUtils.parseTags(raw_packet, offset);
    return this;
};

module.exports = RadioProbeFrame;
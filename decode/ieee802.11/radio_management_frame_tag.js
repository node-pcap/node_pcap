function RadioMangementFrameTag () {
    this.type = undefined;
    this.typeId = undefined;
    this.length = undefined;
}

RadioMangementFrameTag.prototype.decode = function decode(raw_packet, offset) {
      //tag id
    this.typeId = raw_packet[offset++];

    //tag value length
    this.length = raw_packet[offset++];

    if(this.typeId == 0) {
        this.type = 'ssid';

        //tag value
        this.ssid = raw_packet.toString('utf8', offset, offset + this.length);
    }
    return this;
};

module.exports = RadioMangementFrameTag;
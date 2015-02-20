function RadioMangementFrameTag () {
    this.type = undefined;
    this.typeId = undefined;
    this.length = undefined;
    this.value = undefined;
}

RadioMangementFrameTag.prototype.decode = function decode(raw_packet, offset) {
    //tag id
    this.typeId = raw_packet[offset++];

    //tag value length
    this.length = raw_packet[offset++];

    this.value = raw_packet.slice(offset, offset + this.length);

    switch(this.typeId) {
    case 0:
        this.type = "ssid";
        this.ssid = this.value.toString("utf8", 0, this.length);
        break;
    case 1:
        this.type = "rates";
        break;
    case 3:
        this.type = "channel";
        this.channel = raw_packet[offset];
        break;
    case 5:
        this.type = "TIM"; //Traffic Indicator Map
        break;
    case 42:
        this.type = "ERP"; //Extended Rates PHY
        break;
    case 48:
        this.type = "RSN"; //Robust Security Network
        break;
    case 50:
        this.type = "extended_rates";
        break;
    case 221:
        this.type = "vendor_specific";
        break;
    default:
        this.type = "unknown";
        break;
    }
    return this;
};

module.exports = RadioMangementFrameTag;
function DHCP(emitter) {
    this.emitter = emitter;
    this.messageType = undefined;
    this.hardwareType = undefined;
    this.hardwareAddressLen = undefined;
    this.hops = undefined;
    this.transactionId = undefined;
    this.secondsElapsed = undefined;
    this.broadcastFlag = undefined;
}

DHCP.prototype.decode = function (raw_packet, offset) {
    this.messageType = raw_packet.readUInt8(raw_packet, offset); // 0
    this.hardwareType = raw_packet.readUInt8(raw_packet, offset + 1); // 1
    this.hardwareAddressLen = raw_packet.readUInt8(raw_packet, offset + 2); // 2
    this.hops = raw_packet.readUInt8(raw_packet, offset + 3); // 3
    this.transactionId = raw_packet.readUInt32BE(raw_packet, offset + 4); // 4, 5, 6, 7 - use big endian
    this.secondsElapsed = raw_packet.readUInt16BE(raw_packet, offset + 8); // 8, 9
    this.broadcastFlag = (raw_packet[offset + 10] & 0x8) >> 3; // 10, first bit, ignore others because they are unused

};
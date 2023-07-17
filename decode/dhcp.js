var IPv4Addr = require("./ipv4_addr");

function DHCP(emitter) {
    this.emitter = emitter;
    this.messageType = undefined;
    this.hardwareType = undefined;
    this.hardwareAddressLen = undefined;
    this.hops = undefined;
    this.transactionId = undefined;
    this.secondsElapsed = undefined;
    this.broadcastFlag = undefined;
    this.clientIp = undefined;
    this.yourIp = undefined;
    this.nextServerIp = undefined;
    this.nextRelayAgentIp = undefined;
    this.clientMac = undefined;
    this.serverHostName = undefined;
    // skip file here
    // TODO: flags with optional length
}

// TODO: test
DHCP.prototype.decode = function (raw_packet, offset) {
    this.messageType = raw_packet.readUInt8(offset); // 0
    this.hardwareType = raw_packet.readUInt8(offset + 1); // 1
    this.hardwareAddressLen = raw_packet.readUInt8(offset + 2); // 2
    this.hops = raw_packet.readUInt8(offset + 3); // 3
    this.transactionId = raw_packet.readUInt32BE(offset + 4); // 4, 5, 6, 7 - use big endian
    this.secondsElapsed = raw_packet.readUInt16BE(offset + 8); // 8, 9
    this.broadcastFlag = (raw_packet[offset + 10] & 0x80) >> 7; // 10, first bit, ignore others because they are unused
    this.clientIp = new IPv4Addr().decode(raw_packet, offset + 12); // 12, 13, 14, 15
    this.yourIp = new IPv4Addr().decode(raw_packet, offset + 16); // 16, 17, 18, 19
    this.nextServerIp = new IPv4Addr().decode(raw_packet, offset + 20); // 20, 21, 22, 23
    this.nextRelayAgentIp = new IPv4Addr().decode(raw_packet, offset + 24); // 24, 25, 26, 27
    this.clientMac = undefined;
    this.serverHostName = undefined;
    return this;
};

module.exports = DHCP;
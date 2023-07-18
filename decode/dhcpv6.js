//let IPv6Addr = require("./ipv6_addr");
//let EthernetAddr = require("./ethernet_addr");

function DHCPv6(emitter) {
    this.emitter = emitter;
    this.messageType = undefined;
    this.messageTypeDecoded = undefined;
    this.transactionId = undefined;
    this.options_raw = undefined;
}

// see: https://support.huawei.com/enterprise/en/doc/EDOC1000174110/ab96f0e8/dhcpv6-packets
const messageTypes = {
    1: "SOLICIT (DHCP DISCOVER)",
    2: "ADVERTISE (DHCP OFFER)",
    3: "REQUEST (DHCP REQUEST)",
    4: "CONFIRM (no DHCPv4 pendant)",
    5: "RENEW (DHCP REQUEST)",
    6: "REBIND (DHCP REQUEST)",
    7: "REPLY (DHCP ACK/NAK)",
    8: "RELEASE (DHCP RELEASE)",
    9: "DECLINE (DHCP DECLINE)",
    10: "RECONFIGURE (no DHCPv4 pendant)",
    11: "INFORMATION-REQUEST (DHCP INFORM)",
    12: "RELAY-FORW (no DHCPv4 pendant)",
    13: "RELAY-REPL (no DHCPv4 pendant)",
};

DHCPv6.prototype.decode = function (raw_packet, offset) {
    this.messageType = raw_packet.readUInt8(offset); // 0
    this.messageTypeDecoded = messageTypes[this.messageType];
    this.transactionId = raw_packet.readUIntBE(1, 3);
    this.options_raw = raw_packet.slice(4);
    return this;
};

module.exports = DHCPv6;
let IPv4Addr = require("./ipv4_addr");
let EthernetAddr = require("./ethernet_addr");

const magicDHCPNum = 1669485411;

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
    this.options_raw = undefined;
    this.options = undefined;
    // flags with optional length, see: https://datatracker.ietf.org/doc/html/rfc2132
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
    this.clientMac = new EthernetAddr(raw_packet, offset + 28); // read 16 bytes
    this.serverHostName = raw_packet.slice(44, 108).toString().replaceAll("\x00", ""); //read 64 bytes, offset + 44
    if (this.serverHostName === '') {
        this.serverHostName = "Server host name not given";
    }
    // read 128 bytes for file, offset + 108
    const magicNum = raw_packet.readUInt32BE(offset + 236);
    if(magicNum !== magicDHCPNum) {
        this.options = "Malformed input, magic value != 0x63825363";
        return this;
    }

    const options = parseOptions(raw_packet, offset + 240);
    this.options_raw = options;

    this.options = decodeOptions(options);

    return this;
};

function parseOptions(raw_packet, offset) {
    const options = {};
    let optionsIndex = offset;
    while (raw_packet[optionsIndex] !== 255) {
        const currentOption = raw_packet[optionsIndex];
        const currentLength = raw_packet[optionsIndex + 1];
        options[currentOption] = raw_packet.slice(optionsIndex + 2, optionsIndex + 2 + currentLength);
        optionsIndex += currentLength + 2;
    }
    return options;
}

const decoders = {
    53: function (buffer) {
        const lookupTable = {
            1: "DHCPDISCOVER",
            2: "DHCPOFFER",
            3: "DHCPREQUEST",
            4: "DHCPDECLINE",
            5: "DHCPACK",
            6: "DHCPNAK",
            7: "DHCPRELEASE",
            8: "DHCPINFORM"
        };
        return lookupTable[buffer[0]];
    }
};

function decodeOptions(raw_options) {
    const options = {};
    Object.keys(raw_options).forEach(key => {
        if(decoders[key] !== undefined) {
            options[key] = decoders[key](raw_options[key]);
        }
    });
    return options;
}

module.exports = DHCP;
var IPv4 = require("./ipv4");

function LogicalLinkControl() {
    this.dsap = null;
    this.ssap = null;
    this.control_field = null;
    this.org_code = null;
    this.type = null;
}

LogicalLinkControl.prototype.decode = function (raw_packet, offset) {
    this.dsap = raw_packet[offset++];
    this.ssap = raw_packet[offset++];

    if (((this.dsap === 0xaa) && (this.ssap === 0xaa)) || ((this.dsap === 0x00) && (this.ssap === 0x00))) {
        this.control_field = raw_packet[offset++];
        this.org_code = [
            raw_packet[offset++],
            raw_packet[offset++],
            raw_packet[offset++]
        ];
        this.type = raw_packet.readUInt16BE(raw_packet, offset);
        offset += 2;

        switch (this.type) {
        case 0x0800: // IPv4
            this.payload = new IPv4().decode(raw_packet, offset);
            break;
        }
    } else {
        throw new Error("Unknown LLC types: DSAP: " + this.dsap + ", SSAP: " + this.ssap);
    }

    return this;
};

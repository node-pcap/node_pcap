function ICMP(emitter) {
    this.emitter = emitter;
    this.type = undefined;
    this.code = undefined;
    this.checksum = undefined;
}

// http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
ICMP.prototype.decode = function (raw_packet, offset) {
    this.type = raw_packet[offset++];
    this.code = raw_packet[offset++];
    this.checksum = raw_packet.readUInt16BE(offset); // 2, 3

    if(this.emitter) { this.emitter.emit("icmp", this); }
    return this;
};

ICMP.prototype.decoderName = "icmp";
ICMP.prototype.eventsOnDecode = true;

ICMP.prototype.toString = function () {
    var ret = "";

    switch (this.type) {
    case 0:
        ret += "Echo Reply";
        break;
    case 3: // destination unreachable
        switch (this.code) {
        case 0:
            ret += "Destination Network Unreachable";
            break;
        case 1:
            ret += "Destination Host Unreachable";
            break;
        case 2:
            ret += "Destination Protocol Unreachable";
            break;
        case 3:
            ret += "Destination Port Unreachable";
            break;
        case 4:
            ret += "Fragmentation required, and DF flag set";
            break;
        case 5:
            ret += "Source route failed";
            break;
        case 6:
            ret += "Destination network unknown";
            break;
        case 7:
            ret += "Destination host unknown";
            break;
        case 8:
            ret += "Source host isolated";
            break;
        case 9:
            ret += "Network administratively prohibited";
            break;
        case 10:
            ret += "Host administratively prohibited";
            break;
        case 11:
            ret += "Network unreachable for TOS";
            break;
        case 12:
            ret += "Host unreachable for TOS";
            break;
        case 13:
            ret += "Communication administratively prohibited";
            break;
        default:
            ret += "Destination Unreachable (unknown code " + this.code + ")";
        }
        break;
    case 4:
        ret += "Source Quench";
        break;
    case 5: // redirect
        switch (this.code) {
        case 0:
            ret += "Redirect Network";
            break;
        case 1:
            ret += "Redirect Host";
            break;
        case 2:
            ret += "Redirect TOS and Network";
            break;
        case 3:
            ret += "Redirect TOS and Host";
            break;
        default:
            ret += "Redirect (unknown code " + this.code + ")";
            break;
        }
        break;
    case 6:
        ret += "Alternate Host Address";
        break;
    case 7:
        ret += "Reserved";
        break;
    case 8:
        ret += "Echo Request";
        break;
    case 9:
        ret += "Router Advertisement";
        break;
    case 10:
        ret += "Router Solicitation";
        break;
    case 11:
        switch (this.code) {
        case 0:
            ret += "TTL expired in transit";
            break;
        case 1:
            ret += "Fragment reassembly time exceeded";
            break;
        default:
            ret += "Time Exceeded (unknown code " + this.code + ")";
        }
        break;
        // TODO - decode the rest of the well-known ICMP messages, even though they are deprecated
    default:
        ret += "type " + this.type + " code " + this.code;
    }

    // TODO - there are often more exciting things hiding in ICMP packets after the headers
    return ret;
};

module.exports = ICMP;

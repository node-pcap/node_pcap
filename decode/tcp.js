
function TCPFlags() {
    this.cwr = null;
    this.ece = null;
    this.urg = null;
    this.ack = null;
    this.psh = null;
    this.rst = null;
    this.syn = null;
    this.fin = null;
}

TCPFlags.prototype.toString = function () {
    var ret = "[";

    if (this.cwr) {
        ret += "c";
    }
    if (this.ece) {
        ret += "e";
    }
    if (this.urg) {
        ret += "u";
    }
    if (this.ack) {
        ret += "a";
    }
    if (this.psh) {
        ret += "p";
    }
    if (this.rst) {
        ret += "r";
    }
    if (this.syn) {
        ret += "s";
    }
    if (this.fin) {
        ret += "f";
    }
    ret += "]";

    return ret;
};

function TCPOptions() {
    this.mss = null;
    this.window_scale = null;
    this.sack_ok = null;
    this.sack = null;
    this.timestamp = null;
    this.echo = null;
}

TCPOptions.prototype.decode = function (raw_packet, offset, len) {
    var end_offset = offset + len;

    while (offset < end_offset) {
        switch (raw_packet[offset]) {
        case 0: // end of options list
            offset = end_offset;
            break;
        case 1: // NOP / padding
            offset += 1;
            break;
        case 2:
            offset += 2;
            this.mss = raw_packet.readUInt16BE(offset);
            offset += 2;
            break;
        case 3:
            offset += 2;
            this.window_scale = raw_packet[offset];
            offset += 1;
            break;
        case 4:
            this.sack_ok = true;
            offset += 2;
            break;
        case 5:
            this.sack = [];
            offset += 1;
            switch (raw_packet[offset]) {
            case 10:
                offset += 1;
                this.sack.push([raw_packet.readUInt32BE(offset), raw_packet.readUInt32BE(offset + 4)]);
                offset += 8;
                break;
            case 18:
                offset += 1;
                this.sack.push([raw_packet.readUInt32BE(offset), raw_packet.readUInt32BE(offset + 4)]);
                offset += 8;
                this.sack.push([raw_packet.readUInt32BE(offset), raw_packet.readUInt32BE(offset + 4)]);
                offset += 8;
                break;
            case 26:
                offset += 1;
                this.sack.push([raw_packet.readUInt32BE(offset), raw_packet.readUInt32BE(offset + 4)]);
                offset += 8;
                this.sack.push([raw_packet.readUInt32BE(offset), raw_packet.readUInt32BE(offset + 4)]);
                offset += 8;
                this.sack.push([raw_packet.readUInt32BE(offset), raw_packet.readUInt32BE(offset + 4)]);
                offset += 8;
                break;
            case 34:
                offset += 1;
                this.sack.push([raw_packet.readUInt32BE(offset), raw_packet.readUInt32BE(offset + 4)]);
                offset += 8;
                this.sack.push([raw_packet.readUInt32BE(offset), raw_packet.readUInt32BE(offset + 4)]);
                offset += 8;
                this.sack.push([raw_packet.readUInt32BE(offset), raw_packet.readUInt32BE(offset + 4)]);
                offset += 8;
                this.sack.push([raw_packet.readUInt32BE(offset), raw_packet.readUInt32BE(offset + 4)]);
                offset += 8;
                break;
            default:
                console.log("Invalid TCP SACK option length " + raw_packet[offset + 1]);
                offset = end_offset;
            }
            break;
        case 8:
            offset += 2;
            this.timestamp = raw_packet.readUInt32BE(offset);
            offset += 4;
            this.echo = raw_packet.readUInt32BE(offset);
            offset += 4;
            break;
        case 254:
        case 255:
            //We do not know how to parse rfc6994 (Experimental TCP option)
            //however, the first byte is the length of the option (including
            //the 1 byte kind, and 1 byte of length.) So skip over option.
            offset += raw_packet.readUInt8(offset + 1);
            break;
        default:
            throw new Error("Don't know how to process TCP option " + raw_packet[offset]);
        }
    }

    return this;
};

TCPOptions.prototype.toString = function () {
    var ret = "";
    if (this.mss !== null) {
        ret += "mss:" + this.mss + " ";
    }
    if (this.window_scale !== null) {
        ret += "scale:" + this.window_scale + "(" + Math.pow(2, (this.window_scale)) + ") ";
    }
    if (this.sack_ok !== null) {
        ret += "sack_ok" + " ";
    }
    if (this.sack !== null) {
        ret += "sack:" + this.sack.join(",") + " ";
    }

    if (ret.length === 0) {
        ret = ". ";
    }

    return "[" + ret.slice(0, -1) + "]";
};

function TCP() {
    this.sport          = null;
    this.dport          = null;
    this.seqno          = null;
    this.ackno          = null;
    this.data_offset    = null;
    this.header_bytes   = null; // not part of packet but handy
    this.reserved       = null;
    this.flags          = new TCPFlags();
    this.window_size    = null;
    this.checksum       = null;
    this.urgent_pointer = null;
    this.options        = null;
    this.data           = null;
    this.data_bytes     = null;
}

// If you get stuck trying to decode or understand the offset math, stick this block in to dump the contents:
// for (var i = orig_offset; i < orig_offset + len ; i++) {
//     console.log((i - orig_offset) + " / " + i + ": " + raw_packet[i] + " " + String.fromCharCode(raw_packet[i]));
// }

// http://en.wikipedia.org/wiki/Transmission_Control_Protocol
TCP.prototype.decode = function (raw_packet, offset, len) {
    var orig_offset = offset;

    this.sport          = raw_packet.readUInt16BE(offset, true); // 0, 1
    offset += 2;
    this.dport          = raw_packet.readUInt16BE(offset, true); // 2, 3
    offset += 2;
    this.seqno          = raw_packet.readUInt32BE(offset, true); // 4, 5, 6, 7
    offset += 4;
    this.ackno          = raw_packet.readUInt32BE(offset, true); // 8, 9, 10, 11
    offset += 4;
    this.data_offset    = (raw_packet[offset] & 0xf0) >> 4; // first 4 bits of 12
    if (this.data_offset < 5 || this.data_offset > 15) {
        throw new Error("invalid data_offset: " + this.data_offset);
    }
    this.header_bytes   = this.data_offset * 4; // convenience for using data_offset
    this.reserved       = raw_packet[offset] & 15; // second 4 bits of 12
    offset += 1;
    var all_flags = raw_packet[offset];
    this.flags.cwr      = (all_flags & 128) >> 7; // all flags packed into 13
    this.flags.ece      = (all_flags & 64) >> 6;
    this.flags.urg      = (all_flags & 32) >> 5;
    this.flags.ack      = (all_flags & 16) >> 4;
    this.flags.psh      = (all_flags & 8) >> 3;
    this.flags.rst      = (all_flags & 4) >> 2;
    this.flags.syn      = (all_flags & 2) >> 1;
    this.flags.fin      = all_flags & 1;
    offset += 1;
    this.window_size    = raw_packet.readUInt16BE(offset, true); // 14, 15
    offset += 2;
    this.checksum       = raw_packet.readUInt16BE(offset, true); // 16, 17
    offset += 2;
    this.urgent_pointer = raw_packet.readUInt16BE(offset, true); // 18, 19
    offset += 2;

    this.options = new TCPOptions();
    var options_len = this.header_bytes - (offset - orig_offset);
    if (options_len > 0) {
        this.options.decode(raw_packet, offset, options_len);
        offset += options_len;
    }

    this.data_bytes = len - this.header_bytes;
    if (this.data_bytes > 0) {
        // add a buffer slice pointing to the data area of this TCP packet.
        // Note that this does not make a copy, so ret.data is only valid for this current
        // trip through the capture loop.
        this.data = raw_packet.slice(offset, offset + this.data_bytes);
    }

    return this;
};

TCP.prototype.toString = function () {
    var ret = this.sport + "->" + this.dport + " seq " + this.seqno + " ack " + this.ackno + " flags " + this.flags + " " +
        "win " + this.window_size + " csum " + this.checksum;
    if (this.urgent_pointer) {
        ret += " urg " + this.urgent_pointer;
    }
    ret += " " + this.options.toString();
    ret += " len " + this.data_bytes;
    return ret;
};

// automatic protocol decode ends here.  Higher level protocols can be decoded by using payload.

module.exports = TCP;

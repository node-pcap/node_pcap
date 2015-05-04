
function TCPFlags(emitter) {
    this.emitter = emitter;
    this.nonce = undefined;
    this.cwr = undefined;
    this.ece = undefined;
    this.urg = undefined;
    this.ack = undefined;
    this.psh = undefined;
    this.rst = undefined;
    this.syn = undefined;
    this.fin = undefined;
}

TCPFlags.prototype.decode = function (first_byte, second_byte) {
    this.nonce = Boolean(first_byte & 16);
    this.cwr = Boolean(second_byte & 128);
    this.ece = Boolean(second_byte & 64);
    this.urg = Boolean(second_byte & 32);
    this.ack = Boolean(second_byte & 16);
    this.psh = Boolean(second_byte & 8);
    this.rst = Boolean(second_byte & 4);
    this.syn = Boolean(second_byte & 2);
    this.fin = Boolean(second_byte & 1);
    return this;
};

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

function TCP(emitter) {
    this.emitter        = emitter;
    this.sport          = undefined;
    this.dport          = undefined;
    this.seqno          = undefined;
    this.ackno          = undefined;
    this.headerLength   = undefined;
    this.reserved       = undefined;
    this.flags          = undefined;
    this.windowSize     = undefined;
    this.checksum       = undefined;
    this.urgentPointer  = undefined;
    this.options        = undefined;
    this.data           = undefined;
    this.dataLength     = undefined;
}

// If you get stuck trying to decode or understand the offset math, stick this block in to dump the contents:
// for (var i = orig_offset; i < orig_offset + len ; i++) {
//     console.log((i - orig_offset) + " / " + i + ": " + raw_packet[i] + " " + String.fromCharCode(raw_packet[i]));
// }
TCP.prototype.decoderName = "tcp";
TCP.prototype.eventsOnDecode = true;

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
    // The first 4 bits of the next header * 4 tells use the length
    // of the header.
    this.headerLength    = (raw_packet[offset] & 0xf0) >> 2;

    this.flags = new TCPFlags().decode(raw_packet[offset], raw_packet[offset+1]);
    offset += 2;
    this.windowSize    = raw_packet.readUInt16BE(offset, true); // 14, 15
    offset += 2;
    this.checksum       = raw_packet.readUInt16BE(offset, true); // 16, 17
    offset += 2;
    this.urgentPointer = raw_packet.readUInt16BE(offset, true); // 18, 19
    offset += 2;

    this.options = new TCPOptions();
    var options_len = this.headerLength - (offset - orig_offset);
    if (options_len > 0) {
        this.options.decode(raw_packet, offset, options_len);
        offset += options_len;
    }

    this.dataLength = len - this.headerLength;
    if (this.dataLength > 0) {
        // add a buffer slice pointing to the data area of this TCP packet.
        // Note that this does not make a copy, so ret.data is only valid for this current
        // trip through the capture loop.
        this.data = raw_packet.slice(offset, offset + this.dataLength);
    } else {
        // null indicated the value was set. Where as undefined
        // means the value was never set. Since there is no data
        // we explicity want to communicate this to consumers.
        this.data = null;
    }

    if(this.emitter) { this.emitter.emit("tcp", this); }
    return this;
};

TCP.prototype.toString = function () {
    var ret = this.sport + "->" + this.dport + " seq " + this.seqno + " ack " + this.ackno + " flags " + this.flags + " " +
        "win " + this.windowSize + " csum " + this.checksum;
    if (this.urgent_pointer) {
        ret += " urg " + this.urgentPointer;
    }
    ret += " " + this.options.toString();
    ret += " len " + this.dataLength;
    return ret;
};

// automatic protocol decode ends here.  Higher level protocols can be decoded by using payload.

module.exports = TCP;

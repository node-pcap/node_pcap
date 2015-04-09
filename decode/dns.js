var IPv4Addr = require("./ipv4_addr");
var IPv6Addr = require("./ipv6_addr");

function DnsFlags() {
    // is this a response?
    this.isResponse = undefined;

    // 0 == Query
    // 1 == Inverse query
    // 2 == Status
    // 3-15 Reserved for future use
    this.opcode = undefined;

    // is the server the authority for the domain?
    this.isAuthority = undefined;

    // is this message truncated?
    this.isTruncated = undefined;

    // should name server recursively
    // resolve domain?
    this.isRecursionDesired = undefined;

    // Can the server even do recursion?
    this.isRecursionAvailible = undefined;

    // Reserved for future use, unless the present is the future
    // then assume the past is the present and the present is the
    // past...or just update to support whatever this became.
    //
    // currently "should" always be zero.
    this.z = undefined;

    // 0 == no error
    // 1 == format error (query could not be interpeted)
    // 2 == server error
    // 3 == name error (domain requested by query does not exist)
    // 4 == unsupported request
    // 5 == refused
    // a 4bit reply status code
    this.responseCode = undefined;
}

DnsFlags.prototype.decode = function (raw_packet, offset) {
    var byte1 = raw_packet[offset];
    var byte2 = raw_packet[offset + 1];

    this.isResponse = Boolean(byte1 & 0x80);
    this.opcode = (byte1 & 0x78) >> 3;

    this.isAuthority = Boolean(byte1 & 0x04);
    this.isTruncated = Boolean(byte1 & 0x02);
    this.isRecursionDesired   = Boolean(byte1 & 0x01);
    this.isRecursionAvailible = Boolean(byte2 & 0x80);
    this.z = byte2 & 0x70 >> 4;
    this.responseCode = byte2 & 0x0F;
    return this;
};

DnsFlags.prototype.toString = function () {
    return "{ isResponse:" + this.isResponse +
        " opcode:" + this.opcode +
        " isAuthority:" + this.isAuthority +
        " isTruncated:" + this.isTruncated +
        " isRecursionDesired:" + this.isRecursionDesired +
        " isRecursionAvailible:" + this.isRecursionAvailible +
        " z:" + this.z +
        " responseCode:" + this.responseCode +
        " }";
};

function DNS(emitter) {
    this.emitter = emitter;
    this.header = undefined;
    this.question = undefined;
    this.answer = undefined;
    this.authority = undefined;
    this.additional = undefined;
    this._error = undefined;
}

function DNSRRSet(count) {
    this.rrs = new Array(count);
}

DNSRRSet.prototype.toString = function () {
    return this.rrs.join(", ");
};

DNS.prototype.decoderName = "dns";
DNS.prototype.eventsOnDecode = true;

// http://tools.ietf.org/html/rfc1035
DNS.prototype.decode = function (raw_packet, offset) {
    //these 2 fields will be deleted soon.
    this.raw_packet = raw_packet;
    this.offset = offset;

    this.id = raw_packet.readUInt16BE(offset); // 0, 1
    this.header = new DnsFlags().decode(raw_packet.readUInt16BE(this.offset+2));
    this.qdcount = raw_packet.readUInt16BE(offset + 4); // 4, 5
    this.ancount = raw_packet.readUInt16BE(offset + 6); // 6, 7
    this.nscount = raw_packet.readUInt16BE(offset + 8); // 8, 9
    this.arcount = raw_packet.readUInt16BE(offset + 10); // 10, 11
    this.offset += 12;

    this.question = this.decode_RRs(this.qdcount, true);
    this.answer = this.decode_RRs(this.ancount, false);
    this.authority = this.decode_RRs(this.nscount, false);
    this.additional = this.decode_RRs(this.arcount, false);

    if(this.emitter) { this.emitter.emit("dns", this); }
    return this;
};

DNS.prototype.decode_RRs = function (count, is_question) {
    if (count > 100) {
        this._error = "Malformed DNS packet: too many RRs at offset " + this.offset;
        return;
    }

    var ret = new DNSRRSet(count);
    for (var i = 0; i < count; i++) {
        ret.rrs[i] = this.decode_RR(is_question);
    }
    return ret;
};

function DNSRR(is_question) {
    this.name = "";
    this.type = null;
    this.class = null;
    this.ttl = null;
    this.rdlength = null;
    this.rdata = null;
    this.is_question = is_question;
}

DNSRR.prototype.toString = function () {
    var ret = this.name + " ";
    if (this.is_question) {
        ret += qtype_to_string(this.type) + " " + qclass_to_string(this.class);
    } else {
        ret += type_to_string(this.type) + " " + class_to_string(this.class) + " " + this.ttl + " " + this.rdata;
    }
    return ret;
};

DNS.prototype.read_name = function () {
    var result = "";
    var len_or_ptr;
    var pointer_follows = 0;
    var pos = this.offset;

    while ((len_or_ptr = this.raw_packet[pos]) !== 0x00) {
        if ((len_or_ptr & 0xC0) === 0xC0) {
            // pointer is bottom 6 bits of current byte, plus all 8 bits of next byte
            pos = ((len_or_ptr & ~0xC0) << 8) | this.raw_packet[pos + 1];
            pointer_follows++;
            if (pointer_follows === 1) {
                this.offset += 2;
            }
            if (pointer_follows > 5) {
                throw new Error("invalid DNS RR: too many compression pointers found at offset " + pos);
            }
        } else {
            if (result.length > 0) {
                result += ".";
            }
            if (len_or_ptr > 63) {
                throw new Error("invalid DNS RR: length is too large at offset " + pos);
            }
            pos++;
            for (var i = pos; i < (pos + len_or_ptr) && i < this.raw_packet.length; i++) {
                if (i > this.raw_packet.length) {
                    throw new Error("invalid DNS RR: read beyond end of packet at offset " + i);
                }
                var ch = this.raw_packet[i];
                result += String.fromCharCode(ch);
            }
            pos += len_or_ptr;

            if (pointer_follows === 0) {
                this.offset = pos;
            }
        }
    }

    if (pointer_follows === 0) {
        this.offset++;
    }

    return result;
};

DNS.prototype.decode_RR = function (is_question) {
    if (this.offset > this.raw_packet.length) {
        throw new Error("Malformed DNS RR. Offset is beyond packet len (decode_RR) :" + this.offset + " packet_len:" + this.raw_packet.length);
    }

    var rr = new DNSRR(is_question);

    rr.name = this.read_name();

    rr.type = this.raw_packet.readUInt16BE(this.offset);
    this.offset += 2;
    rr.class = this.raw_packet.readUInt16BE(this.offset);
    this.offset += 2;
    if (is_question) {
        return rr;
    }

    rr.ttl = this.raw_packet.readUInt32BE(this.offset);
    this.offset += 4;
    rr.rdlength = this.raw_packet.readUInt16BE(this.offset);
    this.offset += 2;

    if (rr.type === 1 && rr.class === 1 && rr.rdlength) { // A, IN
        rr.rdata = new IPv4Addr().decode(this.raw_packet, this.offset);
    } else if (rr.type === 2 && rr.class === 1) { // NS, IN
        rr.rdata = this.read_name();
        this.offset -= rr.rdlength; // read_name moves offset
    } else if (rr.type === 28 && rr.class === 1 && rr.rdlength === 16) {
        rr.data = new IPv6Addr(this.raw_packet, this.offset);
    }
    // TODO - decode other rr types

    this.offset += rr.rdlength;

    return rr;
};

DNS.prototype.toString = function () {
    var ret = " DNS ";

    ret += this.header.toString();
    if (this.qdcount > 0) {
        ret += "\n  question:" + this.question.rrs[0];
    }
    if (this.ancount > 0) {
        ret += "\n  answer:" + this.answer;
    }
    if (this.nscount > 0) {
        ret += "\n  authority:" + this.authority;
    }
    if (this.arcount > 0) {
        ret += "\n  additional:" + this.additional;
    }

    return ret;
};

function type_to_string(type_num) {
    switch (type_num) {
    case 1:
        return "A";
    case 2:
        return "NS";
    case 3:
        return "MD";
    case 4:
        return "MF";
    case 5:
        return "CNAME";
    case 6:
        return "SOA";
    case 7:
        return "MB";
    case 8:
        return "MG";
    case 9:
        return "MR";
    case 10:
        return "NULL";
    case 11:
        return "WKS";
    case 12:
        return "PTR";
    case 13:
        return "HINFO";
    case 14:
        return "MINFO";
    case 15:
        return "MX";
    case 16:
        return "TXT";
    case 28:
        return "AAAA";
    default:
        return ("Unknown (" + type_num + ")");
    }
}

function qtype_to_string(qtype_num) {
    switch (qtype_num) {
    case 252:
        return "AXFR";
    case 253:
        return "MAILB";
    case 254:
        return "MAILA";
    case 255:
        return "*";
    default:
        return type_to_string(qtype_num);
    }
}

function class_to_string(class_num) {
    switch (class_num) {
    case 1:
        return "IN";
    case 2:
        return "CS";
    case 3:
        return "CH";
    case 4:
        return "HS";
    default:
        return "Unknown (" + class_num + ")";
    }
}

function qclass_to_string(qclass_num) {
    if (qclass_num === 255) {
        return "*";
    } else {
        return class_to_string(qclass_num);
    }
}

module.exports = DNS;

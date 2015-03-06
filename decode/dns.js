var IPv4Addr = require("./ipv4_addr");
var IPv6Addr = require("./ipv6_addr");

function DNSHeader(raw_packet, offset) {
    this.id = raw_packet.readUInt16BE(offset); // 0, 1
    this.qr = (raw_packet[offset + 2] & 128) >> 7;
    this.opcode = (raw_packet[offset + 2] & 120) >> 3;
    this.aa = (raw_packet[offset + 2] & 4) >> 2;
    this.tc = (raw_packet[offset + 2] & 2) >> 1;
    this.rd = raw_packet[offset + 2] & 1;
    this.ra = (raw_packet[offset + 3] & 128) >> 7;
    this.z = 0; // spec says this MUST always be 0
    this.rcode = raw_packet[offset + 3] & 15;
    this.qdcount = raw_packet.readUInt16BE(offset + 4); // 4, 5
    this.ancount = raw_packet.readUInt16BE(offset + 6); // 6, 7
    this.nscount = raw_packet.readUInt16BE(offset + 8); // 8, 9
    this.arcount = raw_packet.readUInt16BE(offset + 10); // 10, 11
}

DNSHeader.prototype.toString = function () {
    return "{" +
        " id:" + this.id +
        " qr:" + this.qr +
        " op:" + this.opcode +
        " aa:" + this.aa +
        " tc:" + this.tc +
        " rd:" + this.rd +
        " ra:" + this.ra +
        " rc:" + this.rcode +
        " qd:" + this.qdcount +
        " an:" + this.ancount +
        " ns:" + this.nscount +
        " ar:" + this.arcount +
        " }";
};

function DNS() {
    this.header = null;
    this.question = null;
    this.answer = null;
    this.authority = null;
    this.additional = null;

    // not part of DNS, but handy so we don't have to pass these around all over the place
    this.raw_packet = null;
    this.offset = null;
    this.packet_start = null;
    this.packet_len = null;
}

function DNSRRSet(count) {
    this.rrs = new Array(count);
}

DNSRRSet.prototype.toString = function () {
    return this.rrs.join(", ");
};

// http://tools.ietf.org/html/rfc1035
DNS.prototype.decode = function (raw_packet, offset, caplen) {
    this.raw_packet = raw_packet;
    this.packet_start = offset;
    this.offset = offset;
    this.packet_len = caplen;

    this.header = new DNSHeader(raw_packet, this.offset);
    this.offset += 12;

    this.question = this.decode_RRs(this.header.qdcount, true);
    this.answer = this.decode_RRs(this.header.ancount, false);
    this.authority = this.decode_RRs(this.header.nscount, false);
    this.additional = this.decode_RRs(this.header.arcount, false);

    return this;
};

DNS.prototype.decode_RRs = function (count, is_question) {
    if (count > 100) {
        throw new Error("Malformed DNS packet: too many RRs at offset " + this.offset);
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
            for (var i = pos; i < (pos + len_or_ptr) && i < this.packet_len ; i++) {
                if (i > this.packet_len) {
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
    if (this.offset > this.packet_len) {
        throw new Error("Malformed DNS RR. Offset is beyond packet len (decode_RR) :" + this.offset + " packet_len:" + this.packet_len);
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
        rr.rdata = new IPv4Addr.decode(this.raw_packet, this.offset);
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
    if (this.header.qdcount > 0) {
        ret += "\n  question:" + this.question.rrs[0];
    }
    if (this.header.ancount > 0) {
        ret += "\n  answer:" + this.answer;
    }
    if (this.header.nscount > 0) {
        ret += "\n  authority:" + this.authority;
    }
    if (this.header.arcount > 0) {
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

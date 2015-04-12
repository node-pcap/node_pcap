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

DNS.prototype.decoderName = "dns";
DNS.prototype.eventsOnDecode = true;

// http://tools.ietf.org/html/rfc1035
DNS.prototype.decode = function (raw_packet, offset) {
    //these 2 fields will be deleted soon.
    this.raw_packet = raw_packet;
    var offsetOriginal = offset;

    this.id = raw_packet.readUInt16BE(offset); // 0, 1
    this.header = new DnsFlags().decode(raw_packet.readUInt16BE(offset+2));

    // the number of question asked by this packet
    var qcount = raw_packet.readUInt16BE(offset + 4); // 4, 5

    // the number of answers provided by this packet
    var acount = raw_packet.readUInt16BE(offset + 6); // 6, 7

    // the number of authority records provided by this packet
    var ncount = raw_packet.readUInt16BE(offset + 8); // 8, 9

    // the number of addtional records provided by this packet
    var arcount = raw_packet.readUInt16BE(offset + 10); // 10, 11
    offset += 12;

    this.questions = this.decode_RRs(qdcount, true);

    var offsetClosure = { offset: offset };
    this.answers = DecodeResourceRecords(raw_packet, offsetClosure, ancount, false);
    this.authorities = DecodeResourceRecords(raw_packet, offsetClosure, nscount, false);
    this.additionals = DecodeResourceRecords(raw_packet, offsetClosure, arcount, false);

    if(this.emitter) { this.emitter.emit("dns", this); }
    return this;
};

function DecodeResourceRecords(raw_packet, offsetClosure, count) {
    var ret = new Array(count);
    for (var i = ret.length - 1; i >= 0; i--) {
        ret[i] = new DNSRR().decode(raw_packet, offsetClosure);
        offsetClosure.offset = ret[i].length;
    }
    return ret;
};

function DNSRR() {
    this.name = undefined;

/*
  1 = A, a host address
  2 = NS, an authoritative name server
  3 = MD, a mail destination (Obsolete - use MX)
  4 = MF, a mail forwarder (Obsolete - use MX)
  5 = CNAME, the canonical name for an alias
  6 = SOA, marks the start of a zone of authority
  7 = MB, a mailbox domain name (EXPERIMENTAL)
  8 = MG, a mail group member (EXPERIMENTAL)
  9 = MR, a mail rename domain name (EXPERIMENTAL)
 10 = NULL, a null RR (EXPERIMENTAL)
 11 = WKS, a well known service description
 12 = PTR, a domain name pointer
 13 = HINFO, host information
 14 = MINFO, mailbox or mail list information
 15 = MX, mail exchange
 16 = TXT, text strings
*/
    this.type = undefined;

/*
 1 = IN, the Internet
 2 = CS, the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
 3 = CH, the CHAOS class
 4 = HS, Hesiod [Dyer 87]
*/
    this.class = undefined;
    this.ttl = undefined;
    this.rdlength = undefined;
    this.rdata = undefined;
}

DNSRR.prototype.decode = function (raw_packet, offset) {
    var initialOffset = offset;
    this.name = [];
    var currentChar;
    while((currentChar = raw_packet[offset++]) != 0) {
        this.name.push = currentChar;
    }

    this.type = this.raw_packet.readUInt16BE(offset);
    offset += 2;
    this.class = this.raw_packet.readUInt16BE(offset);
    offset += 2;
    this.ttl = this.raw_packet.readUInt32BE(offset);
    offset += 4;
    this.rdlength = this.raw_packet.readUInt16BE(offset);
    offset += 2;


    return this;
};

function DnsQuery() {
    this.name = undefined;

/*
   1 = A, a host address
   2 = NS, an authoritative name server
   3 = MD, a mail destination (Obsolete - use MX)
   4 = MF, a mail forwarder (Obsolete - use MX)
   5 = CNAME, the canonical name for an alias
   6 = SOA, marks the start of a zone of authority
   7 = MB, a mailbox domain name (EXPERIMENTAL)
   8 = MG, a mail group member (EXPERIMENTAL)
   9 = MR, a mail rename domain name (EXPERIMENTAL)
  10 = NULL, a null RR (EXPERIMENTAL)
  11 = WKS, a well known service description
  12 = PTR, a domain name pointer
  13 = HINFO, host information
  14 = MINFO, mailbox or mail list information
  15 = MX, mail exchange
  16 = TXT, text strings
 
 # The following are only used by queries.
 252 = AXFR, a request for a transfer of an entire zone
 253 = MAILB, a request for mailbox-related records (MB, MG or MR)
 254 = MAILA, a request for mail agent RRs (Obsolete - see MX)
 255 = *, a request for all records
*/
    this.type = undefined;

/*
 1 = IN, the Internet
 2 = CS, the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
 3 = CH, the CHAOS class
 4 = HS, Hesiod [Dyer 87]
*/
    this.class = undefined;
}

DnsQuery.prototype.decode = function (raw_packet, offset) {
    var initialOffset = offset;
    this.name = [];
    var currentChar;
    while((currentChar = raw_packet[offset++]) != 0) {
        this.name.push = currentChar;
    }

    this.type = this.raw_packet.readUInt16BE(offset);
    offset += 2;
    this.class = this.raw_packet.readUInt16BE(offset);
    offset += 2;

    return this;
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

var IPv4Addr = require("../ipv4_addr");
var IPv6Addr = require("../ipv6_addr");
var ResourceRecord = require("../resource_record");
var QueryRequest = require("../query");
var Flags = require("../flags");

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
        ret[i] = new ResourceRecord().decode(raw_packet, offsetClosure);
        offsetClosure.offset = ret[i].length;
    }
    return ret;
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

module.exports = DNS;

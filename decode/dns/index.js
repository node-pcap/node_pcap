var ResourceRecord = require("./resource_record");
var QueryRequest = require("./query");
var Flags = require("./flags");

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

    this.id = raw_packet.readUInt16BE(offset); // 0, 1
    this.header = new Flags().decode(raw_packet.readUInt16BE(offset+2));

    // the number of question asked by this packet
    var qcount = raw_packet.readUInt16BE(offset + 4); // 4, 5

    // the number of answers provided by this packet
    var acount = raw_packet.readUInt16BE(offset + 6); // 6, 7

    // the number of authority records provided by this packet
    var nscount = raw_packet.readUInt16BE(offset + 8); // 8, 9

    // the number of addtional records provided by this packet
    var arcount = raw_packet.readUInt16BE(offset + 10); // 10, 11
    offset += 12;

    this.questions = decodeQueries(raw_packet, offset, qcount);

    this.answers = decodeResourceRecords(raw_packet, offset, acount);
    this.authorities = decodeResourceRecords(raw_packet, offset, nscount);
    this.additionals = decodeResourceRecords(raw_packet, offset, arcount);

    if(this.emitter) { this.emitter.emit("dns", this); }
    return this;
};

function decodeResourceRecords(raw_packet, offset, count) {
    var ret = new Array(count);
    for (var i = ret.length - 1; i >= 0; i--) {
        ret[i] = new ResourceRecord().decode(raw_packet, offset);
        offset += ret[i].bytesDecoded;
    }
    return ret;
}

function decodeQueries(raw_packet, offset, count) {
    var ret = new Array(count);
    for (var i = ret.length - 1; i >= 0; i--) {
        ret[i] = new QueryRequest().decode(raw_packet, offset);
        offset += ret[i].bytesDecoded;
    }
    return ret;
}

DNS.prototype.toString = function () {
    var ret = " DNS ";

    ret += this.header.toString();
    if (this.questions.length > 0) {
        ret += "\n  question:" + this.questions.join("\n\t");
    }
    if (this.answers.length > 0) {
        ret += "\n  answer:" + this.answers.join("\n\t");
    }
    if (this.authorities.length > 0) {
        ret += "\n  authority:" + this.authorities.join("\n\t");
    }
    if (this.additionals.length > 0) {
        ret += "\n  additional:" + this.additionals.join("\n\t");
    }

    return ret;
};

module.exports = DNS;

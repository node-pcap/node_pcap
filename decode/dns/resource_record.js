function DnsResourceRecord() {
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

  // the number of bytes decoded by this instance.
  this.bytesDecoded = undefined;
}

DnsResourceRecord.prototype.decode = function (raw_packet, offset) {
  var initialOffset = offset;
  this.name = [];
  var currentChar;
  while((currentChar = raw_packet[offset++]) !== 0) {
    this.name.push = currentChar;
  }

  this.type = raw_packet.readUInt16BE(offset);
  offset += 2;
  this.class = raw_packet.readUInt16BE(offset);
  offset += 2;
  this.ttl = raw_packet.readUInt32BE(offset);
  offset += 4;
  this.rdlength = raw_packet.readUInt16BE(offset);
  offset += 2;
  this.bytesDecoded = offset - initialOffset;

  return this;
};

module.exports = DnsResourceRecord;

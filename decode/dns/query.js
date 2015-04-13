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

  // The total number of bytes read from the packet
  this.length = undefined;
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

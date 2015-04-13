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
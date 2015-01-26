function IPv6Header() {

}

IPv6Header.prototype.decode = function (raw_packet, next_header, ip, offset) {
    switch (next_header) {
    case 1:
        ip.protocol_name = "ICMP";
        ip.icmp = decode.icmp(raw_packet, offset);
        break;
    case 2:
        ip.protocol_name = "IGMP";
        ip.igmp = decode.igmp(raw_packet, offset);
        break;
    case 4:
        ret.protocol_name = "IPv4"; //IPv4 encapsulation, RFC2003
        ret.ip = decode.ip4(raw_packet, offset);
        break;
    case 6:
        ip.protocol_name = "TCP";
        ip.tcp = decode.tcp(raw_packet, offset, ip);
        break;
    case 17:
        ip.protocol_name = "UDP";
        ip.udp = decode.udp(raw_packet, offset);
        break;
    case 41:
        ret.protocol_name = "IPv6"; //IPv6 encapsulation, RFC2473
        ret.ip = decode.ip6(raw_packet, offset);
        break;
    /* Please follow numbers and RFC in http://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#extension-header
     * Not all next protocols follow this rule (and we can have unsuported upper protocols here too).
     *  */
    case 0: //Hop-by-Hop
    case 60: //Destination Options
    case 43: //Routing
    case 135: //Mobility
    case 139: //Host Identity Protocol. //Discussion: rfc5201 support only No Next Header/trailing data, but future documents May do. 
    case 140: //Shim6 Protocol
        decode.ip6_header(raw_packet, raw_packet[offset], ip, offset + 8*raw_packet[offset+1] + 8);
        break;
    case 51: //Authentication Header
        decode.ip6_header(raw_packet, raw_packet[offset], ip, offset + 4*raw_packet[offset+1] + 8);
        break;
    default:
        // 59 - No next Header, and unknowed upper layer protocols, do nothing.
    }
};

function IPv6() {

}

IPv6.prototype.decode = function (raw_packet, offset) {
    var ret = {};

    // http://en.wikipedia.org/wiki/IPv6
    ret.version = (raw_packet[offset] & 240) >> 4; // first 4 bits
    ret.traffic_class = ((raw_packet[offset] & 15) << 4) + ((raw_packet[offset+1] & 240) >> 4);
    ret.flow_label = ((raw_packet[offset + 1] & 15) << 16) +
        (raw_packet[offset + 2] << 8) +
        raw_packet[offset + 3];
    ret.payload_length = unpack.uint16(raw_packet, offset+4);
    ret.total_length = ret.payload_length + 40;
    ret.next_header = raw_packet[offset+6];
    ret.hop_limit = raw_packet[offset+7];
    ret.saddr = unpack.ipv6_addr(raw_packet, offset+8);
    ret.daddr = unpack.ipv6_addr(raw_packet, offset+24);
    ret.header_bytes = 40;

    decode.ip6_header(raw_packet, ret.next_header, ret, offset+40);
    return ret;
};

module.exports = IPv6;

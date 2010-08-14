"use strict";
/*global process require exports */

var sys        = require('sys'),
    dns        = require('dns'),
    Buffer     = require('buffer').Buffer,
    events     = require('events'),
    binding    = require('./build/default/pcap_binding'),
    HTTPParser = process.binding('http_parser').HTTPParser,
    url        = require('url');

function Pcap() {
    this.opened = false;
    this.fd = null;

    events.EventEmitter.call(this);
}
sys.inherits(Pcap, events.EventEmitter);

exports.lib_version = binding.lib_version();

Pcap.prototype.findalldevs = function () {
    return binding.findalldevs();
};

Pcap.prototype.open = function (live, device, filter) {
    var me = this;

    if (live) {
        this.device_name = device || binding.default_device();
        this.link_type = binding.open_live(this.device_name, filter || "");
    } else {
        this.device_name = device;
        this.link_type = binding.open_offline(device, filter || "");
    }

    this.fd = binding.fileno();
    this.opened = true;
    this.readWatcher = new process.IOWatcher();
    this.empty_reads = 0;
    this.buf = new Buffer(65535);

    // called for each packet read by pcap
    function packet_ready(header) {
        header.link_type = me.link_type;
        header.time_ms = (header.tv_sec * 1000) + (header.tv_usec / 1000);
        me.buf.pcap_header = header;
        me.emit('packet', me.buf);
    }

    // readWatcher gets a callback when pcap has data to read. multiple packets may be readable.
    this.readWatcher.callback = function pcap_read_callback() {
        var packets_read = binding.dispatch(me.buf, packet_ready);
        if (packets_read < 1) {
            // TODO - figure out what is causing this, and if it is bad.
            me.empty_reads += 1;
        }
    };
    this.readWatcher.set(this.fd, true, false);
    this.readWatcher.start();
};

Pcap.prototype.close = function () {
    this.opened = false;
    binding.close();
    // TODO - remove listeners so program will exit I guess?
};

Pcap.prototype.stats = function () {
    return binding.stats();
};

exports.Pcap = Pcap;

exports.createSession = function (device, filter) {
    var session = new Pcap();
    session.open(true, device, filter);
    return session;
};

exports.createOfflineSession = function (path, filter) {
    var session = new Pcap();
    session.open(false, path, filter);
    return session;
};

//
// Decoding functions
// 
function lpad(str, len) {
    while (str.length < len) {
        str = "0" + str;
    }
    return str;
}

function dump_bytes(raw_packet, offset) {
    for (var i = offset; i < raw_packet.pcap_header.caplen ; i += 1) {
        console.log(i + ": " + raw_packet[i]);
    }
}

var unpack = {
    ethernet_addr: function (raw_packet, offset) {
        return [
            lpad(raw_packet[offset].toString(16), 2),
            lpad(raw_packet[offset + 1].toString(16), 2),
            lpad(raw_packet[offset + 2].toString(16), 2),
            lpad(raw_packet[offset + 3].toString(16), 2),
            lpad(raw_packet[offset + 4].toString(16), 2),
            lpad(raw_packet[offset + 5].toString(16), 2)
        ].join(":");
    },
    uint16: function (raw_packet, offset) {
        return ((raw_packet[offset] * 256) + raw_packet[offset + 1]);
    },
    uint32: function (raw_packet, offset) {
        return (
            (raw_packet[offset] * 16777216) + 
            (raw_packet[offset + 1] * 65536) +
            (raw_packet[offset + 2] * 256) + 
            raw_packet[offset + 3]
        );
    },
    ipv4_addr: function (raw_packet, offset) {
        return [
            raw_packet[offset],
            raw_packet[offset + 1],
            raw_packet[offset + 2],
            raw_packet[offset + 3]
        ].join('.');
    }
};
exports.unpack = unpack;

var decode = {}; // convert raw packet data into JavaScript objects with friendly names
decode.packet = function (raw_packet) {
    var packet = {};

    packet.link_type = raw_packet.pcap_header.link_type;
    switch (packet.link_type) {
    case "LINKTYPE_ETHERNET":
        packet.link = decode.ethernet(raw_packet, 0);
        break;
    case "LINKTYPE_NULL":
        packet.link = decode.nulltype(raw_packet, 0);
        break;
    default:
        console.log("pcap.js: decode.packet() - Don't yet know how to decode link type " + raw_packet.pcap_header.link_type);
    }
    
    packet.pcap_header = raw_packet.pcap_header; // TODO - merge values here instead of putting ref on packet buffer

    return packet;
};

decode.nulltype = function (raw_packet, offset) {
    var ret = {};
    
    ret.pftype = raw_packet[0];  // this is a pretty big hack as the compiler is the only one that knows this for sure.
    if (ret.pftype === 2) { // AF_INET, at least on my Linux and OSX machines right now
        ret.ip = decode.ip(raw_packet, 4);
    } else if (ret.pftype === 30) { // AF_INET6, often
        console.log("pcap.js: decode.nulltype() - Don't know how to decode IPv6 packets.");
    } else {
        console.log("pcap.js: decode.nulltype() - Don't know how to decode protocol family " + ret.pftype);
    }

    return ret;
};

decode.ethernet = function (raw_packet, offset) {
    var ret = {};
    
    ret.dhost = unpack.ethernet_addr(raw_packet, 0);
    ret.shost = unpack.ethernet_addr(raw_packet, 6);
    ret.ethertype = unpack.uint16(raw_packet, 12);

    // http://en.wikipedia.org/wiki/EtherType
    switch (ret.ethertype) {
    case 0x800: // IPv4
        ret.ip = decode.ip(raw_packet, 14);
        break;
    case 0x806: // ARP
        ret.arp = decode.arp(raw_packet, 14);
        break;
    default:
        console.log("pcap.js: decode.ethernet() - Don't know how to decode ethertype " + ret.ethertype);
    }

    return ret;
};

decode.arp = function (raw_packet, offset) {
    var ret = {};

    // http://en.wikipedia.org/wiki/Address_Resolution_Protocol
    ret.htype = unpack.uint16(raw_packet, offset); // 0, 1
    ret.ptype = unpack.uint16(raw_packet, offset + 2); // 2, 3
    ret.hlen = raw_packet[offset + 4];
    ret.plen = raw_packet[offset + 5];
    ret.operation = unpack.uint16(raw_packet, offset + 6); // 6, 7
    if (ret.operation === 1) {
        ret.operation = "request";
    }
    else if (ret.operation === 2) {
        ret.operation = "reply";
    }
    else {
        ret.operation = "unknown";
    }
    if (ret.hlen === 6 && ret.plen === 4) { // ethernet + IPv4
        ret.sender_ha = unpack.ethernet_addr(raw_packet, offset + 8); // 8, 9, 10, 11, 12, 13
        ret.sender_pa = unpack.ipv4_addr(raw_packet, offset + 14); // 14, 15, 16, 17
        ret.target_ha = unpack.ethernet_addr(raw_packet, offset + 18); // 18, 19, 20, 21, 22, 23
        ret.target_pa = unpack.ipv4_addr(raw_packet, offset + 24); // 24, 25, 26, 27
    }
    // don't know how to decode more exotic ARP types

    return ret;
};

decode.ip = function (raw_packet, offset) {
    var ret = {};
    
    // http://en.wikipedia.org/wiki/IPv4
    ret.version = (raw_packet[offset] & 240) >> 4; // first 4 bits
    ret.header_length = raw_packet[offset] & 15; // second 4 bits
    ret.header_bytes = ret.header_length * 4;
    ret.diffserv = raw_packet[offset + 1];
    ret.total_length = unpack.uint16(raw_packet, offset + 2); // 2, 3
    ret.identification = unpack.uint16(raw_packet, offset + 4); // 4, 5
    ret.flags = {};
    ret.flags.reserved = (raw_packet[offset + 6] & 128) >> 7;
    ret.flags.df = (raw_packet[offset + 6] & 64) >> 6;
    ret.flags.mf = (raw_packet[offset + 6] & 32) >> 5;
    ret.fragment_offset = ((raw_packet[offset + 6] & 31) * 256) + raw_packet[offset + 7]; // 13-bits from 6, 7
    ret.ttl = raw_packet[offset + 8];
    ret.protocol = raw_packet[offset + 9];
    ret.header_checksum = unpack.uint16(raw_packet, offset + 10); // 10, 11
    ret.saddr = unpack.ipv4_addr(raw_packet, offset + 12); // 12, 13, 14, 15
    ret.daddr = unpack.ipv4_addr(raw_packet, offset + 16); // 16, 17, 18, 19

    // TODO - parse IP "options" if header_length > 5

    switch (ret.protocol) {
    case 1:
        ret.protocol_name = "ICMP";
        ret.icmp = decode.icmp(raw_packet, offset + (ret.header_length * 4));
        break;
    case 2:
        ret.protocol_name = "IGMP";
        ret.igmp = decode.igmp(raw_packet, offset + (ret.header_length * 4));
        break;
    case 6:
        ret.protocol_name = "TCP";
        ret.tcp = decode.tcp(raw_packet, offset + (ret.header_length * 4), ret);
        break;
    case 17:
        ret.protocol_name = "UDP";
        ret.udp = decode.udp(raw_packet, offset + (ret.header_length * 4));
        break;
    default:
        ret.protocol_name = "Unknown";
    }

    return ret;
};

decode.icmp = function (raw_packet, offset) {
    var ret = {};

    // http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
    ret.type = raw_packet[offset];
    ret.code = raw_packet[offset + 1];
    ret.checksum = unpack.uint16(raw_packet, offset + 2); // 2, 3
    ret.id = unpack.uint16(raw_packet, offset + 4); // 4, 5
    ret.sequence = unpack.uint16(raw_packet, offset + 6); // 6, 7

    switch (ret.type) {
    case 0:
        ret.type_desc = "Echo Reply";
        break;
    case 1:
    case 2:
        ret.type_desc = "Reserved";
        break;
    case 3:
        switch (ret.code) {
        case 0:
            ret.type_desc = "Destination Network Unreachable";
            break;
        case 1:
            ret.type_desc = "Destination Host Unreachable";
            break;
        case 2:
            ret.type_desc = "Destination Protocol Unreachable";
            break;
        case 3:
            ret.type_desc = "Destination Port Unreachable";
            break;
        case 4:
            ret.type_desc = "Fragmentation required, and DF flag set";
            break;
        case 5:
            ret.type_desc = "Source route failed";
            break;
        case 6:
            ret.type_desc = "Destination network unknown";
            break;
        case 7:
            ret.type_desc = "Destination host unknown";
            break;
        case 8:
            ret.type_desc = "Source host isolated";
            break;
        case 9:
            ret.type_desc = "Network administratively prohibited";
            break;
        case 10:
            ret.type_desc = "Host administratively prohibited";
            break;
        case 11:
            ret.type_desc = "Network unreachable for TOS";
            break;
        case 12:
            ret.type_desc = "Host unreachable for TOS";
            break;
        case 13:
            ret.type_desc = "Communication administratively prohibited";
            break;
        default:
            ret.type_desc = "Destination Unreachable (unknown code " + ret.code + ")";
        }
        break;
    case 4:
        ret.type_desc = "Source Quench";
        break;
    case 5:
        switch (ret.code) {
        case 0:
            ret.type_desc = "Redirect Network";
            break;
        case 1:
            ret.type_desc = "Redirect Host";
            break;
        case 2:
            ret.type_desc = "Redirect TOS and Network";
            break;
        case 3:
            ret.type_desc = "Redirect TOS and Host";
            break;
        default:
            ret.type_desc = "Redirect (unknown code " + ret.code + ")";
            break;
        }
        break;
    case 6:
        ret.type_desc = "Alternate Host Address";
        break;
    case 7:
        ret.type_desc = "Reserved";
        break;
    case 8:
        ret.type_desc = "Echo Request";
        break;
    case 9:
        ret.type_desc = "Router Advertisement";
        break;
    case 10:
        ret.type_desc = "Router Solicitation";
        break;
    case 11:
        switch (ret.code) {
        case 0:
            ret.type_desc = "TTL expired in transit";
            break;
        case 1:
            ret.type_desc = "Fragment reassembly time exceeded";
            break;
        default:
            ret.type_desc = "Time Exceeded (unknown code " + ret.code + ")";
        }
        break;
        // TODO - decode the rest of the well-known ICMP messages
    default:
        ret.type_desc = "type " + ret.type + " code " + ret.code;
    }

    // There are usually more exciting things hiding in ICMP packets after the headers
    return ret;
};

decode.igmp = function (raw_packet, offset) {
    var ret = {};

    // http://en.wikipedia.org/wiki/Internet_Group_Management_Protocol
    ret.type = raw_packet[offset];
    ret.max_response_time = raw_packet[offset + 1];
    ret.checksum = unpack.uint16(raw_packet, offset + 2); // 2, 3
    ret.group_address = unpack.ipv4_addr(raw_packet, offset + 4); // 4, 5, 6, 7

    switch (ret.type) {
    case 0x11:
        ret.version = ret.max_response_time > 0 ? 2 : 1;
        ret.type_desc = "Membership Query"
        break;
    case 0x12:
        ret.version = 1;
        ret.type_desc = "Membership Report"
        break;
    case 0x16:
        ret.version = 2;
        ret.type_desc = "Membership Report"
        break;
    case 0x17:
        ret.version = 2;
        ret.type_desc = "Leave Group"
        break;
    case 0x22:
        ret.version = 3;
        ret.type_desc = "Membership Report"
        // TODO: Decode v3 message
        break;
    default:
        ret.type_desc = "type " + ret.type;
        break;
    }

    return ret;
}

decode.udp = function (raw_packet, offset) {
    var ret = {};

    // http://en.wikipedia.org/wiki/User_Datagram_Protocol
    ret.sport = unpack.uint16(raw_packet, offset); // 0, 1
    ret.dport = unpack.uint16(raw_packet, offset + 2); // 2, 3
    ret.length = unpack.uint16(raw_packet, offset + 4); // 4, 5
    ret.checksum = unpack.uint16(raw_packet, offset + 6); // 6, 7

    if (ret.sport === 53 || ret.dport === 53) {
        ret.dns = decode.dns(raw_packet, offset + 8);
    }
    
    return ret;
};

decode.tcp = function (raw_packet, offset, ip) {
    var ret = {}, option_offset, options_end;

    // http://en.wikipedia.org/wiki/Transmission_Control_Protocol
    ret.sport          = unpack.uint16(raw_packet, offset); // 0, 1
    ret.dport          = unpack.uint16(raw_packet, offset + 2); // 2, 3
    ret.seqno          = unpack.uint32(raw_packet, offset + 4); // 4, 5, 6, 7
    ret.ackno          = unpack.uint32(raw_packet, offset + 8); // 8, 9, 10, 11
    ret.data_offset    = (raw_packet[offset + 12] & 0xf0) >> 4; // first 4 bits of 12
    ret.header_bytes   = ret.data_offset * 4; // convenience for using data_offset
    ret.reserved       = raw_packet[offset + 12] & 15; // second 4 bits of 12
    ret.flags          = {};
    ret.flags.cwr      = (raw_packet[offset + 13] & 128) >> 7; // all flags packed into 13
    ret.flags.ece      = (raw_packet[offset + 13] & 64) >> 6;
    ret.flags.urg      = (raw_packet[offset + 13] & 32) >> 5;
    ret.flags.ack      = (raw_packet[offset + 13] & 16) >> 4;
    ret.flags.psh      = (raw_packet[offset + 13] & 8) >> 3;
    ret.flags.rst      = (raw_packet[offset + 13] & 4) >> 2;
    ret.flags.syn      = (raw_packet[offset + 13] & 2) >> 1;
    ret.flags.fin      = raw_packet[offset + 13] & 1;
    ret.window_size    = unpack.uint16(raw_packet, offset + 14); // 14, 15
    ret.checksum       = unpack.uint16(raw_packet, offset + 16); // 16, 17
    ret.urgent_pointer = unpack.uint16(raw_packet, offset + 18); // 18, 19
    ret.options        = {};

    option_offset = offset + 20;
    options_end = offset + (ret.data_offset * 4);
    while (option_offset < options_end) {
        switch (raw_packet[option_offset]) {
        case 0:
            option_offset += 1;
            break;
        case 1:
            option_offset += 1;
            break;
        case 2:
            ret.options.mss = unpack.uint16(raw_packet, option_offset + 2);
            option_offset += 4;
            break;
        case 3:
            ret.options.window_scale = Math.pow(2, (raw_packet[option_offset + 2]));
            option_offset += 3;
            break;
        case 4:
            ret.options.sack_ok = true;
            option_offset += 2;
            break;
        case 5:
            ret.options.sack = [];
            switch (raw_packet[option_offset + 1]) {
            case 10:
                ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 2), unpack.uint32(raw_packet, option_offset + 6)]);
                option_offset += 10;
                break;
            case 18:
                ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 2), unpack.uint32(raw_packet, option_offset + 6)]);
                ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 10), unpack.uint32(raw_packet, option_offset + 14)]);
                option_offset += 18;
                break;
            case 26:
                ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 2), unpack.uint32(raw_packet, option_offset + 6)]);
                ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 10), unpack.uint32(raw_packet, option_offset + 14)]);
                ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 18), unpack.uint32(raw_packet, option_offset + 22)]);
                option_offset += 26;
                break;
            case 34:
                ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 2), unpack.uint32(raw_packet, option_offset + 6)]);
                ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 10), unpack.uint32(raw_packet, option_offset + 14)]);
                ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 18), unpack.uint32(raw_packet, option_offset + 22)]);
                ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 26), unpack.uint32(raw_packet, option_offset + 30)]);
                option_offset += 34;
                break;
            default:
                console.log("Invalid TCP SACK option length " + raw_packet[option_offset + 1]);
                option_offset = options_end;
            }
            break;
        case 8:
            ret.options.timestamp = unpack.uint32(raw_packet, option_offset + 2);
            ret.options.echo = unpack.uint32(raw_packet, option_offset + 6);
            option_offset += 10;
            break;
        default:
            throw new Error("Don't know how to process TCP option " + raw_packet[option_offset]);
        }
    }

    ret.data_offset = offset + ret.header_bytes;
    ret.data_end = offset + ip.total_length - ip.header_bytes;
    ret.data_bytes = ret.data_end - ret.data_offset;
    if (ret.data_bytes > 0) {
        // add a buffer slice pointing to the data area of this TCP packet.
        // Note that this does not make a copy, so ret.data is only valid for this current
        // trip through the capture loop.
        ret.data = raw_packet.slice(ret.data_offset, ret.data_end);
        ret.data.length = ret.data_bytes;
    }

    // automatic protocol decode ends here.  Higher level protocols can be decoded by using payload.
    return ret;
};

// helpers for DNS decoder
var dns_util = {
    type_to_string: function (type_num) {
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
        default:
            return ("Unknown (" + type_num + ")");
        }
    },
    qtype_to_string: function (qtype_num) {
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
            return dns_util.type_to_string(qtype_num);
        }
    },
    class_to_string: function (class_num) {
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
    },
    qclass_to_string: function (qclass_num) {
        if (qclass_num === 255) {
            return "*";
        } else {
            return dns_util.class_to_string(qclass_num);
        }
    }
};

decode.dns = function (raw_packet, offset) {
    var ret = {}, i, internal_offset, question_done, len, parts;

    // http://tools.ietf.org/html/rfc1035
    ret.header = {};
    ret.header.id = unpack.uint16(raw_packet, offset); // 0, 1
    ret.header.qr = (raw_packet[offset + 2] & 128) >> 7;
    ret.header.opcode = (raw_packet[offset + 2] & 120) >> 3;
    ret.header.aa = (raw_packet[offset + 2] & 4) >> 2;
    ret.header.tc = (raw_packet[offset + 2] & 2) >> 1;
    ret.header.rd = raw_packet[offset + 2] & 1;
    ret.header.ra = (raw_packet[offset + 3] & 128) >> 7;
    ret.header.z = 0; // spec says this MUST always be 0
    ret.header.rcode = raw_packet[offset + 3] & 15;
    ret.header.qdcount = unpack.uint16(raw_packet, offset + 4); // 4, 5
    ret.header.ancount = unpack.uint16(raw_packet, offset + 6); // 6, 7
    ret.header.nscount = unpack.uint16(raw_packet, offset + 8); // 8, 9
    ret.header.arcount = unpack.uint16(raw_packet, offset + 10); // 10, 11

    internal_offset = offset + 12;

    ret.question = [];
    for (i = 0; i < ret.header.qdcount ; i += 1) {
        ret.question[i] = {};
        question_done = false;
        parts = [];
        while (!question_done && internal_offset < raw_packet.pcap_header.caplen) {
            len = raw_packet[internal_offset];
            if (len > 0) {
                parts.push(raw_packet.toString("ascii", internal_offset + 1, internal_offset + 1 + len));
            } else {
                question_done = true;
            }
            internal_offset += (len + 1);
        }
        ret.question[i].qname = parts.join('.');
        ret.question[i].qtype = dns_util.qtype_to_string(unpack.uint16(raw_packet, internal_offset));
        internal_offset += 2;
        ret.question[i].qclass = dns_util.qclass_to_string(unpack.uint16(raw_packet, internal_offset));
        internal_offset += 2;
    }

    // TODO - actual hard parts here, understand RR compression scheme, etc.
    ret.answer = {};
    ret.authority = {};
    ret.additional = {};

    return ret;
};

exports.decode = decode;

// cache reverse DNS lookups for the life of the program
var dns_cache = (function () {
    var cache = {},
        requests = {};

    function lookup_ptr(ip, callback) {
        if (cache[ip]) {
            return cache[ip];
        }
        else {
            if (! requests[ip]) {
                requests[ip] = true;
                dns.reverse(ip, function (err, domains) {
                    if (err) {
                        cache[ip] = ip;
                        // TODO - check for network and broadcast addrs, since we have iface info
                    } else {
                        cache[ip] = domains[0];
                        if (typeof callback === 'function') {
                            callback(domains[0]);
                        }
                    }
                    delete requests[ip];
                });
            }
            return ip;
        }
    }
    
    return {
        ptr: function (ip, callback) {
            return lookup_ptr(ip, callback);
        }
    };
}());
exports.dns_cache = dns_cache;

var print = {}; // simple printers for common types

print.dns = function (packet) {
    var ret = " DNS", dns = packet.link.ip.udp.dns;
    
    if (dns.header.qr === 0) {
        ret += " question";
    } else if (dns.header.qr === 1) {
        ret += " answer";
    } else {
        return " DNS format invalid: qr = " + dns.header.qr;
    }

    ret += " " + dns.question[0].qname + " " + dns.question[0].qtype;
    
    return ret;
};

print.ip = function (packet) {
    var ret = "",
        ip = packet.link.ip;

    switch (ip.protocol_name) {
    case "TCP":
        ret += " " + dns_cache.ptr(ip.saddr) + ":" + ip.tcp.sport + " -> " + dns_cache.ptr(ip.daddr) + ":" + ip.tcp.dport + 
            " TCP len " + ip.total_length + " [" + 
            Object.keys(ip.tcp.flags).filter(function (v) {
                if (ip.tcp.flags[v] === 1) {
                    return true;
                }
            }).join(",") + "]";
        break;
    case "UDP":
        ret += " " + dns_cache.ptr(ip.saddr) + ":" + ip.udp.sport + " -> " + dns_cache.ptr(ip.daddr) + ":" + ip.udp.dport;
        if (ip.udp.sport === 53 || ip.udp.dport === 53) {
            ret += print.dns(packet);
        } else {
            ret += " UDP len " + ip.total_length;
        }
        break;
    case "ICMP":
        ret += " " + dns_cache.ptr(ip.saddr) + " -> " + dns_cache.ptr(ip.daddr) + " ICMP " + ip.icmp.type_desc + " " + 
            ip.icmp.sequence;
        break;
    case "IGMP":
        ret += " " + dns_cache.ptr(ip.saddr) + " -> " + dns_cache.ptr(ip.daddr) + " IGMP " + ip.igmp.type_desc + " " + 
            ip.igmp.group_address;
        break;
    default:
        ret += " proto " + ip.protocol_name;
        break;
    }

    return ret;
};

print.arp = function (packet) {
    var ret = "",
        arp = packet.link.arp;

    if (arp.htype === 1 && arp.ptype === 0x800 && arp.hlen === 6 && arp.plen === 4) {
        ret += " " + arp.sender_pa + " ARP " + arp.operation + " " + arp.target_pa;
        if (arp.operation === "reply") {
            ret += " hwaddr " + arp.target_ha;
        }
    } else {
        ret = " unknown arp type";
        ret += sys.inspect(arp);
    }

    return ret;
};

print.ethernet = function (packet) {
    var ret = packet.link.shost + " -> " + packet.link.dhost;

    switch (packet.link.ethertype) {
    case 0x800:
        ret += print.ip(packet);
        break;
    case 0x806:
        ret += print.arp(packet);
        break;
    default:
        console.log("Don't know how to print ethertype " + packet.link.ethertype);
    }

    return ret;
};

print.nulltype = function (packet) {
    var ret = "loopback";

    if (packet.link.pftype === 2) { // AF_INET, at least on my Linux and OSX machines right now
        ret += print.ip(packet);
    } else if (packet.link.pftype === 30) { // AF_INET6, often
        console.log("pcap.js: print.nulltype() - Don't know how to print IPv6 packets.");
    } else {
        console.log("pcap.js: print.nulltype() - Don't know how to print protocol family " + packet.link.pftype);
    }

    return ret;
};

print.packet = function (packet_to_print) {
    var ret = "";
    switch (packet_to_print.link_type) {
    case "LINKTYPE_ETHERNET":
        ret += print.ethernet(packet_to_print);
        break;
    case "LINKTYPE_NULL":
        ret += print.nulltype(packet_to_print);
        break;
    default:
        console.log("Don't yet know how to print link_type " + packet_to_print.link_type);
    }

    return ret;
};

exports.print = print;

// Meaningfully hold the different types of frames at some point
function WebSocketFrame() {
    this.type = null;
    this.data = "";
}

function WebSocketParser(flag) {
    this.buffer = new Buffer(64 * 1024); // 64KB is the max message size
    this.buffer.end = 0;
    if (flag === "draft76") {
        this.state = "skip_response";
        this.skipped_bytes = 0;
    } else {
        this.state = "frame_type";
    }
    this.frame = new WebSocketFrame();

    events.EventEmitter.call(this);
}
sys.inherits(WebSocketParser, events.EventEmitter);

WebSocketParser.prototype.execute = function (incoming_buf) {
    var pos = 0;

    while (pos < incoming_buf.length) {
        switch (this.state) {
        case "skip_response":
            this.skipped_bytes += 1;
            if (this.skipped_bytes === 16) {
                this.state = "frame_type";
            }
            pos += 1;
            break;
        case "frame_type":
            this.frame.type = incoming_buf[pos];
            pos += 1;
            this.state = "read_until_marker";
            break;
        case "read_until_marker":
            if (incoming_buf[pos] !== 255) {
                this.buffer[this.buffer.end] = incoming_buf[pos];
                this.buffer.end += 1;
                pos += 1;
            } else {
                this.frame.data = this.buffer.toString('utf8', 0, this.buffer.end);
                this.emit("message", this.frame.data);
                this.state = "frame_type";
                this.buffer.end = 0;
                pos += 1;
            }
            break;
        default:
            throw new Error("invalid state " + this.state);
        }
    }
};

function TCP_tracker() {
    this.sessions = {};
    events.EventEmitter.call(this);
}
sys.inherits(TCP_tracker, events.EventEmitter);
exports.TCP_tracker = TCP_tracker;

TCP_tracker.prototype.make_session_key = function (src, dst) {
    return [ src, dst ].sort().join("-");
};

TCP_tracker.prototype.detect_http_request = function (buf) {
    var str = buf.toString('utf8', 0, buf.length);
    
    return (/^(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|COPY|LOCK|MKCOL|MOVE|PROPFIND|PROPPATCH|UNLOCK) [^\s\r\n]+ HTTP\/\d\.\d\r\n/.test(str));
};

TCP_tracker.prototype.session_stats = function (session) {
    var send_acks = Object.keys(session.send_acks),
        recv_acks = Object.keys(session.recv_acks),
        total_time = session.close_time - session.syn_time,
        stats = {};

    send_acks.sort();
    recv_acks.sort();

    stats.recv_times = {};
    send_acks.forEach(function (v) {
        if (session.recv_packets[v]) {
            stats.recv_times[v] = session.send_acks[v] - session.recv_packets[v];
        } else {
            console.log("send ACK with missing recv seqno: " + v);
        }
    });

    stats.send_times = {};
    recv_acks.forEach(function (v) {
        if (session.send_packets[v]) {
            stats.send_times[v] = session.recv_acks[v] - session.send_packets[v];
        } else {
            console.log("recv ACK with missing send seqno: " + v);
        }
    });

    stats.recv_retrans = {};
    Object.keys(session.recv_retrans).forEach(function (v) {
        stats.recv_retrans[v] = session.recv_retrans[v];
    });
    
    stats.total_time = total_time;
    stats.send_overhead = session.send_bytes_ip + session.send_bytes_tcp;
    stats.send_payload = session.send_bytes_payload;
    stats.send_total = stats.send_overhead + stats.send_payload;
    stats.recv_overhead = session.recv_bytes_ip + session.recv_bytes_tcp;
    stats.recv_payload = session.recv_bytes_payload;
    stats.recv_total = stats.recv_overhead + stats.recv_payload;

    if (session.http.request) {
        stats.http_request = session.http.request;
    }

    return stats;
};

TCP_tracker.prototype.setup_http_tracking = function (session) {
    var self = this, http = {};

    http.request_parser = new HTTPParser('request');
    http.request_parser.onMessageBegin = function () {
        http.request = {
            headers: {},
            url: "",
            method: "",
            body_len: 0,
            http_version: null
        };
        http.response = {
            headers: {},
            status_code: null,
            body_len: 0,
            http_version: null
        };

        http.request_parser.onURL = function (buf, start, len) {
            var url_string = buf.toString('ascii', start, start + len);
            if (http.request.url) {
                http.request.url += url_string;
            } else {
                http.request.url = url_string;
            }
        };

        http.request_parser.onHeaderField = function (buf, start, len) {
            var field = buf.toString('ascii', start, start + len);
            if (http.request_parser.header_value) {
                http.request.headers[http.request_parser.header_field] = http.request_parser.header_value;
                http.request_parser.header_field = null;
                http.request_parser.header_value = null;
            }
            if (http.request_parser.header_field) {
                http.request_parser.header_field += field;
            } else {
                http.request_parser.header_field = field;
            }
        };

        http.request_parser.onHeaderValue = function (buf, start, len) {
            var value = buf.toString('ascii', start, start + len);
            if (http.request_parser.header_value) {
                http.request_parser.header_value += value;
            } else {
                http.request_parser.header_value = value;
            }
        };

        http.request_parser.onHeadersComplete = function (info) {
            if (http.request_parser.header_field && http.request_parser.header_value) {
                http.request.headers[http.request_parser.header_field] = http.request_parser.header_value;
            }

            http.request.http_version = info.versionMajor + "." + info.versionMinor;

            http.request.method = info.method;
            self.emit("http_request", session, http);
        };

        http.request_parser.onBody = function (buf, start, len) {
            http.request.body_len += len;
            self.emit("http_request_body", session, http, buf.slice(start, start + len));
        };

        http.request_parser.onMessageComplete = function () {
            self.emit("http_request_complete", session, http);
        };
    };

    http.response_parser = new HTTPParser('response');
    http.response_parser.onMessageBegin = function () {
        http.response_parser.onHeaderField = function (buf, start, len) {
            var field = buf.toString('ascii', start, start + len);
            if (http.response_parser.header_value) {
                http.response.headers[http.response_parser.header_field] = http.response_parser.header_value;
                http.response_parser.header_field = null;
                http.response_parser.header_value = null;
            }
            if (http.response_parser.header_field) {
                http.response_parser.header_field += field;
            } else {
                http.response_parser.header_field = field;
            }
        };

        http.response_parser.onHeaderValue = function (buf, start, len) {
            var value = buf.toString('ascii', start, start + len);
            if (http.response_parser.header_value) {
                http.response_parser.header_value += value;
            } else {
                http.response_parser.header_value = value;
            }
        };

        http.response_parser.onHeadersComplete = function (info) {
            if (http.response_parser.header_field && http.response_parser.header_value) {
                http.response.headers[http.response_parser.header_field] = http.response_parser.header_value;
            }

            http.response.http_version = info.versionMajor + "." + info.versionMinor;
            http.response.status_code = info.statusCode;

            if (http.response.status_code === 101 && http.response.headers.Upgrade === "WebSocket") {
                if (http.response.headers["Sec-WebSocket-Location"]) {
                    self.setup_websocket_tracking(session, "draft76");
                } else {
                    self.setup_websocket_tracking(session);
                }
                self.emit('websocket_upgrade', session, http);
                session.http_detect = false;
                session.websocket_detect = true;
                delete http.response_parser.onMessageComplete;
            } else {
                self.emit('http_response', session, http);
            }
        };

        http.response_parser.onBody = function (buf, start, len) {
            http.response.body_len += len;
            self.emit('http_response_body', session, http, buf.slice(start, start + len));
        };
        
        http.response_parser.onMessageComplete = function () {
            self.emit('http_response_complete', session, http);
        };
    };

    session.http = http;
};

TCP_tracker.prototype.setup_websocket_tracking = function (session, flag) {
    var self = this;

    session.websocket_parser_send = new WebSocketParser();
    session.websocket_parser_send.on("message", function (message_string) {
        self.emit("websocket_message", session, "send", message_string);
    });
    session.websocket_parser_recv = new WebSocketParser(flag);
    session.websocket_parser_recv.on("message", function (message_string) {
        self.emit("websocket_message", session, "recv", message_string);
    });
};

TCP_tracker.prototype.track_states = {};

TCP_tracker.prototype.track_states.SYN_SENT = function (packet, session) {
    var ip  = packet.link.ip,
        tcp = ip.tcp,
        src = ip.saddr + ":" + tcp.sport;

    if (src === session.dst && tcp.flags.syn && tcp.flags.ack) {
        session.recv_bytes_ip += ip.header_bytes;
        session.recv_bytes_tcp += tcp.header_bytes;
        session.recv_packets[tcp.seqno + 1] = packet.pcap_header.time_ms;
        session.recv_acks[tcp.ackno] = packet.pcap_header.time_ms;
        session.recv_isn = tcp.seqno;
        session.recv_window_scale = tcp.options.window_scale || 1; // multiplier, not bit shift value
        session.state = "SYN_RCVD";
    } else if (tcp.flags.rst) {
        console.log("Connection reset by receiver -> CLOSED");
        session.state = "CLOSED";
    } else {
        console.log("Didn't get SYN-ACK packet from dst while handshaking: " + sys.inspect(tcp, false, 4));
    }
};

TCP_tracker.prototype.track_states.SYN_RCVD = function (packet, session) {
    var ip  = packet.link.ip,
        tcp = ip.tcp,
        src = ip.saddr + ":" + tcp.sport;

    if (src === session.src && tcp.flags.ack) { // TODO - make sure SYN flag isn't set, also match src and dst
        session.send_bytes_ip += ip.header_bytes;
        session.send_bytes_tcp += tcp.header_bytes;
        session.send_acks[tcp.ackno] = packet.pcap_header.time_ms;
        session.handshake_time = packet.pcap_header.time_ms;
        this.emit('start', session);
        session.state = "ESTAB";
    } else {
        console.log("Didn't get ACK packet from src while handshaking: " + sys.inspect(tcp, false, 4));
    }
};

TCP_tracker.prototype.track_states.ESTAB = function (packet, session) {
    var ip  = packet.link.ip,
        tcp = ip.tcp,
        src = ip.saddr + ":" + tcp.sport;
        
// if (tcp.options.sack) {
//     console.log("SACK magic, handle this: " + sys.inspect(tcp.options.sack));
//     console.log(sys.inspect(ip, false, 5));
// }

    if (src === session.src) { // this packet came from the active opener / client
        session.send_bytes_ip += ip.header_bytes;
        session.send_bytes_tcp += tcp.header_bytes;
        if (tcp.data_bytes) {
            if (session.send_bytes_payload === 0) {
                session.http_detect = this.detect_http_request(tcp.data);
                if (session.http_detect) {
                    this.setup_http_tracking(session);
                }
            }
            session.send_bytes_payload += tcp.data_bytes;
            if (session.send_packets[tcp.seqno + tcp.data_bytes]) {
                console.log("Retransmission send of segment " + (tcp.seqno - session.send_isn + tcp.data_bytes));
            } else {
                if (session.http_detect) {
                    try {
                        session.http.request_parser.execute(tcp.data, 0, tcp.data.length);
                    } catch (request_err) {
                        console.log("HTTP request parser exception: " + request_err.stack);
                    }
                } else if (session.websocket_detect) {
                    session.websocket_parser_send.execute(tcp.data);
                }
            }
            session.send_packets[tcp.seqno + tcp.data_bytes] = packet.pcap_header.time_ms;
        }
        if (session.recv_packets[tcp.ackno]) {
            if (session.send_acks[tcp.ackno]) {
                //                    console.log("Already sent this ACK, which I'm guessing is fine.");
            } else {
                session.send_acks[tcp.ackno] = packet.pcap_header.time_ms;
            }
        } else {
            console.log("sending ACK for packet we didn't see received: " + tcp.ackno);
        }
        if (tcp.flags.fin) {
            session.state = "FIN_WAIT";
        }
    } else if (src === session.dst) { // this packet came from the passive opener / server
        session.recv_bytes_ip += ip.header_bytes;
        session.recv_bytes_tcp += tcp.header_bytes;
        if (tcp.data_bytes) {
            session.recv_bytes_payload += tcp.data_bytes;
            if (session.recv_packets[tcp.seqno + tcp.data_bytes]) {
                console.log("Retransmission recv of segment " + (tcp.seqno - session.recv_isn + tcp.data_bytes));
                if (session.recv_retrans[tcp.seqno + tcp.data_bytes]) {
                    session.recv_retrans[tcp.seqno + tcp.data_bytes] += 1;
                } else {
                    session.recv_retrans[tcp.seqno + tcp.data_bytes] = 1;
                }
            } else {
                if (session.http_detect) {
                    try {
                        session.http.response_parser.execute(tcp.data, 0, tcp.data.length);
                    } catch (response_err) {
                        console.log("HTTP response parser exception: " + response_err.stack);
                    }
                } else if (session.websocket_detect) {
                    session.websocket_parser_recv.execute(tcp.data);
                }
            }
            session.recv_packets[tcp.seqno + tcp.data_bytes] = packet.pcap_header.time_ms;
        }
        if (session.send_packets[tcp.ackno]) {
            if (session.recv_acks[tcp.ackno]) {
                //                    console.log("Already received this ACK, which I'm guessing is fine.");
            } else {
                session.recv_acks[tcp.ackno] = packet.pcap_header.time_ms;
            }
        } else {
            console.log("receiving ACK for packet we didn't see sent: " + tcp.ackno);
        }
        if (tcp.flags.fin) {
            session.state = "CLOSE_WAIT";
        }
    } else {
        console.log("non-matching packet in session: " + sys.inspect(packet));
    }
};

TCP_tracker.prototype.track_states.FIN_WAIT = function (packet, session) {
    var ip  = packet.link.ip,
        tcp = ip.tcp,
        src = ip.saddr + ":" + tcp.sport;

    // TODO - need to track half-closed data
    if (src === session.dst && tcp.flags.fin) {
        session.state = "CLOSING";
    }
};

TCP_tracker.prototype.track_states.CLOSE_WAIT = function (packet, session) {
    var ip  = packet.link.ip,
        tcp = ip.tcp,
        src = ip.saddr + ":" + tcp.sport;

    // TODO - need to track half-closed data
    if (src === session.src && tcp.flags.fin) {
        session.state = "LAST_ACK";
    }
};

TCP_tracker.prototype.track_states.LAST_ACK = function (packet, session) {
    var ip  = packet.link.ip,
        tcp = ip.tcp,
        src = ip.saddr + ":" + tcp.sport;

    // TODO - need to track half-closed data
    if (src === session.dst) {
        session.close_time = packet.pcap_header.time_ms;
        session.state = "CLOSED";
        delete this.sessions[session.key];
        this.emit('end', session);
    }
};

TCP_tracker.prototype.track_states.CLOSING = function (packet, session) {
    var ip  = packet.link.ip,
        tcp = ip.tcp,
        src = ip.saddr + ":" + tcp.sport;

    // TODO - need to track half-closed data
    if (src === session.src) {
        session.close_time = packet.pcap_header.time_ms;
        session.state = "CLOSED";
        delete this.sessions[session.key];
        this.emit('end', session);
    }
};

TCP_tracker.prototype.track_states.CLOSED = function (packet, session) {
    var ip  = packet.link.ip,
        tcp = ip.tcp,
        src = ip.saddr + ":" + tcp.sport;

    // The states aren't quite right here.  All possible states of FIN and FIN/ACKs aren't handled.
    // So some of the bytes of the session may not be properly accounted for.
};

TCP_tracker.prototype.track_next = function (key, packet) {
    var session = this.sessions[key];

    if (typeof session !== 'object') {
        throw new Error("track_next: couldn't find session for " + key);
    }

    if (typeof this.track_states[session.state] === 'function') {
        this.track_states[session.state].call(this, packet, session);
    } else {
        console.log(sys.debug(session));
        throw new Error("Don't know how to handle session state " + session.state);
    }
};

TCP_tracker.prototype.track_packet = function (packet) {
    var ip, tcp, src, dst, key, session, self = this;

    if (packet.link && packet.link.ip && packet.link.ip.tcp) {
        ip  = packet.link.ip;
        tcp = ip.tcp;
        src = ip.saddr + ":" + tcp.sport;
        dst = ip.daddr + ":" + tcp.dport;
        key = this.make_session_key(src, dst);
        session = this.sessions[key];

        if (tcp.flags.syn && !tcp.flags.ack) {
            if (session === undefined) {
                this.sessions[key] = {
                    src: src, // the side the sent the initial SYN
                    dst: dst, // the side that the initial SYN was sent to
                    syn_time: packet.pcap_header.time_ms,
                    state: "SYN_SENT",
                    key: key, // so we can easily remove ourselves

                    send_isn: tcp.seqno,
                    send_window_scale: tcp.options.window_scale || 1, // multipler, not bit shift value
                    send_packets: {}, // send_packets is indexed by the expected ackno: seqno + length
                    send_acks: {},
                    send_retrans: {},
                    send_next_seq: tcp.seqno + 1,
                    send_acked_seq: null,
                    send_bytes_ip: ip.header_bytes,
                    send_bytes_tcp: tcp.header_bytes,
                    send_bytes_payload: 0,

                    recv_isn: null,
                    recv_window_scale: null,
                    recv_packets: {},
                    recv_acks: {},
                    recv_retrans: {},
                    recv_next_seq: null,
                    recv_acked_seq: null,
                    recv_bytes_ip: 0,
                    recv_bytes_tcp: 0,
                    recv_bytes_payload: 0
                };
                session = this.sessions[key];
                session.send_packets[tcp.seqno + 1] = packet.pcap_header.time_ms;
                session.src_name = dns_cache.ptr(ip.saddr, function (name) {
                    session.src_name = name + ":" + tcp.sport;
                    self.emit("reverse", ip.saddr, name);
                }) + ":" + tcp.sport;
                session.dst_name = dns_cache.ptr(ip.daddr, function (name) {
                    session.dst_name = name + ":" + tcp.dport;
                    self.emit("reverse", ip.daddr, name);
                }) + ":" + tcp.dport;
                session.current_cap_time = packet.pcap_header.time_ms;
            } else { // SYN retry
                console.log("SYN retry from " + src + " to " + dst);
            }
        } else { // not a SYN
            if (session) {
                session.current_cap_time = packet.pcap_header.time_ms;
                this.track_next(key, packet);
            } else {
                // silently ignore session in progress
            }
        }
    } else {
        throw new Error("tcp_tracker.track_packet fed a non-IPv4 TCP packet: " + sys.inspect(packet));
    }
};

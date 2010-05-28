"use strict";
/*global process require exports */

var sys     = require("sys"),
    dns     = require("dns"),
    Buffer  = require('buffer').Buffer,
    events  = require("events"),
    binding = require("./build/default/binding");

function Pcap() {
    this.opened = false;
    this.fd = null;

    events.EventEmitter.call(this);
}
sys.inherits(Pcap, events.EventEmitter);

Pcap.prototype.findalldevs = function () {
    return binding.findalldevs();
};

Pcap.prototype.open_live = function (device, filter) {
    var me = this;

    this.device_name = device || binding.default_device();
    this.link_type = binding.open_live(this.device_name, filter);
    this.fd = binding.fileno();
    this.opened = true;
    this.readWatcher = new process.IOWatcher();
    this.empty_reads = 0;
    this.buf = new Buffer(65535);

    this.readWatcher.callback = function () {
        var packets_read = binding.dispatch(me.buf, function (header) {
            header.link_type = me.link_type;
            me.buf.pcap_header = header;
            me.emit('packet', me.buf);
        });
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
    session.open_live(device, filter);
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
        sys.puts(i + ": " + raw_packet[i]);
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

var decode = {
    packet: function (raw_packet) {
        var packet = {};

        switch (raw_packet.pcap_header.link_type) {
        case "LINKTYPE_ETHERNET":
            packet.link = decode.ethernet(raw_packet, 0);
            break;
        case "LINKTYPE_NULL":
            packet.link = decode.nulltype(raw_packet, 0);
            break;
        default:
            sys.puts("Don't yet know how to decode link type " + raw_packet.pcap_header.link_type);
        }

        packet.pcap_header = raw_packet.pcap_header; // TODO - merge values here instead of putting ref on packet buffer

        return packet;
    },
    nulltype: function (raw_packet, offset) {
        var ret = {};
        ret.pftype = raw_packet[0];  // this is a pretty big hack as the compiler is the only one that knows this for sure.
        if (ret.pftype === 2) { // AF_INET, at least on my Linux and OSX machines right now
            ret.ip = decode.ip(raw_packet, 4);
        }
        else {
            sys.puts("Don't know how to decode protocol family " + ret.pftype);
        }

        return ret;
    },
    ethernet: function (raw_packet, offset) {
        var ret = {};
        ret.dhost = unpack.ethernet_addr(raw_packet, 0);
        ret.shost = unpack.ethernet_addr(raw_packet, 6);
        ret.ethertype = unpack.uint16(raw_packet, 12);

        // http://en.wikipedia.org/wiki/EtherType
        switch (ret.ethertype) {
        case 2048: // 0x0800 - IPv4
            ret.ip = decode.ip(raw_packet, 14);
            break;
        case 2054: // ARP
            ret.arp = decode.arp(raw_packet, 14);
            break;
        default:
            sys.puts("Don't know how to decode ethertype " + ret.ethertype);
        }

        return ret;
    },
    arp: function (raw_packet, offset) {
        var ret = {};
    
        // http://en.wikipedia.org/wiki/Address_Resolution_Protocol
        ret.htype = unpack.uint16(raw_packet, 0); // 0, 1
        ret.ptype = unpack.uint16(raw_packet, 2); // 2, 3
        ret.hlen = raw_packet[4];
        ret.plen = raw_packet[5];
        ret.operation = unpack.uint16(raw_packet, 6); // 6, 7
        if (ret.operation === 1) {
            ret.operation = "request";
        }
        else if (ret.operation === 2) {
            ret.operation = "reply";
        }
        else {
            ret.operation = "unknown";
        }
        ret.sender_ha = unpack.uint16(raw_packet, 8); // 8, 9
        ret.sender_pa = unpack.uint16(raw_packet, 10); // 10, 11
        ret.target_ha = unpack.uint16(raw_packet, 12); // 12, 13
        ret.target_pa = unpack.uint16(raw_packet, 14); // 14, 15
    
        return ret;
    },
    ip: function (raw_packet, offset) {
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
        case 6:
            ret.protocol_name = "TCP";
            ret.tcp = decode.tcp(raw_packet, offset + (ret.header_length * 4));
            ret.data_offset = offset + ret.header_bytes + ret.tcp.header_bytes;
            ret.data_bytes = (offset + ret.total_length) - ret.data_offset;
            if (ret.data_bytes > 0) {
                ret.data = raw_packet.slice(ret.data_offset, (ret.data_offset + ret.total_length));
                ret.data.length = ret.data_bytes;
            }
            break;
        case 17:
            ret.protocol_name = "UDP";
            break;
        default:
            ret.protocol_name = "Unknown";
        }

        return ret;
    },
    icmp: function (raw_packet, offset) {
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
    },
    tcp: function (raw_packet, offset) {
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
                    sys.puts("Invalid TCP SACK option length " + raw_packet[option_offset + 1]);
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

        // automatic protocol decode ends here.  Higher level protocols can be decoded by using payload.
        return ret;
    }
};
exports.decode = decode;

function format_rate(bytes, ms) {
    return ((bytes * 8 * 1024) / (ms * 1000)).toFixed(2);
}

function make_session_key(src, dst) {
    return [ src, dst ].sort().join("-");
};

function parse_http_request(buf) {
    var str = buf.toString('utf8', 0, buf.length),
        matches = /^(GET|POST) ([^\s]+) /.exec(str);

    if (matches) {
        return {
            method: matches[1],
            url: matches[2]
        };
    }
    else {
        return null;
    }
}

function TCP_tracker() {
    this.sessions = {};
    events.EventEmitter.call(this);
}
sys.inherits(TCP_tracker, events.EventEmitter);
exports.TCP_tracker = TCP_tracker;

TCP_tracker.prototype.session_stats = function (session) {
    var send_acks = Object.keys(session.send_acks),
        recv_acks = Object.keys(session.recv_acks),
        total_time = session.close_time - session.syn_time,
        stats = {};

    send_acks.sort();
    recv_acks.sort();

    send_acks.forEach(function (v) {
        if (session.recv_packets[v]) {
            //                sys.puts("RTT for recv seqno " + v + ": " + (session.send_acks[v] - session.recv_packets[v]) + "ms");
        } else {
            sys.puts("send ACK with missing recv seqno: " + v);
        }
    });

    recv_acks.forEach(function (v) {
        if (session.send_packets[v]) {
            //                sys.puts("RTT for send seqno " + v + ": " + (session.recv_acks[v] - session.send_packets[v]) + "ms");
        } else {
            sys.puts("recv ACK with missing send seqno: " + v);
        }
    });

    stats.total_time = total_time;
    stats.send_overhead = session.send_bytes_ip + session.send_bytes_tcp;
    stats.send_total = stats.send_overhead + session.send_bytes_payload;
    stats.recv_overhead = session.recv_bytes_ip + session.recv_bytes_tcp;
    stats.recv_total = stats.recv_overhead + session.recv_bytes_payload;

    if (session.http_request) {
        stats.http_request = session.http_request;
    }

    return stats;
};

TCP_tracker.prototype.track_next = function (key, packet) {
    var ip      = packet.link.ip,
        tcp     = ip.tcp;
        src     = ip.saddr + ":" + tcp.sport;
        dst     = ip.daddr + ":" + tcp.dport;
        key     = make_session_key(src, dst),
        session = this.sessions[key];

    if (typeof session !== 'object') {
        throw new Error("track_next: couldn't find session for " + key);
    }

    switch (session.state) {
    case "SYN_SENT":
        if (src === session.dst && tcp.flags.syn && tcp.flags.ack) {
            session.recv_bytes_ip += ip.header_bytes;
            session.recv_bytes_tcp += tcp.header_bytes;
            session.recv_packets[tcp.seqno + 1] = packet.pcap_header.time.getTime();
            session.recv_acks[tcp.ackno] = packet.pcap_header.time.getTime();
            session.isn_dst = tcp.seqno;
            session.state = "SYN_RCVD";
        } else {
            sys.puts("Didn't get SYN-ACK packet from dst while handshaking: " + sys.inspect(packet));
        }
        break;
    case "SYN_RCVD":
        if (src === session.src && tcp.flags.ack) { // TODO - make sure SYN flag isn't set, also match src and dst
            session.send_bytes_ip += ip.header_bytes;
            session.send_bytes_tcp += tcp.header_bytes;
            session.send_acks[tcp.ackno] = packet.pcap_header.time.getTime();
            session.handshake_time = packet.pcap_header.time.getTime() - session.syn_time;
            this.emit('start', session);
            session.state = "ESTAB";
        } else {
            sys.puts("Didn't get ACK packet from src while handshaking: " + sys.inspect(packet));
        }
        break;
    case "ESTAB":
        if (src === session.src) {
            session.send_bytes_ip += ip.header_bytes;
            session.send_bytes_tcp += tcp.header_bytes;
            if (ip.data_bytes) {
                if (session.send_bytes_payload === 0) {
                    session.http_request = parse_http_request(ip.data);
                    if (session.http_request) {
                        this.emit('http_request', session);
                    }
                }
                session.send_bytes_payload += ip.data_bytes;
                session.send_packets[tcp.seqno + ip.data_bytes] = packet.pcap_header.time.getTime();
            }
            if (session.recv_packets[tcp.ackno]) {
                if (session.send_acks[tcp.ackno]) {
                    // sys.puts("Already sent this ACK, which I'm guessing is fine.");
                } else {
                    session.send_acks[tcp.ackno] = packet.pcap_header.time.getTime();
                }
            } else {
                sys.puts("sending ACK for packet we didn't see received.");
            }
            if (tcp.flags.fin) {
                sys.puts("FIN send -> FIN_WAIT");
                session.state = "FIN_WAIT";
            }
        } else if (src === session.dst) {
            session.recv_bytes_ip += ip.header_bytes;
            session.recv_bytes_tcp += tcp.header_bytes;
            if (ip.data_bytes) {
                session.recv_bytes_payload += ip.data_bytes;
                session.recv_packets[tcp.seqno + ip.data_bytes] = packet.pcap_header.time.getTime();
            }
            if (session.send_packets[tcp.ackno]) {
                if (session.recv_acks[tcp.ackno]) {
                    // sys.puts("Already received this ACK, which I'm guessing is fine.");
                } else {
                    session.recv_acks[tcp.ackno] = packet.pcap_header.time.getTime();
                }
            } else {
                sys.puts("receiving ACK for packet we didn't see sent.");
            }
            if (tcp.flags.fin) {
                sys.puts("FIN received -> CLOSE_WAIT");
                session.state = "CLOSE_WAIT";
            }
        } else {
            sys.puts("non-matching packet in session: " + sys.inspect(packet));
        }
        break;
    case "FIN_WAIT":
        if (src === session.dst && tcp.flags.fin) {
            sys.puts("FIN received -> CLOSING");
            session.state = "CLOSING";
        }
        break;
    case "CLOSE_WAIT":
        if (src === session.src && tcp.flags.fin) {
            sys.puts("FIN sent -> LAST_ACK");
            session.state = "LAST_ACK";
        }
        break;
    case "LAST_ACK":
        if (src === session.dst) {
            sys.puts("LAST_ACK -> CLOSED");
            session.close_time = packet.pcap_header.time.getTime();
            session.state = "CLOSED";
            this.emit('end', session);
        }
        break;
    case "CLOSING":
        if (src === session.src) {
            sys.puts("CLOSING -> CLOSED");
            session.close_time = packet.pcap_header.time.getTime();
            session.state = "CLOSED";
            this.emit('end', session);
        }
        break;
    case "CLOSED":
        // The states aren't quite right here.  All possible states of FIN and FIN/ACKs aren't handled.
        // So some of the bytes of the session may not be properly accounted for.
        // sys.puts("Got packet for CLOSED session: " + sys.inspect(ip));
        break;
    default:
        sys.puts(sys.debug(session));
        throw new Error("Don't know how to handle session state " + session.state);
    }
};

TCP_tracker.prototype.track_packet = function (packet) {
    var ip, tcp, src, dst, key;

    if (packet.link && packet.link.ip && packet.link.ip.tcp) {
        ip  = packet.link.ip;
        tcp = ip.tcp;
        src = ip.saddr + ":" + tcp.sport;
        dst = ip.daddr + ":" + tcp.dport;
        key = make_session_key(src, dst);

        if (this.sessions[key] === undefined) {
            if (tcp.flags.syn && !tcp.flags.ack) {
                this.sessions[key] = {
                    src: src, // the side the sent the initial SYN
                    dst: dst, // the side that the initial SYN was sent to
                    syn_time: packet.pcap_header.time,
                    state: "SYN_SENT",
                    isn_src: tcp.seqno,
                    recv_packets: {},
                    recv_acks: {},
                    recv_bytes_ip: 0,
                    recv_bytes_tcp: 0,
                    recv_bytes_payload: 0,
                    send_packets: {}, // send_packets is indexed by the expected ackno: seqno + length
                    send_acks: {},
                    send_bytes_ip: ip.header_bytes,
                    send_bytes_tcp: tcp.header_bytes,
                    send_bytes_payload: 0
                };
                this.sessions[key].send_packets[tcp.seqno + 1] = packet.pcap_header.time.getTime();
            }
            // silently ignore session in progress
        } else {
            this.track_next(key, packet);
        }
    } else {
        throw new Error("tcp_tracker.track_packet fed a non-TCP packet: " + sys.inspect(packet));
    }
};

var dns_cache = (function () {
    var cache = {},
        requests = {};

    function lookup_ptr(ip) {
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
                    }
                    else {
                        cache[ip] = domains[0];
                    }
                    delete requests[ip];
                });
            }
            return ip;
        }
    }
    
    return {
        ptr: function (ip) {
            return lookup_ptr(ip);
        }
    };
}());
exports.dns_cache = dns_cache;



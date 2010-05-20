var sys = require("sys"),
    Buffer = require('buffer').Buffer,
    binding = require("./build/default/binding"),
    events = require("events");

function Pcap () {
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
    sys.debug("Link type: " + this.link_type);
    this.fd = binding.fileno();
    this.opened = true;
    this.readWatcher = new process.IOWatcher();
    this.buf = new Buffer(65535);

    this.readWatcher.callback = function () {
        var packets_read = binding.dispatch(me.buf, function (header) {
            me.emit('packet', header, me.buf);
        });
        if (packets_read !== 1) {
            sys.debug("readWatcher callback fired and dispatch read " + packets_read + " packets instead of 1");
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

function dump_bytes(pcap_header, raw_packet) {
    for (var i = 0; i < pcap_header.caplen ; i += 1) {
        sys.puts(i + ": " + raw_packet[i]);
    }
}

function unpack_ethernet_addr(raw_packet, offset) {
    return [
        lpad(raw_packet[offset].toString(16), 2),
        lpad(raw_packet[offset + 1].toString(16), 2),
        lpad(raw_packet[offset + 2].toString(16), 2),
        lpad(raw_packet[offset + 3].toString(16), 2),
        lpad(raw_packet[offset + 4].toString(16), 2),
        lpad(raw_packet[offset + 5].toString(16), 2)
    ].join(":");
}

function unpack_uint16(raw_packet, offset) {
    return ((raw_packet[offset] * 256) + raw_packet[offset + 1]);
}

function unpack_uint32(raw_packet, offset) {
    return (
        (raw_packet[offset] * 16777216) + 
        (raw_packet[offset + 1] * 65536) +
        (raw_packet[offset + 2] * 256) + 
        raw_packet[offset + 3]
    );
}

function decode_ethernet(raw_packet, offset) {
    var ret = {};
    ret.dhost = unpack_ethernet_addr(raw_packet, 0);
    ret.shost = unpack_ethernet_addr(raw_packet, 6);
    ret.ethertype = unpack_uint16(raw_packet, 12);
    // http://en.wikipedia.org/wiki/EtherType

    return ret;
}

function unpack_ipv4_addr(raw_packet, offset) {
    return [
        raw_packet[offset],
        raw_packet[offset + 1],
        raw_packet[offset + 2],
        raw_packet[offset + 3]
    ].join('.');
}

function decode_ip(raw_packet, offset) {
    var ret = {};
    // http://en.wikipedia.org/wiki/IPv4
    ret.version = (raw_packet[offset] & 240) >> 4; // first 4 bits
    ret.header_length = raw_packet[offset] & 15; // second 4 bits
    ret.diffserv = raw_packet[offset + 1];
    ret.total_length = unpack_uint16(raw_packet, offset + 2); // 2, 3
    ret.identification = unpack_uint16(raw_packet, offset + 4); // 4, 5
    ret.flag_reserved = (raw_packet[offset + 6] & 128) >> 7;
    ret.flag_df = (raw_packet[offset + 6] & 64) >> 6;
    ret.flag_mf = (raw_packet[offset + 6] & 32) >> 5;
    ret.fragment_offset = ((raw_packet[offset + 6] & 31) * 256) + raw_packet[offset + 7]; // 13-bits from 6, 7
    ret.ttl = raw_packet[offset + 8];
    ret.protocol = raw_packet[offset + 9];
    ret.header_checksum = unpack_uint16(raw_packet, offset + 10); // 10, 11
    ret.saddr = unpack_ipv4_addr(raw_packet, offset + 12); // 12, 13, 14, 15
    ret.daddr = unpack_ipv4_addr(raw_packet, offset + 16); // 16, 17, 18, 19

    // TODO - parse IP "options" if header_length > 5
    return ret;
}

function decode_tcp(raw_packet, offset) {
    var ret = {};

    // http://en.wikipedia.org/wiki/Transmission_Control_Protocol
    ret.sport = unpack_uint16(raw_packet, offset); // 0, 1
    ret.dport = unpack_uint16(raw_packet, offset + 2); // 2, 3
    ret.seqno = unpack_uint32(raw_packet, 4); // 4, 5, 6, 7
    ret.ackno = unpack_uint32(raw_packet, 8); // 8, 9, 10, 11
    ret.data_offset = (raw_packet[offset + 12] & 240) >> 4; // first 4 bits of 12
    ret.reserved = raw_packet[offset + 12] & 15; // second 4 bits of 12
    ret.flag_cwr = (raw_packet[offset + 13] & 128) >> 7; // all flags packed into 13
    ret.flag_ece = (raw_packet[offset + 13] & 64) >> 6;
    ret.flag_urg = (raw_packet[offset + 13] & 32) >> 5;
    ret.flag_ack = (raw_packet[offset + 13] & 16) >> 4;
    ret.flag_psh = (raw_packet[offset + 13] & 8) >> 3;
    ret.flag_rst = (raw_packet[offset + 13] & 4) >> 2;
    ret.flag_syn = (raw_packet[offset + 13] & 2) >> 1;
    ret.flag_fin = raw_packet[offset + 13] & 1;
    ret.window_size = unpack_uint16(raw_packet, offset + 14); // 14, 15
    ret.checksum = unpack_uint16(raw_packet, offset + 16); // 16, 17
    ret.urgent_pointer = unpack_uint16(raw_packet, offset + 18); // 18, 19
    
    // TODO - parse TCP "options" if data_offset > 5

    return ret;
}

exports.decode_packet = function (pcap_header, raw_packet) {
    var packet = {};

    // TODO - this needs to handle different link types and associated offsets
    if (session.link_type === "LINKTYPE_ETHERNET") {
        packet.ethernet = decode_ethernet(raw_packet, 0);

        switch(packet.ethernet.ethertype) {
            case 2048: // 0x0800 - IPv4
                packet.ip = decode_ip(raw_packet, 14);

                switch (packet.ip.protocol) {
                    case 1:
                        packet.ip.protocol_name = "ICMP";
                        break;
                    case 6:
                        packet.ip.protocol_name = "TCP";
                        packet.tcp = decode_tcp(raw_packet, 14 + (packet.ip.header_length * 4));
                        packet.payload_offset = 14 + (packet.ip.header_length * 4) + (packet.tcp.data_offset * 4);
                        packet.payload = raw_packet.slice(packet.payload_offset, pcap_header.caplen);
                        break;
                    case 17:
                        packet.ip.protocol_name = "UDP";
                        break;
                    default:
                        packet.ip.protocol_name = "Unknown";
                }
                break;
            case 2054: // ARP
                sys.puts("Don't yet know how to decode ARP packets");
                break;
            default:
                sys.puts("Don't know how to decode ethertype " + packet.ethertype);
        }
    }
    else {
        sys.puts("Don't know how to decode link type " + session.link_type);
    }
    
    return packet;
};


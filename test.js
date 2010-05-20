var sys = require("sys"),
    pcap = require("./pcap"),
    count = 0,
    start_time = new Date();

//sys.puts(sys.inspect(pcap));

session = pcap.createSession("en0", "port 22");

sys.puts(sys.inspect(session.findalldevs(), false, 4));

function lpad(str, len) {
    while (str.length < len) {
        str = "0" + str;
    }
    return str;
}

function decode_packet(pcap_header, raw_packet) {
    var packet = {};

    // for (var i = 0; i < pcap_header.caplen ; i += 1) {
    //     sys.puts(i + ": " + raw_packet[i]);
    // }

    // TODO - this needs to be split out to handle different link types and associated offsets
    if (session.link_type === "LINKTYPE_ETHERNET") {
        packet.ethernet = {};
        packet.ethernet.dhost = [
            lpad(raw_packet[0].toString(16), 2),
            lpad(raw_packet[1].toString(16), 2),
            lpad(raw_packet[2].toString(16), 2),
            lpad(raw_packet[3].toString(16), 2),
            lpad(raw_packet[4].toString(16), 2),
            lpad(raw_packet[5].toString(16), 2)
        ].join(":");
        packet.ethernet.shost = [
            lpad(raw_packet[6].toString(16), 2),
            lpad(raw_packet[7].toString(16), 2),
            lpad(raw_packet[8].toString(16), 2),
            lpad(raw_packet[9].toString(16), 2),
            lpad(raw_packet[10].toString(16), 2),
            lpad(raw_packet[11].toString(16), 2)
        ].join(":");

        packet.ethernet.ethertype = (raw_packet[12] * 256) + raw_packet[13];

        // http://en.wikipedia.org/wiki/EtherType
        switch(packet.ethernet.ethertype) {
            case 2048: // IPv4 - http://en.wikipedia.org/wiki/IPv4
                packet.ip = {};
                packet.ip.version = (raw_packet[14] & 240) >> 4;
                packet.ip.header_length = raw_packet[14] & 15;
                packet.ip.diffserv = raw_packet[15];
                packet.ip.total_length = (raw_packet[16] * 256) + raw_packet[17];
                packet.ip.identification = (raw_packet[18] * 256) + raw_packet[19];
                packet.ip.flag_reserved = (raw_packet[20] & 128) >> 7;
                packet.ip.flag_df = (raw_packet[20] & 64) >> 6;
                packet.ip.flag_mf = (raw_packet[20] & 32) >> 5;
                packet.ip.fragment_offset = ((raw_packet[20] & 31) * 256) + raw_packet[21];
                packet.ip.ttl = raw_packet[22];
                packet.ip.protocol = raw_packet[23];
                packet.ip.header_checksum = (raw_packet[24] * 256) + raw_packet[25];
                packet.ip.saddr = raw_packet[26] + "." + raw_packet[27] + "." + raw_packet[28] + ";" + raw_packet[29];
                packet.ip.daddr = raw_packet[30] + "." + raw_packet[31] + "." + raw_packet[32] + ";" + raw_packet[33];

                switch (packet.ip.protocol) {
                    case 1:
                        packet.ip.protocol_name = "ICMP";
                        break;
                    case 6: // http://en.wikipedia.org/wiki/Transmission_Control_Protocol
                        packet.ip.protocol_name = "TCP";
                        packet.tcp = {};
                        packet.tcp.sport = (raw_packet[34] * 256) + raw_packet[35];
                        packet.tcp.dport = (raw_packet[36] * 256) + raw_packet[37];
                        packet.tcp.seqno = (raw_packet[38] * 16777216) + (raw_packet[39] * 65536) + (raw_packet[40] * 256) + raw_packet[41];
                        packet.tcp.ackno = (raw_packet[42] * 16777216) + (raw_packet[43] * 65536) + (raw_packet[44] * 256) + raw_packet[45];
                        packet.tcp.data_offset = (raw_packet[46] & 240) >> 4;
                        packet.tcp.reserved = raw_packet[46] & 15;
                        packet.tcp.flag_cwr = (raw_packet[47] & 128) >> 7;
                        packet.tcp.flag_ece = (raw_packet[47] & 64) >> 6;
                        packet.tcp.flag_urg = (raw_packet[47] & 32) >> 5;
                        packet.tcp.flag_ack = (raw_packet[47] & 16) >> 4;
                        packet.tcp.flag_psh = (raw_packet[47] & 8) >> 3;
                        packet.tcp.flag_rst = (raw_packet[47] & 4) >> 2;
                        packet.tcp.flag_syn = (raw_packet[47] & 2) >> 1;
                        packet.tcp.flag_fin = raw_packet[47] & 1;
                        packet.tcp.window_size = (raw_packet[48] * 256) + raw_packet[49];
                        packet.tcp.checksum = (raw_packet[50] * 256) + raw_packet[51];
                        packet.tcp.urgent_pointer = (raw_packet[52] * 256) + raw_packet[53];
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

session.addListener('packet', function (pcap_header, raw_packet) {
    count += 1;
    decoded = decode_packet(pcap_header, raw_packet);
    sys.puts((pcap_header.time - start_time) + "ms len: " + pcap_header.len + " " + 
        decoded.ethernet.shost + " " + decoded.ethernet.dhost + " " +
        sys.inspect(decoded.ip) + sys.inspect(decoded.tcp)
    );
});

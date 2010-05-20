var sys = require("sys"),
    pcap = require("./pcap"),
    count = 0,
    start_time = new Date();

session = pcap.createSession("en1", "port 6667");

sys.puts("All devices: ");
sys.puts(sys.inspect(session.findalldevs(), false, 4));

session.addListener('packet', function (pcap_header, raw_packet) {
    decoded = pcap.decode_packet(pcap_header, raw_packet);
    sys.puts(pcap_header.len + " " + 
        decoded.ip.saddr + ":" + decoded.tcp.sport + " -> " +
        decoded.ip.daddr + ":" + decoded.tcp.dport + " " +
        decoded.payload
    );
    sys.puts(sys.inspect(session.stats()));
});

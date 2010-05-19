var sys = require("sys"),
    pcap = require("./pcap"),
    count = 0;

//sys.puts(sys.inspect(pcap));

session = pcap.createSession("en0", "port 22");

sys.puts(sys.inspect(session.findalldevs(),false,4));

session.addListener('packet', function (header, packet) {
    count += 1;
    sys.puts("Header:");
    sys.puts(sys.inspect(header));
    sys.puts("Packet:");
    var i;
    for (i = 0; i < header.caplen; i += 1) {
        sys.puts(i + ": " + packet[i]);
    }
    sys.puts(sys.inspect(session.stats()));
});

var sys = require("sys"),
    pcap = require("./pcap");

sys.puts(sys.inspect(pcap));

session = pcap.createSession("en0", "port 22");

session.addListener('packet', function (header, packet) {
    sys.puts("Header:");
    sys.puts(sys.inspect(header));
    sys.puts("Packet:");
    var i;
    for (i = 0; i < header.caplen; i += 1) {
        sys.puts(i + ": " + packet[i]);
    }
});

setTimeout(function () {
    session.close();
}, 10000);

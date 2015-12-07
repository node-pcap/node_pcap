var pcap = require("../index"),
    pcap_session = new pcap.Session("", {
        filter: "tcp"
    }),
    matcher = /safari/i;

console.log("Listening on " + pcap_session.device_name);

pcap_session.on('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet),
        data = packet.link.ip.tcp.data;

    if (data && matcher.test(data.toString())) {
        console.log(pcap.print.packet(packet));
        console.log(data.toString());
    }
});

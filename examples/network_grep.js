var pcap = require("../pcap"), 
    pcap_session = pcap.createSession("", { filter: "tcp" }),
    matcher = /safari/i;

console.log("Listening on " + pcap_session.device_name);

pcap_session.on('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet),
        data = packet.payload.payload.payload.data;
    
    if (data && matcher.test(data.toString())) {
        console.log(packet);
        console.log(data.toString());
    }
});

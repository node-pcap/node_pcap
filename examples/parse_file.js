var pcap = require("../pcap");

var pcapfile = process.argv[2];

if (!pcapfile) {
    console.log('ERROR: you must define a pcap file to open')
    process.exit(1);
}

console.log('opening:', pcapfile);

var pcap_session = pcap.createOfflineSession(pcapfile);

var packetCount = 0;

pcap_session.on('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet);

    packetCount++;

    // console.log('packet:', packet);
    if (packet.hasOwnProperty('payload')) {
        // console.log('payload:', packet.payload.payload);
    }
});

pcap_session.on('complete', function() {
    console.log('counted', packetCount, 'packets');
});

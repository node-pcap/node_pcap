var pcap_session;
var pcap = require("../pcap");

var runs = 10000;

function run() {
    var start = Date.now();
    var count = 0;
    pcap_session = pcap.createOfflineSession(process.argv[2]);
    pcap_session.on("packet", function (raw_packet) {
        var packet = pcap.decode(raw_packet);
        count++;
    });

    pcap_session.on("complete", function () {
        var elapsed = Date.now() - start;
        console.log("count=" + count + " duration=" + elapsed);
        runs--;
        if (runs > 0) {
            run();
        }
    });
}

run();

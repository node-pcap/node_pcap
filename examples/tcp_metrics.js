"use strict";
/*global process require exports setInterval */

var sys          = require("sys"),
    pcap         = require("../pcap"), pcap_session,
    dns_cache    = pcap.dns_cache,
    tcp_tracker  = new pcap.TCP_tracker();
    
if (process.argv.length !== 4) {
    sys.error("usage: " + process.argv[1] + " interface filter");
    sys.error("Examples: ");
    sys.error('  sudo node tcp_metrics.js en0 "tcp port 80"');
    sys.error('  sudo node tcp_metrics.js eth1 ""');
    sys.error('  sudo node tcp_metrics.js lo0 "ip proto \\tcp and tcp port 80"');
    process.exit(1);
}

pcap_session = pcap.createSession(process.argv[2], process.argv[3]);

sys.puts("Listening on " + pcap_session.device_name);

// Check for pcap dropped packets on an interval
setInterval(function () {
    var stats = pcap_session.stats();
    if (stats.ps_drop > 0) {
        sys.puts("pcap dropped packets: " + sys.inspect(stats));
    }
}, 2000);

tcp_tracker.addListener('start', function (session) {
    sys.puts("Start of TCP session between " + session.src + " and " + session.dst);
});

tcp_tracker.addListener('http_request', function (session, http) {
    sys.puts("HTTP request: " + sys.inspect(http.request));
});

tcp_tracker.addListener('http_response', function (session, http) {
    sys.puts("HTTP response headers " + sys.inspect(http.response));
});

tcp_tracker.addListener('end', function (session) {
    sys.puts("End of TCP session between " + session.src + " and " + session.dst);
    sys.puts("Set stats for session: " + sys.inspect(tcp_tracker.session_stats(session)));
});

// listen for packets, decode them, and feed TCP to the tracker
pcap_session.addListener('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet);

    tcp_tracker.track_packet(packet);
});

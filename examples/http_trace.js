"use strict";
/*global process require exports setInterval */

var sys         = require("sys"),
    node_http   = require('http'),
    pcap        = require("../pcap"), pcap_session,
    dns_cache   = pcap.dns_cache,
    tcp_tracker = new pcap.TCP_tracker();
    
if (process.argv.length !== 4) {
    sys.error("usage: " + process.argv[1] + " interface filter");
    sys.error("Examples: ");
    sys.error('  sudo node http_trace.js en0 "tcp port 80"');
    sys.error('  sudo node http_trace.js eth1 ""');
    sys.error('  sudo node http_trace.js lo0 "ip proto \\tcp and tcp port 80"');
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

tcp_tracker.addListener('http_request', function (session, http) {
    if (session.http_request_count) {
        session.http_request_count += 1;
    } else {
        session.http_request_count = 1;
    }
    sys.puts(session.src_name + " -> " + session.dst_name + " #" + session.http_request_count + 
        " HTTP " + http.request.http_version + " request: " + 
        http.request.method + " " + http.request.url);
//    sys.puts(sys.inspect(http.request.headers));
});

tcp_tracker.addListener('http_request_body', function (session, http, data) {
    sys.puts(session.src_name + " -> " + session.dst_name + " #" + session.http_request_count + 
        " HTTP " + http.request.http_version + " request body: " + 
        data.length + " bytes");
});

tcp_tracker.addListener('http_response', function (session, http) {
    sys.puts(session.dst_name + " -> " + session.src_name + " #" + session.http_request_count + 
        " HTTP " + http.response.http_version + " response: " + http.response.status_code + " " + node_http.STATUS_CODES[http.response.status_code]);
//    sys.puts(sys.inspect(http.request.headers));
});

tcp_tracker.addListener('http_response_body', function (session, http, data) {
    sys.puts(session.dst_name + " -> " + session.src_name + " #" + session.http_request_count + 
        " HTTP " + http.response.http_version + " response body: " + 
        data.length + " bytes");
//    sys.puts(data);
});

tcp_tracker.addListener('http_response_complete', function (session, http, data) {
    sys.puts(session.dst_name + " -> " + session.src_name + " #" + session.http_request_count +
        " HTTP " + http.response.http_version + " response complete " + (http.response.body_len / 1024).toFixed(2) + "KB");
});

// listen for packets, decode them, and feed TCP to the tracker
pcap_session.addListener('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet);

    tcp_tracker.track_packet(packet);
});

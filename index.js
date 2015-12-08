
var decode         = require("./decode").decode;
var tcp_tracker    = require("./lib/tcpTracker");
var DNSCache       = require("./lib/dnsCache");
var binding        = require("./build/Release/pcap_binding");
var LiveSession    = require("./lib/liveSession");
var OfflineSession = require("./lib/offlineSession");

module.exports = {
    Session: LiveSession,
    OfflineSession: OfflineSession,
    decode: decode,
    TCPTracker: tcp_tracker.TCPTracker,
    TCPSession: tcp_tracker.TCPSession,
    DNSCache: DNSCache,
    libVersion: binding.lib_version()
};

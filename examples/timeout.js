#!/usr/bin/env node

var pcap = require("../pcap");

if (process.argv.length !== 4) {
    console.error("usage: timeout <interface> <timeout>...");
    console.error("Example: ");
    console.error('  timeout eth0 1000');
    process.exit(1);
}

var dev = process.argv[2];
var timeout = parseInt(process.argv[3]);
var session = pcap.createSession(dev, {
    timeout: timeout
});

var count = 1;
session.on('packet', function() {
    console.log(`packet ${count++}`);
});

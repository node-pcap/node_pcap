#!/usr/bin/env node

var pcap = require("../index");

if (process.argv.length !== 4) {
    console.error("usage: timeout <interface> <timeout>...");
    console.error("Example: ");
    console.error('  timeout eth0 1000');
    process.exit(1);
}

var dev = process.argv[2];
var timeout = parseInt(process.argv[3]);
var session = new pcap.Session(dev, {
    timeout: timeout
});

var count = 1;
session.on('packet', function() {
    console.log(`packet ${count++}`);
});

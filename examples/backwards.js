#!/usr/bin/env node

//var util = require('util');
var pcap = require('../index');

if (process.argv.length !== 3) {
    console.error('usage: backwards <interface>...');
    console.error('Example: ');
    console.error('  backwards eth0');
    process.exit(1);
}

var dev = process.argv[2];
var session = new pcap.createSession(dev, '');

var count = 1;
session.on('packet', function() {
    console.log(`packet ${count++}`);
});

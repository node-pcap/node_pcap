'use strict';
var fs = require('fs');
var pcap = require('../pcap');
var IPv4Defrag = require("./ipDefrag/IPv4Defrag");

var filename = process.argv[2]; 
var pcap_session = pcap.createOfflineSession(filename, '');

function findIPv4Packet(pcapPacket) {
    if(pcapPacket.link_type === 'LINKTYPE_RAW') {
        return pcapPacket.payload;
    }
    
    if(pcapPacket.link_type ===  'LINKTYPE_ETHERNET') {
        var packetEthernet = pcapPacket.payload;
        if(packetEthernet.ethertype === 2048) {
            return packetEthernet.payload;
        }
    }
    //TODO LINKTYPE_NULL
    return null;
}

var packetCount = 0;
var iPv4Defrag = new IPv4Defrag();
pcap_session.on('packet', function filterDecodePacket(rawPacket) {
    var packet = pcap.decode.packet(rawPacket);
    var iPPacket = findIPv4Packet(packet);
    packetCount++;
    var result = iPv4Defrag.receivePart(iPPacket);
    
    if(result !== null) {
        console.log("New fragmented IPv4 packet reassembled! Last part is in the packet number", packetCount);
        console.log(result.toString(), result);
    }
    
});


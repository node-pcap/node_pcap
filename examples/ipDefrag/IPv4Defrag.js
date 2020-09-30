'use strict';
var protocols = require("../../decode/ip_protocols");
var IPv4Reassembler = require("./IPv4Reassembler");

/* Handle with differents fragments of differents original parts to reassembly
 * Use this class to reassembly*/

function IPv4Defrag() {
    this.fragmentsById = {};
}

function isFragment(iPPacket) {
    return (iPPacket.fragmentOffset > 0 || iPPacket.flags.moreFragments);
}

//If complete, returns de reassempled payload!
IPv4Defrag.prototype.receivePart = function(iPPacket) {
    if(!isFragment(iPPacket)) {
        return null;
    }
    
    if(this.fragmentsById[iPPacket.identification] === undefined) {
        this.fragmentsById[iPPacket.identification] = new IPv4Reassembler();
    }
    
    this.fragmentsById[iPPacket.identification].newPart(iPPacket);
    var buffer = this.fragmentsById[iPPacket.identification].buildBuffer();
    if(buffer === null) {
        return null;
    }
    
    var ProtocolDecoder = protocols[iPPacket.protocol];
    if(ProtocolDecoder === undefined) {
        return null;
    } else {
        var payload = new ProtocolDecoder(this.emitter).decode(buffer, 0, buffer.length);
        return payload;
    }
}

module.exports = IPv4Defrag;
module.exports.isFragment = isFragment;

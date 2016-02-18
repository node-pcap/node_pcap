var EthernetAddr = require("./ethernet_addr");
var IPv4Addr = require("./ipv4_addr");

function LLDP(emitter) {
    this.emitter = emitter;
    this.chassisId = undefined;
    this.chassisIdType = undefined;
    this.portId = undefined;
    this.portIdType = undefined;
    this.ttl = undefined;
    this.orgTLVs = [];
    this.otherTLVs = [];
}

// http://en.wikipedia.org/wiki/Address_Resolution_Protocol
LLDP.prototype.decode = function (raw_packet, offset) {
    var tOffset = offset;

    while(tOffset < raw_packet.length) {
        
        // Read TLV header
        var tlvType = raw_packet[tOffset] >> 1;
        var tlvLength = (raw_packet.readUInt16BE(tOffset) & 0x1FF);

        // Move along the packet to the TLV value
        tOffset += 2;

        // Parse value
        switch(tlvType) {

            // end of packet
            case 0: break;

            // chassis type
            case 1: {
                this.chassisIdType = raw_packet[tOffset];
                switch(this.chassisIdType) {
                    case 4: { // MAC Address
                        this.chassisId = new EthernetAddr(raw_packet, tOffset);
                    }; break;
                    default: {
                        this.chassisId = raw_packet.slice(tOffset, tOffset+tlvLength-1);
                    }
                }
            } break;

            // port ID
            case 2: {
                this.portIdType = raw_packet[tOffset];
                switch(this.portIdType) {
                    case 3: { // MAC Address
                        this.portId = new EthernetAddr(raw_packet, tOffset);
                    }; break;
                    default: {
                        this.portId = raw_packet.slice(tOffset, tOffset+tlvLength-1);
                    }
                }
            }; break;

            // TTL
            case 3: {
                this.ttl = raw_packet.readUInt16BE(tOffset);
            } break;

            // Port Description
            case 4: {
                this.portDescription = raw_packet.toString('utf8', tOffset, tOffset+tlvLength);
            } break;

            // System Description
            case 5: {
                this.systemName = raw_packet.toString('utf8', tOffset, tOffset+tlvLength);
            } break;

            // System Description
            case 6: {
                this.systemDescription = raw_packet.toString('utf8', tOffset, tOffset+tlvLength);
            } break;


            // System management address
            case 8: {
                
                // TODO: add support for more address types, OID extraction, etc.
                if(raw_packet[tOffset+1] == 1) { // IPv4
                    this.managementAddress = new IPv4Addr().decode(raw_packet, tOffset+2);
                }

            }

            case 127: {
                this.orgTLVs.push(raw_packet.slice(tOffset, tOffset+tlvLength-1));
            }

            /* Please add more TLV's here */

            default: {
                this.otherTLVs.push({ type: tlvType, value: raw_packet.slice(tOffset, tOffset+tlvLength) });
            }
        }

        tOffset += tlvLength;
    }

    // Return via emitter? idk
    if(this.emitter) { this.emitter.emit("lldp", this); }
    return this;
};

LLDP.prototype.decoderName = "lldp";
LLDP.prototype.eventsOnDecode = true;

LLDP.prototype.toString = function () {
    return 'LLDP Announcement from ' + this.chassisId;
};

module.exports = LLDP;

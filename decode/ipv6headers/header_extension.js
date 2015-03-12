var protocols = require("../ip_protocols");

// A generic header extension class
// https://tools.ietf.org/html/rfc6564
// none of the header specif details will
// be decoded by this extension.
function HeaderExtension() {
  this.payload = undefined;
  this.nextHeader = undefined;
  this.headerLength = undefined;
}

HeaderExtension.prototype.decode = function (raw_packet, offset) {
  var originalOffset = offset;
  this.nextHeader = raw_packet[offset++];
  this.headerLength = (raw_packet[offset++]+1)*8;

  offset = originalOffset + this.headerLength;

  var ProtocolDecoder = protocols[this.nextHeader];
  if(ProtocolDecoder === undefined) {
    this.protocolName = "Unknown";
  } else {
    this.payload = new ProtocolDecoder().decode(raw_packet, offset, raw_packet.length - offset);
  }

  return this;
};

HeaderExtension.prototype.toString = function () {
  var ret = "";
  if(this.payload === undefined || this.payload === null){
      ret += "proto " + this.nextHeader;
  } else {
      ret += this.payload.constructor.name;
  }

  return ret + " " + this.payload;
};

module.exports = HeaderExtension;

exports.decodeName = function(raw_packet, offset) {
  var segLength;
  var firstSegment = true;
  var initialOffset = offset;
  var result = { bytesDecoded:undefined, name:"" };

  while((segLength = raw_packet[offset++]) !== 0) {
    if(firstSegment) {
      firstSegment = false;
    } else {
      result.name += ".";
    }

    for (var i = 0; i < segLength; i++) {
      result.name += String.fromCharCode(raw_packet[offset++]);
    }
  }
  result.bytesDecoded = offset - initialOffset;
  return result;
};

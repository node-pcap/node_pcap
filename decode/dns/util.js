exports.decodeName = function(raw_packet, offset) {
  var segLength;
  var firstSegment = true;
  var initialOffset = offset;
  var result = { bytesDecoded:undefined, name:"" };

  while((segLength = raw_packet[offset++]) !== 0 && segLength <= 63) {
    if(firstSegment) {
      firstSegment = false;
    } else {
      result.name += ".";
    }

    for (var i = 0; i < segLength; i++) {
      result.name += String.fromCharCode(raw_packet[offset++]);
    }
  }

  if(raw_packet[offset-1] > 63) {
    // Detected a pointer, pointers
    // are 2 bytes long so inc the offset
    // At this time we have very poor support
    // for pointers
    offset++;
  }

  result.bytesDecoded = offset - initialOffset;
  return result;
};

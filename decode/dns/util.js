exports.decodeName = function(raw_packet, offset) {
  var segLength;
  var firstSegment = true;
  var initialOffset = offset;
  var result = { bytesDecoded:undefined, name:"" };

  if(raw_packet[offset] > 63) {
    //Name is in pointer format which is currently not supported
    result.bytesDecoded = 2;
    result.name = "";
    return result;
  }

  while((segLength = raw_packet[offset++]) !== 0 && segLength < 63) {
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

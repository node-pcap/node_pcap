// A collection of helper functions used in decoding radio packets.
// Always consider adding a class before adding a function to this
// file.

var RadioManagementFrameTag = require("./radio_management_frame_tag");

// Returns an array of RadioManagementFrameTag read from
// raw_packet starting at offset.
exports.parseTags = function parseTags(raw_packet, offset) {
  var tags = [];
  var tag;
  while(raw_packet.length - offset >= 6) {
    tag = new RadioManagementFrameTag().decode(raw_packet, offset);
    if (tag.typeId !== undefined && tag.typeId !== null) {
        tags.push(tag);
        offset += tag.length + 2;
    }
  }
  return tags;
};

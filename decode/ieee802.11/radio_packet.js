/* jshint evil: true */

var RadioFrame = require("./radio_frame");
var radiotap_fields = require('./radiotap_fields');

const associations = {
  u8: 'data.readUInt8(',
  u16: 'data.readUInt16LE(',
  u32: 'data.readUInt32LE(',
  u64: Buffer.prototype.readBigUInt64LE ? 'data.readBigUInt64LE(' : 'readBigUInt64LE(data, ',
  s8: 'data.readInt8(',
  s16: 'data.readInt16LE(',
  s32: 'data.readInt32LE(',
};

function readBigUInt64LE(buffer, offset = 0) {
  const lo = buffer.readUInt32LE(offset);
  const hi = buffer.readUInt32LE(offset + 4);
  return BigInt(lo) + (BigInt(hi) << BigInt(32));
}

/** Radiotap header (http://www.radiotap.org) **/
function RadioPacket(emitter) {
    this.emitter = emitter;
    this.headerRevision = undefined;
    this.headerPad = undefined;
    this.headerLength = undefined;
    this.presentFields = undefined;
    this.fields = undefined;
    this._decoderCache = {};
}

RadioPacket.globalCache = {};

RadioPacket.prototype.decode = function (raw_packet, offset, options) {
    var original_offset = offset;

    this.headerRevision = raw_packet[offset++];
    if (this.headerRevision !== 0)
        console.warning(`Unknown radiotap version: ${this.headerRevision}`);

    this.headerPad = raw_packet[offset++];
    this.headerLength = raw_packet.readUInt16LE(offset); offset += 2;
    this.presentFields = raw_packet.readUInt32LE(offset); offset += 4;
    // We need to use a bigint if the extension bit is set
    if (this.presentFields >> 31) {
        this.presentFields = BigInt(this.presentFields);
        for (var s = BigInt(32); this.presentFields >> (s-BigInt(1)); s += BigInt(32)) {
            this.presentFields ^= BigInt(1) << (s-BigInt(1));
            const v = raw_packet.readUInt32LE(offset); offset += 4;
            this.presentFields |= BigInt(v) << s;
        }
    }
  
    const cache = (options && options.radiotapCache) || RadioPacket.globalCache;
    if (!Object.hasOwnProperty.call(cache, this.presentFields))
        cache[this.presentFields] = buildDecoder(this.presentFields);
    this.fields = cache[this.presentFields](raw_packet, offset, original_offset + this.headerLength);

    offset = original_offset + this.headerLength;

    if (options && options.decodeLower === false) {
        this.ieee802_11Frame = raw_packet.slice(offset);
    } else {
        this.ieee802_11Frame = new RadioFrame(this.emitter).decode(raw_packet, offset);
    }

    if(this.emitter) { this.emitter.emit("radio-packet", this); }
    return this;
};

// Creates a (data, offset, end_offset) function that parses
// radiotap field data and returns the `fields` object.
// Both this function and the returned function may throw
// Important: Bits 31, 63, etc. must NOT be set
function buildDecoder(fields) {
    var code = 'var result = {};\n';

    // Generate field extraction code
    fields = BigInt(fields);
    var offset = 0;
    var has_tlv = false;
    for (let i = 0; fields; (i++, fields >>= BigInt(1))) {
        if (!(fields & BigInt(1))) continue;
        if ((i % 32) === 29 || (i % 32) === 30)
            throw new Error('Radiotap Namespace / Vendor Namespace not implemented yet');
        if (i === 28) {
            has_tlv = true;
            break;
        }

        if (!Object.hasOwnProperty.call(radiotap_fields, i))
            throw new Error(`Unknown field bit ${i}`);
        const { id, structure, align } = radiotap_fields[i];
        // consume alignment
        offset += (((-offset) % align) + align) % align;
        // prepare structure
        let things = structure.map(([kind, name]) => [kind, id + '.' + name]);
        if (structure.length === 1)
            things[0][1] = id || structure[0][1];
        else
            code += `result.${id} = {};\n`; // extensions with many fields are grouped
        // parse the things
        things.forEach(([kind, name]) => {
            if (typeof kind === 'number') {
                code += `result.${name} = data.slice(offset + ${offset}, offset + ${offset + kind});\n`;
                offset += kind;
                return;
            }
            // FIXME: parse flags too
            const fname = associations[kind].toString();
            code += `result.${name} = ${fname}offset + ${offset});\n`;
            offset += Number(kind.substring(1))/8;
        });
    }

    // Check length
    var pre_check = '';
    pre_check += `if (end_offset - offset < ${offset})\n`;
    pre_check += `  throw Error('Radiotap header length too short');\n`;

    // Extract TLV or check for extra data
    if (has_tlv) {
        if (fields >> BigInt(1))
            throw Error('If bit 28 (TLV) is set, no higher bits can be set');
        // FIXME: parse better?
        code += `result.tlv = Buffer.slice(data, offset+${offset}, end_offset);\n`;
    } else {
        // FIXME: make this a warning
        pre_check += `if (end_offset - offset > ${offset})\n`;
        pre_check += `  throw Error('Radiotap header length too high, extra data?');\n`;
    }

    code = pre_check + code + 'return result;';
    return new Function('readBigUInt64LE', 'data', 'offset', 'end_offset', code)
        .bind(null, readBigUInt64LE);
}

module.exports = RadioPacket;

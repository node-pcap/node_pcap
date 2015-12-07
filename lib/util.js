function lpad(str, len) {
    while (str.length < len) {
        str = "0" + str;
    }
    return str;
}

var int8_to_hex = [];
var int8_to_hex_nopad = [];
var int8_to_dec = [];

for (var i = 0; i <= 255; i++) {
    int8_to_hex[i] = lpad(i.toString(16), 2);
    int8_to_hex_nopad[i] = i.toString(16);
    int8_to_dec[i] = i.toString();
}

module.exports = {
    int8_to_dec: int8_to_dec,
    int8_to_hex: int8_to_hex,
    int8_to_hex_nopad: int8_to_hex_nopad
};

function NoNext() {
    this._error = undefined;
}

// The no next header is nothing. Just an empty payload.
NoNext.prototype.decode = function (raw_packet, offset) {
    var remainingLength = raw_packet.length - offset;
    if(remainingLength !== 0) {
        this._error = "There is more packet left to be parse," +
        "but NoNext.decode was called with " + remainingLength +
        " bytes left.";
    }
    return this;
};

NoNext.prototype.toString = function () {
    return "";
};

module.exports = NoNext;

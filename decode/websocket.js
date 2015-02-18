var events = require("events");
// Meaningfully hold the different types of frames at some point
function WebSocketFrame() {
    this.type = null;
    this.data = "";
}

function WebSocketParser(flag) {
    this.buffer = new Buffer(64 * 1024); // 64KB is the max message size
    this.buffer.end = 0;
    if (flag === "draft76") {
        this.state = "skip_response";
        this.skipped_bytes = 0;
    } else {
        this.state = "frame_type";
    }
    this.frame = new WebSocketFrame();

    events.EventEmitter.call(this);
}
require("util").inherits(WebSocketParser, require("events").EventEmitter);

WebSocketParser.prototype.execute = function (incoming_buf) {
    var pos = 0;

    while (pos < incoming_buf.length) {
        switch (this.state) {
        case "skip_response":
            this.skipped_bytes += 1;
            if (this.skipped_bytes === 16) {
                this.state = "frame_type";
            }
            pos += 1;
            break;
        case "frame_type":
            this.frame.type = incoming_buf[pos];
            pos += 1;
            this.state = "read_until_marker";
            break;
        case "read_until_marker":
            if (incoming_buf[pos] !== 255) {
                this.buffer[this.buffer.end] = incoming_buf[pos];
                this.buffer.end += 1;
                pos += 1;
            } else {
                this.frame.data = this.buffer.toString("utf8", 0, this.buffer.end);
                this.emit("message", this.frame.data); // this gets converted to "websocket message" in TCP_Tracker
                this.state = "frame_type";
                this.buffer.end = 0;
                pos += 1;
            }
            break;
        default:
            throw new Error("invalid state " + this.state);
        }
    }
};

module.exports = WebSocketParser;

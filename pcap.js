var util          = require("util");
var events        = require("events");
var binding       = require("./build/Release/pcap_binding");
var decode        = require("./decode").decode;
var tcp_tracker   = require("./tcp_tracker");
var DNSCache      = require("./dns_cache");
var timers        = require("timers");

exports.decode = decode;
exports.TCPTracker = tcp_tracker.TCPTracker;
exports.TCPSession = tcp_tracker.TCPSession;
exports.DNSCache = DNSCache;

// This may be overriden by the user
exports.warningHandler = function warningHandler(x) {
    console.warn('warning: %s - this may not actually work', x);
};

function PcapSession(is_live, device_name, filter, buffer_size, snap_length, outfile, is_monitor, buffer_timeout, promiscuous) {
    this.is_live = is_live;
    this.device_name = device_name;
    this.filter = filter || "";
    this.buffer_size = buffer_size;
    this.snap_length = snap_length;
    this.outfile = outfile || "";
    this.is_monitor = Boolean(is_monitor);
    this.buffer_timeout = buffer_timeout;
    this.promiscuous = typeof promiscuous === 'undefined' ? true : promiscuous;

    this.link_type = null;
    this.opened = null;
    this.buf = null;
    this.header = null;
    this.empty_reads = 0;
    this.packets_read = null;

    this.session = new binding.PcapSession();

    if (typeof this.buffer_size === "number" && !isNaN(this.buffer_size)) {
        this.buffer_size = Math.round(this.buffer_size);
    } else {
        this.buffer_size = 10 * 1024 * 1024; // Default buffer size is 10MB
    }

    if (typeof this.snap_length === "number" && !isNaN(this.snap_length)) {
        this.snap_length = Math.round(this.snap_length);
    } else {
        this.snap_length = 65535; // Default snap length is 65535
    }

    if (typeof this.buffer_timeout === "number" && !isNaN(this.buffer_timeout)) {
        this.buffer_timeout = Math.round(this.buffer_timeout);
    } else {
        this.buffer_timeout = 1000; // Default buffer timeout is 1s
    }

    const packet_ready = this.on_packet_ready.bind(this);
    if (this.is_live) {
        this.device_name = this.device_name || binding.default_device();
        this.link_type = this.session.open_live(this.device_name, this.filter, this.buffer_size, this.snap_length, this.outfile, packet_ready, this.is_monitor, this.buffer_timeout, exports.warningHandler, this.promiscuous);
    } else {
        this.link_type = this.session.open_offline(this.device_name, this.filter, this.buffer_size, this.snap_length, this.outfile, packet_ready, this.is_monitor, this.buffer_timeout, exports.warningHandler, this.promiscuous);
    }

    this.opened = true;
    this.buf = Buffer.alloc(this.snap_length);
    this.header = Buffer.alloc(16);

    if (is_live) {
        // callback when pcap has data to read. multiple packets may be readable.
        this.session.read_callback = () => {
            var packets_read = this.session.dispatch(this.buf, this.header);
            if (packets_read < 1) {
                this.empty_reads += 1;
            }
        };
        this.session.start_polling();
        process.nextTick(this.session.read_callback); // kickstart to prevent races
    } else {
        timers.setImmediate(() => {
            var packets = 0;
            do {
                packets = this.session.dispatch(this.buf, this.header);
            } while ( packets > 0 );
            this.emit("complete");
        });
    }

    events.EventEmitter.call(this);
}
util.inherits(PcapSession, events.EventEmitter);

exports.lib_version = binding.lib_version();

exports.findalldevs = function () {
    return binding.findalldevs();
};

function PacketWithHeader(buf, header, link_type) {
    this.buf = buf;
    this.header = header;
    this.link_type = link_type;
}

PcapSession.prototype.on_packet_ready = function () {
    var full_packet = new PacketWithHeader(this.buf, this.header, this.link_type);
    this.emit("packet", full_packet);
};

PcapSession.prototype.close = function () {
    this.opened = false;

    this.removeAllListeners();

    this.session.close();
};

PcapSession.prototype.stats = function () {
    return this.session.stats();
};

PcapSession.prototype.inject = function (data) {
    return this.session.inject(data);
};

exports.Pcap = PcapSession;
exports.PcapSession = PcapSession;

exports.createSession = function (device, options) {
    options = options || {};
    return new PcapSession(true, device, options.filter, options.buffer_size, options.snap_length, null, options.monitor, options.buffer_timeout, options.promiscuous);
};

exports.createOfflineSession = function (path, options) {
    options = options || {};
    return new PcapSession(false, path, options.filter, 0, null, null);
};

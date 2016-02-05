var util          = require("util");
var events        = require("events");
var binding       = require("./build/Release/pcap_binding");
var SocketWatcher = require("socketwatcher").SocketWatcher;
var decode        = require("./decode").decode;
var tcp_tracker   = require("./tcp_tracker");
var DNSCache      = require("./dns_cache");
var timers        = require("timers");

exports.decode = decode;
exports.TCPTracker = tcp_tracker.TCPTracker;
exports.TCPSession = tcp_tracker.TCPSession;
exports.DNSCache = DNSCache;

function PcapSession(is_live, device_name, filter, buffer_size, outfile, is_monitor) {
    this.is_live = is_live;
    this.device_name = device_name;
    this.filter = filter || "";
    this.buffer_size = buffer_size;
    this.outfile = outfile || "";
    this.is_monitor = Boolean(is_monitor);

    this.link_type = null;
    this.fd = null;
    this.opened = null;
    this.buf = null;
    this.header = null;
    this.read_watcher = null;
    this.empty_reads = 0;
    this.packets_read = null;

    this.session = new binding.PcapSession();

    if (typeof this.buffer_size === "number" && !isNaN(this.buffer_size)) {
        this.buffer_size = Math.round(this.buffer_size);
    } else {
        this.buffer_size = 10 * 1024 * 1024; // Default buffer size is 10MB
    }

    var self = this;

    // called for each packet read by pcap
    function packet_ready() {
        self.on_packet_ready();
    }

    if (this.is_live) {
        this.device_name = this.device_name || binding.default_device();
        this.link_type = this.session.open_live(this.device_name, this.filter, this.buffer_size, this.outfile, packet_ready, this.is_monitor);
    } else {
        this.link_type = this.session.open_offline(this.device_name, this.filter, this.buffer_size, this.outfile, packet_ready, this.is_monitor);
    }

    this.fd = this.session.fileno();
    this.opened = true;
    this.buf = new Buffer(this.buffer_size || 65535);
    this.header = new Buffer(16);

    if (is_live) {
        this.readWatcher = new SocketWatcher();

        // readWatcher gets a callback when pcap has data to read. multiple packets may be readable.
        this.readWatcher.callback = function pcap_read_callback() {
            var packets_read = self.session.dispatch(self.buf, self.header);
            if (packets_read < 1) {
                this.empty_reads += 1;
            }
        };
        this.readWatcher.set(this.fd, true, false);
        this.readWatcher.start();
    } else {
        timers.setImmediate(function() {
            var packets = 0;
            do {
                packets = self.session.dispatch(self.buf, self.header);
            } while ( packets > 0 );
            self.emit("complete");
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
    this.session.close();
    if (this.is_live) {
        this.readWatcher.stop();
    }
    // TODO - remove listeners so program will exit I guess?
};

PcapSession.prototype.stats = function () {
    return this.session.stats();
};

PcapSession.prototype.inject = function (data) {
    return this.session.inject(data);
};

exports.Pcap = PcapSession;
exports.PcapSession = PcapSession;

exports.createSession = function (device, filter, buffer_size, monitor) {
    return new PcapSession(true, device, filter, buffer_size, null, monitor);
};

exports.createOfflineSession = function (path, filter) {
    return new PcapSession(false, path, filter, 0, null, null);
};

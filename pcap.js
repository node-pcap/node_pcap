var util          = require("util");
var events        = require("events");
var binding       = require("./build/Release/pcap_binding");
var SocketWatcher = require("socketwatcher").SocketWatcher;
var decode        = require("./decode").decode;
var tcp_tracker   = require("./tcp_tracker");
var DNSCache      = require("./dns_cache");
var timers        = require("timers");

module.exports.decode = decode;
module.exports.TCPTracker = tcp_tracker.TCPTracker;
module.exports.TCPSession = tcp_tracker.TCPSession;
module.exports.DNSCache = DNSCache;

function PcapSession(is_live, device_name, params) {
    var defaultParams = {
        bufferSize: 10 * 1024 * 1024,  // Default buffer size is 10MB
        isMonitor: false,
        outfile: "",
        filter: "",
        timeout: 1000
    };

    this.params = Object.assign({}, defaultParams, params);

    this.is_live = is_live;
    this.device_name = device_name;

    this.link_type = null;
    this.fd = null;
    this.opened = null;
    this.buf = null;
    this.header = null;
    this.read_watcher = null;
    this.empty_reads = 0;
    this.packets_read = null;

    this.session = new binding.PcapSession();

    if (typeof this.params.bufferSize === "number" &&
        !isNaN(this.params.bufferSize)) {
        this.params.bufferSize = Math.round(this.params.bufferSize);
    } else {
        this.params.bufferSize = defaultParams.bufferSize;
    }

    // called for each packet read by pcap
    var packet_ready = () => {
        this.on_packet_ready();
    };

    if (this.is_live) {
        this.device_name = this.device_name || binding.default_device();
        this.link_type = this.session.open_live(
            this.device_name,
            this.params.filter,
            this.params.bufferSize,
            this.params.outfile,
            packet_ready,
            this.params.isMonitor,
            this.params.timeout);
    } else {
        this.link_type = this.session.open_offline(
            this.device_name,
            this.params.filter,
            this.params.bufferSize,
            this.params.outfile,
            packet_ready,
            this.params.isMonitor,
            this.params.timeout);
    }

    this.fd = this.session.fileno();
    this.opened = true;
    this.buf = new Buffer(this.params.bufferSize || 65535);
    this.header = new Buffer(16);

    if (is_live) {
        this.readWatcher = new SocketWatcher();

        // readWatcher gets a callback when pcap has data to read. multiple packets may be readable.
        this.readWatcher.callback = () => {
            var packets_read = this.session.dispatch(this.buf, this.header);
            if (packets_read < 1) {
                this.empty_reads += 1;
            }
        };
        this.readWatcher.set(this.fd, true, false);
        this.readWatcher.start();
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

module.exports.lib_version = binding.lib_version();

PcapSession.prototype.findalldevs = function () {
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
    this.readWatcher.stop();
    // TODO - remove listeners so program will exit I guess?
};

PcapSession.prototype.stats = function () {
    return this.session.stats();
};

PcapSession.prototype.inject = function (data) {
    return this.session.inject(data);
};

module.exports.Pcap = PcapSession;
module.exports.PcapSession = PcapSession;

module.exports.createSession = function (device, params) {
    return new PcapSession(true, device, params);
};

module.exports.createOfflineSession = function (path, params) {
    return new PcapSession(false, path, params);
};

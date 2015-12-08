var util          = require("util");
var events        = require("events");
var binding       = require("../build/Release/pcap_binding");
var SocketWatcher = require("socketwatcher").SocketWatcher;
var timers        = require("timers");

function Session(is_live, device_name, options) {
    var defaultOptions = {
        bufferSize: 10 * 1024 * 1024,  // 10MB
        isMonitor: false,
        outfile: "",
        filter: "",
        timeout: 1000   // 1 second
    };

    this.options = Object.assign({}, defaultOptions, options);

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

    if (typeof this.options.bufferSize === "number" &&
        !isNaN(this.options.bufferSize)) {
        this.options.bufferSize = Math.round(this.options.bufferSize);
    } else {
        this.options.bufferSize = defaultOptions.bufferSize;
    }

    // called for each packet read by pcap
    var packet_ready = () => {
        this.on_packet_ready();
    };

    if (this.is_live) {
        this.device_name = this.device_name || binding.default_device();
        this.link_type = this.session.open_live(
            this.device_name,
            this.options.filter,
            this.options.bufferSize,
            this.options.outfile,
            packet_ready,
            this.options.isMonitor,
            this.options.timeout);
    } else {
        this.link_type = this.session.open_offline(
            this.device_name,
            this.options.filter,
            this.options.bufferSize,
            this.options.outfile,
            packet_ready,
            this.options.isMonitor,
            this.options.timeout);
    }

    this.fd = this.session.fileno();
    this.opened = true;
    this.buf = new Buffer(this.options.bufferSize || 65535);
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

util.inherits(Session, events.EventEmitter);

Session.prototype.findalldevs = function () {
    return binding.findalldevs();
};

function PacketWithHeader(buf, header, link_type) {
    this.buf = buf;
    this.header = header;
    this.link_type = link_type;
}

Session.prototype.on_packet_ready = function () {
    var full_packet = new PacketWithHeader(this.buf, this.header, this.link_type);
    this.emit("packet", full_packet);
};

Session.prototype.close = function () {
    this.opened = false;
    this.session.close();
    this.readWatcher.stop();
    this.removeAllListeners();
};

Session.prototype.stats = function () {
    return this.session.stats();
};

Session.prototype.inject = function (data) {
    return this.session.inject(data);
};

module.exports = Session;

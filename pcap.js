var sys = require("sys"),
    Buffer = require('buffer').Buffer,
    binding = require("./build/default/binding"),
    events = require("events");

sys.debug(sys.inspect(binding));

function Pcap () {
    this.opened = false;
    this.fd = null;

    events.EventEmitter.call(this);
}
sys.inherits(Pcap, events.EventEmitter);

Pcap.prototype.findalldevs = function () {
    return binding.findalldevs();
};

Pcap.prototype.open_live = function (device, filter) {
    this.link_type = binding.open_live(device, filter);
    sys.debug("Link type: " + this.link_type);
    this.fd = binding.fileno();
    this.opened = true;
    this.readWatcher = new process.IOWatcher();
    this.buf = new Buffer(65535);
    var me = this;
    this.readWatcher.callback = function () {
        var packets_read = binding.dispatch(me.buf, function (header) {
            me.emit('packet', header, me.buf);
        });
        if (packets_read !== 1) {
            sys.debug("readWatcher callback fired and dispatch read " + packets_read + " packets instead of 1");
        }
    };
    this.readWatcher.set(this.fd, true, false);
    this.readWatcher.start();
};

Pcap.prototype.close = function () {
    this.opened = false;
    binding.close();
    // TODO - remove listeners so program will exit I guess?
};

Pcap.prototype.stats = function () {
    return binding.stats();
};

exports.Pcap = Pcap;

exports.createSession = function (device, filter) {
    var session = new Pcap();
    session.open_live(device, filter);
    return session;
};

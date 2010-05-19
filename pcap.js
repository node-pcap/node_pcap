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
    
};

Pcap.prototype.open_live = function (device, filter) {
    binding.open_live(device, filter);
    this.fd = binding.fileno();
    this.opened = true;
    this.readWatcher = new process.IOWatcher();
    this.buf = new Buffer(65535);
    var me = this;
    this.readWatcher.callback = function () {
        sys.debug("readWatcher callback");
        var packets_read = binding.dispatch(me.buf, function (header) {
            sys.debug("callback called back.");
            me.emit('packet', header, me.buf);
        });
        sys.debug("pcap dispatched, packet count: " + packets_read);
    };
    this.readWatcher.set(this.fd, true, false);
    this.readWatcher.start();
};

Pcap.prototype.close = function () {
    this.opened = false;
};

exports.Pcap = Pcap;

exports.createSession = function (device, filter) {
    var session = new Pcap();
    session.open_live(device, filter);
    return session;
};

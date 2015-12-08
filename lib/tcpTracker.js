var EventEmitter = require("events").EventEmitter;
var inherits = require("util").inherits;
var IPv4 = require("../decode/ipv4");
var TCP = require("../decode/tcp");

function TCPTracker() {
    this.sessions = {};
    EventEmitter.call(this);
}
inherits(TCPTracker, EventEmitter);

TCPTracker.prototype.track_packet = function (packet) {
    var ip, tcp, src, dst, key, session;

    if (packet.payload.payload instanceof IPv4 && packet.payload.payload.payload instanceof TCP) {
        ip  = packet.payload.payload;
        tcp = ip.payload;
        src = ip.saddr + ":" + tcp.sport;
        dst = ip.daddr + ":" + tcp.dport;

        if (src < dst) {
            key = src + "-" + dst;
        } else {
            key = dst + "-" + src;
        }

        var is_new = false;
        session = this.sessions[key];
        if (! session) {
            is_new = true;
            session = new TCPSession();
            this.sessions[key] = session;
        }

        session.track(packet);

        // need to track at least one packet before we emit this new session, otherwise nothing
        // will be initialized.
        if (is_new) {
            this.emit("session", session);
        }
    }
    // silently ignore any non IPv4 TCP packets
    // user should filter these out with their pcap filter, but oh well.
};

function TCPSession() {
    this.src = null;
    this.src_name = null; // from DNS
    this.dst = null;
    this.dst_name = null; // from DNS

    this.state = null;
    this.current_cap_time = null;

    this.syn_time = null;
    this.missed_syn = null;
    this.connect_time = null;

    this.send_isn = null;
    this.send_window_scale = null;
    this.send_packets = {}; // send_packets is indexed by the expected ackno: seqno + length
    this.send_acks = {};
    this.send_retrans = {};
    this.send_next_seq = null;
    this.send_acked_seq = null;
    this.send_bytes_ip = null;
    this.send_bytes_tcp = null;
    this.send_bytes_payload = 0;

    this.recv_isn = null;
    this.recv_window_scale = null;
    this.recv_packets = {};
    this.recv_acks = {};
    this.recv_retrans = {};
    this.recv_next_seq = null;
    this.recv_acked_seq = null;
    this.recv_bytes_ip = 0;
    this.recv_bytes_tcp = 0;
    this.recv_bytes_payload = 0;

    EventEmitter.call(this);
}
inherits(TCPSession, EventEmitter);

TCPSession.prototype.track = function (packet) {
    var ip  = packet.payload.payload;
    var tcp = ip.payload;
    var src = ip.saddr + ":" + tcp.sport;
    var dst = ip.daddr + ":" + tcp.dport;

    this.current_cap_time = packet.pcap_header.tv_sec + (packet.pcap_header.tv_usec / 1000000);

    if (this.state === null) {
        this.src = src; // the side the sent the first packet we saw
        this.src_name = src;
        this.dst = dst; // the side that the first packet we saw was sent to
        this.dst_name = dst;

        if (tcp.flags.syn && !tcp.flags.ack) { // initial SYN, best case
            this.state = "SYN_SENT";
        } else { // joining session already in progress
            this.missed_syn = true;
            this.connect_time = this.current_cap_time;
            this.state = "ESTAB";  // I mean, probably established, right? Unless it isn't.
        }

        this.syn_time = this.current_cap_time;
        this.send_isn = tcp.seqno;
        this.send_window_scale = tcp.options.window_scale || 1; // multipler, not bit shift value
        this.send_next_seq = tcp.seqno + 1;
        this.send_bytes_ip = ip.headerLength;
        this.send_bytes_tcp = tcp.headerLength;
    } else if (tcp.flags.syn && !tcp.flags.ack) {
        this.emit("syn retry", this);
    } else { // not a SYN, so run the state machine
        this[this.state](packet);
    }
};

TCPSession.prototype.SYN_SENT = function (packet) {
    var ip  = packet.payload.payload;
    var tcp = ip.payload;
    var src = ip.saddr + ":" + tcp.sport;

    if (src === this.dst && tcp.flags.syn && tcp.flags.ack) {
        this.recv_bytes_ip += ip.headerLength;
        this.recv_bytes_tcp += tcp.headerLength;
        this.recv_packets[tcp.seqno + 1] = this.current_cap_time;
        this.recv_acks[tcp.ackno] = this.current_cap_time;
        this.recv_isn = tcp.seqno;
        this.recv_window_scale = tcp.options.window_scale || 1;
        this.state = "SYN_RCVD";
    } else if (tcp.flags.rst) {
        this.state = "CLOSED";
        this.emit("reset", this, "recv"); // TODO - check which direction did the reset, probably recv
//    } else {
//        console.log("Didn't get SYN-ACK packet from dst while handshaking: " + util.inspect(tcp, false, 4));
    }
};

TCPSession.prototype.SYN_RCVD = function (packet) {
    var ip  = packet.payload.payload;
    var tcp = ip.payload;
    var src = ip.saddr + ":" + tcp.sport;

    if (src === this.src && tcp.flags.ack) { // TODO - make sure SYN flag isn't set, also match src and dst
        this.send_bytes_ip += ip.headerLength;
        this.send_bytes_tcp += tcp.headerLength;
        this.send_acks[tcp.ackno] = this.current_cap_time;
        this.connect_time = this.current_cap_time;
        this.emit("start", this);
        this.state = "ESTAB";
//    } else {
//        console.log("Didn't get ACK packet from src while handshaking: " + util.inspect(tcp, false, 4));
    }
};

// TODO - actually implement SACK decoding and tracking
// if (tcp.options.sack) {
//     console.log("SACK magic, handle this: " + util.inspect(tcp.options.sack));
//     console.log(util.inspect(ip, false, 5));
// }
// TODO - check for tcp.flags.rst and emit reset event

TCPSession.prototype.ESTAB = function (packet) {
    var ip  = packet.payload.payload;
    var tcp = ip.payload;
    var src = ip.saddr + ":" + tcp.sport;

    if (src === this.src) { // this packet came from the active opener / client
        this.send_bytes_ip += ip.headerLength;
        this.send_bytes_tcp += tcp.headerLength;
        if (tcp.dataLength > 0) {
            if (this.send_packets[tcp.seqno + tcp.dataLength]) {
                this.emit("retransmit", this, "send", tcp.seqno + tcp.dataLength);
                if (this.send_retrans[tcp.seqno + tcp.dataLength]) {
                    this.send_retrans[tcp.seqno + tcp.dataLength] += 1;
                } else {
                    this.send_retrans[tcp.seqno + tcp.dataLength] = 1;
                }
            } else {
                this.emit("data send", this, tcp.data);
            }
            this.send_bytes_payload += tcp.dataLength;
            this.send_packets[tcp.seqno + tcp.dataLength] = this.current_cap_time;
        }
        if (this.recv_packets[tcp.ackno]) {
            this.send_acks[tcp.ackno] = this.current_cap_time;
        }
        // console.log("sending ACK for packet we didn't see received: " + tcp.ackno);
        if (tcp.flags.fin) {
            this.state = "FIN_WAIT";
        }
    } else if (src === this.dst) { // this packet came from the passive opener / server
        this.recv_bytes_ip += ip.headerLength;
        this.recv_bytes_tcp += tcp.headerLength;
        if (tcp.dataLength > 0) {
            if (this.recv_packets[tcp.seqno + tcp.dataLength]) {
                this.emit("retransmit", this, "recv", tcp.seqno + tcp.dataLength);
                if (this.recv_retrans[tcp.seqno + tcp.dataLength]) {
                    this.recv_retrans[tcp.seqno + tcp.dataLength] += 1;
                } else {
                    this.recv_retrans[tcp.seqno + tcp.dataLength] = 1;
                }
            } else {
                this.emit("data recv", this, tcp.data);
            }
            this.recv_bytes_payload += tcp.dataLength;
            this.recv_packets[tcp.seqno + tcp.dataLength] = this.current_cap_time;
        }
        if (this.send_packets[tcp.ackno]) {
            this.recv_acks[tcp.ackno] = this.current_cap_time;
        }
        if (tcp.flags.fin) {
            this.state = "CLOSE_WAIT";
        }
    } else {
        console.log("non-matching packet in session: " + packet);
    }
};

// TODO - need to track half-closed data
TCPSession.prototype.FIN_WAIT = function (packet) {
    var ip  = packet.payload.payload;
    var tcp = ip.payload;
    var src = ip.saddr + ":" + tcp.sport;

    if (src === this.dst && tcp.flags.fin) {
        this.state = "CLOSING";
    }
};

// TODO - need to track half-closed data
TCPSession.prototype.CLOSE_WAIT = function (packet) {
    var ip  = packet.payload.payload;
    var tcp = ip.payload;
    var src = ip.saddr + ":" + tcp.sport;

    if (src === this.src && tcp.flags.fin) {
        this.state = "LAST_ACK";
    }
};

// TODO - need to track half-closed data
TCPSession.prototype.LAST_ACK = function (packet) {
    var ip  = packet.payload.payload;
    var tcp = ip.payload;
    var src = ip.saddr + ":" + tcp.sport;

    if (src === this.dst) {
        this.close_time = this.current_cap_time;
        this.state = "CLOSED";
        this.emit("end", this);
    }
};

// TODO - need to track half-closed data
TCPSession.prototype.CLOSING = function (packet) {
    var ip  = packet.payload.payload;
    var tcp = ip.payload;
    var src = ip.saddr + ":" + tcp.sport;

    if (src === this.src) {
        this.close_time = this.current_cap_time;
        this.state = "CLOSED";
        this.emit("end", this);
    }
};

// The states aren't quite right here.  All possible states of FIN and FIN/ACKs aren't handled.
// So some of the bytes of the session may not be properly accounted for.

TCPSession.prototype.CLOSED = function (/*packet*/) {
    // not sure what to do here. We are closed, so I guess bump some counters or something.
};

TCPSession.prototype.session_stats = function () {
    var send_acks = Object.keys(this.send_acks)
        .map(function (key) { return +key; })
        .sort(function (a, b) { return a > b; });
    var recv_acks = Object.keys(this.recv_acks)
        .map(function (key) { return +key; })
        .sort(function (a, b) { return a > b; });

    var total_time = this.close_time - this.syn_time;
    var stats = {};

    stats.recv_times = {};
    send_acks.forEach((v) => {
        if (this.recv_packets[v]) {
            stats.recv_times[v] = this.send_acks[v] - this.recv_packets[v];
        }
    });

    stats.send_times = {};
    recv_acks.forEach((v) => {
        if (this.send_packets[v]) {
            stats.send_times[v] = this.recv_acks[v] - this.send_packets[v];
        }
    });

    stats.send_retrans = {};
    Object.keys(this.send_retrans).forEach((v) => {
        stats.send_retrans[v] = this.send_retrans[v];
    });

    stats.recv_retrans = {};
    Object.keys(this.recv_retrans).forEach((v) => {
        stats.recv_retrans[v] = this.recv_retrans[v];
    });

    stats.connect_duration = this.connect_time - this.syn_time;
    stats.total_time = total_time;
    stats.send_overhead = this.send_bytes_ip + this.send_bytes_tcp;
    stats.send_payload = this.send_bytes_payload;
    stats.send_total = stats.send_overhead + stats.send_payload;
    stats.recv_overhead = this.recv_bytes_ip + this.recv_bytes_tcp;
    stats.recv_payload = this.recv_bytes_payload;
    stats.recv_total = stats.recv_overhead + stats.recv_payload;

    return stats;
};

module.exports = {
    TCPSession: TCPSession,
    TCPTracker: TCPTracker
};

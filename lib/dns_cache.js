var dns = require("dns");

// cache reverse DNS lookups for the life of the program. No TTL checking. No tricks.

function DNSCache() {
    this.cache = {};
    this.requests = {};
}

DNSCache.prototype.ptr = function (ip) {
    if (this.cache[ip]) {
        return this.cache[ip];
    }

    if (this.requests[ip] === undefined) {
        this.requests[ip] = true;
        dns.reverse(ip, (err, domains) => {
            this.on_ptr(err, ip, domains);
        });
    }

    return ip;
};

DNSCache.prototype.on_ptr = function (err, ip, domains) {
    // TODO - check for network and broadcast addrs, since we have iface info
    if (err) {
        this.cache[ip] = ip;
    } else {
        this.cache[ip] = domains[0];
    }
};

module.exports = DNSCache;

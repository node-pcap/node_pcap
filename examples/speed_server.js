"use strict";
/*global process require exports setInterval __dirname */

var sys = require("sys"),
    pcap = require("../pcap"),
    count = 0,
    start_time = new Date(),
    pcap_session = pcap.createSession("", 'ip proto \\tcp and port 80'),
    dns_cache = pcap.dns_cache,
    tcp_tracker = new pcap.TCP_tracker(),
    http = require('http'),
    url = require('url'),
    path = require('path'),
    fs = require('fs'),
    track_ids = {};

// Print all devices, currently listening device prefixed with an asterisk
sys.puts("All devices:");
pcap_session.findalldevs().forEach(function (dev) {
    if (pcap_session.device_name === dev.name) {
        sys.print("* ");
    }
    sys.print(dev.name + " ");
    if (dev.addresses.length > 0) {
        dev.addresses.forEach(function (address) {
            sys.print(address.addr + "/" + address.netmask);
        });
        sys.print("\n");
    } else {
        sys.print("no address\n");
    }
});

setInterval(function () {
    var stats = pcap_session.stats();
    if (stats.ps_drop > 0) {
        sys.puts("pcap dropped packets: " + sys.inspect(stats));
    }
}, 5000);

tcp_tracker.addListener('start', function (session) {
    sys.puts("Start of TCP session between " + session.src + " and " + session.dst);
});

tcp_tracker.addListener('http_request', function (session) {
    var matches = /send_file\?id=(\d+)/.exec(session.http_request.url);
    if (matches && matches[1]) {
        session.track_id = matches[1];
        sys.puts("Added tracking for " + matches[1]);
    }
    else {
        sys.puts("Didn't add tracking for " + sys.inspect(session));
    }
});

tcp_tracker.addListener('end', function (session) {
    sys.puts("End of TCP session between " + session.src + " and " + session.dst);
    if (session.track_id) {
        track_ids[session.track_id] = tcp_tracker.session_stats(session);
        sys.puts("Set stats for session: " + sys.inspect(track_ids));
    }
});

// listen for packets, decode them, and feed TCP to the tracker
pcap_session.addListener('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet);
    
    tcp_tracker.track_packet(packet);
});

function lookup_mime_type(file_name) {
    var mime_types = {
            html: "text/html",
            txt: "text/plain",
            js: "application/javascript",
            css: "text/css",
            ico: "image/x-icon",
            jpg: "image/jpeg"
        },
        index = file_name.lastIndexOf('.'),
        suffix;
    // TODO - use path.extname() here
    if (index > 0 && index < (file_name.length - 2)) {
        suffix = file_name.substring(index + 1);
        if (mime_types[suffix] !== undefined) {
            return mime_types[suffix];
        }
    }
    return "text/plain";
}

function do_error(response, code, message) {
    sys.puts("do_error: " + code + " - " + message);
    response.writeHead(code, {
        "Content-Type": "text/plain",
        "Connection": "close"
    });
    response.write(message);
    response.end();
}

function handle_file(file_name, in_request, in_response) {
    var local_name = file_name.replace(/^\//, __dirname + "/"),
        file;

    if (local_name.match(/\/$/)) {
        local_name += "index.html";
    }

    path.exists(local_name, function (exists) {
        if (exists) {
            file = fs.readFile(local_name, "binary", function (err, data) {
                var out_headers = {
                    "Content-Type": lookup_mime_type(local_name),
                    "Content-Length": data.length,
                    "Connection": "close"
                };
                if (err) {
                    do_error(in_response, 404, "Error opening " + local_name + ": " + err);
                    return;
                }
                in_request.setEncoding("binary");
                if (in_request.headers.origin) {
                    out_headers["access-control-allow-origin"] = in_request.headers.origin;
                }

                in_response.writeHead(200, out_headers);
                in_response.write(data, "binary");
                in_response.end();
            });
        }
        else {
            do_error(in_response, 404, local_name + " does not exist");
        }
    });
}

function send_start(url, request, response) {
    if (url.query && url.query.id) {
        track_ids[url.query.id] = {};
        handle_file('/testfile.txt', request, response);
    }
    else {
        do_error(response, 400, "Missing id in query string");
    }
}

function get_stats(url, request, response) {
    if (url.query && url.query.id) {
        response.writeHead(200, {
            "Content-Type": "text/plain",
            "Connection": "close"
        });
        if (track_ids[url.query.id]) {
            response.write(JSON.stringify(track_ids[url.query.id]));
        }
        else {
            response.write(JSON.stringify({
                error: "Can't find id in session table"
            }));
        }
        response.end();
    }
    else {
        do_error(response, 400, "Missing id in query string");
    }
}

function new_client(new_request, new_response) {
    sys.puts(new_request.connection.remoteAddress + " " + new_request.method + " " + new_request.url);
    if (new_request.method === "GET") {
        var url_parsed = url.parse(new_request.url, true),
            pathname = url_parsed.pathname;

        switch (url_parsed.pathname) {
        case "/":
        case "/index.html":
        case "/favicon.ico":
            handle_file(pathname, new_request, new_response);
            break;
        case "/send_file":
            send_start(url_parsed, new_request, new_response);
            break;
        case "/get_stats":
            get_stats(url_parsed, new_request, new_response);
            break;
        default:
            do_error(new_response, 404, "Not found");
        }
    } else {
        do_error(new_response, 404, "WTF");
    }
}

http.createServer(new_client).listen(80);
sys.puts("Listening for HTTP");

process.addListener("uncaughtException", function (event) {
    sys.puts("Uncaught Exception: " + event.stack);
});

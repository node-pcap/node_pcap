var
  rewire = require("rewire"),
  pcap = rewire("../pcap");

describe("pcap Tests", function() {
  beforeEach(function() {
    //is_live, device_name, filter, buffer_size, outfile, is_monitor
    var pcapServiceMock = {

      default_device: function() {
        return "en0";
      },
      PcapSession: function() {
        return mysessionObject;
      },
      findalldevs: function(){
        return ["en0","eth0"];
      }
    };

    var mysessionObject = {
      /* jshint ignore:start */
      open_live: function(device_name, filter, buffer_size, outfile, packet_ready, is_monitor) {
        return "LINKTYPE_ETHERNET";
      },
      open_offline: function(device_name, filter, buffer_size, outfile, packet_ready, is_monitor) {

        return "LINKTYPE_ETHERNET";
      },
      /* jshint ignore:end */
      fileno: function() {
        return "123";
      }

    };
    var SocketWatcherMock = function() {

    };

    /* jshint ignore:start */
    SocketWatcherMock.prototype.set = function(fd, two, three) {

    };
    /* jshint ignore:end */
    SocketWatcherMock.prototype.start = function() {

    };

    pcap.__set__({
      "binding": pcapServiceMock,
      "SocketWatcher": SocketWatcherMock
    });

  });

  describe("#Initializing with default values  ", function() {


    it("link type should be LINKTYPE_ETHERNET", function() {
      this.instance = pcap.createSession("en0", "ip tcp", 1000, "", false);
      this.instance.link_type.should.equal("LINKTYPE_ETHERNET");

    });

    it(" device_name should be en0", function() {
      this.instance = pcap.createSession("en0", "ip tcp", 1000, "", false);

      this.instance.device_name.should.equal("en0");

    });

    it(" filter should be ip tcp", function() {
      this.instance = pcap.createSession("en0", "ip tcp", 1000, "", false);
      this.instance.filter.should.equal("ip tcp");

    });

    it(" monitor  should be false", function() {
      this.instance = pcap.createSession("en0", "ip tcp", 1000, "", false);
      this.instance.is_monitor.should.equal(false);

    });

    it(" buffer_size  should be 1000", function() {
      this.instance = pcap.createSession("en0", "ip tcp", 1000, "", false);
      this.instance.buffer_size.should.equal(1000);

    });
    it(" buffer_size  should be 10 * 1024 * 1024 by default", function() {
      this.instance = pcap.createSession("en0", "ip tcp", "", "", false);
      this.instance.buffer_size.should.equal(10 * 1024 * 1024);

    });


  });



});
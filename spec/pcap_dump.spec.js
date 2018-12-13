var
  rewire = require("rewire"),
  pcap_dump = rewire("../pcap_dump"),
  should = require("should"),
  sinon = require("sinon");

describe("pcap_dump", function() {
  beforeEach(function() {
    var pcapServiceMock = {

      default_device: function() {
        return "en0";
      },
      PcapSession: function() {
        return mysessionObject;
      },
      findalldevs: function() {
        return ["en0", "eth0"];
      },
      /* jshint ignore:start */
      create_pcap_dump_async: function(device_name, filter, buffer_size, outfile, packet_ready, is_monitor, packet_write_complete) {
          return "LINKTYPE_ETHERNET";
        }
        /* jshint ignore:end */
    };
    var mysessionObject = {
      /* jshint ignore:start */
      open_live: function(device_name, filter, buffer_size, outfile, packet_ready, is_monitor) {
        return "LINKTYPE_ETHERNET";
      },
      open_offline: function(device_name, filter, buffer_size, outfile, packet_ready, is_monitor) {

        return "LINKTYPE_ETHERNET";
      },

      fileno: function() {
        return "123";
      },

      stats: function() {

      },
      close: function() {

        }
        /* jshint ignore:end */
    };
    pcap_dump.__set__({
      "binding": pcapServiceMock

    });

  });



  describe("#start should take the default values ", function() {
    beforeEach(function() {
      this.instance = pcap_dump.createPcapDumpSession();
    });
    it("buffer size should be 10485760 ", function() {
      this.instance.startAsyncCapture();
      should(this.instance.buffer_size).be.equal(10485760);
    });

    it("outfile should be tmp.pcap ", function() {
      this.instance.startAsyncCapture();

      should(this.instance.outfile).be.equal("tmp.pcap");

    });

    it("number_of_packets_to_be_read should be 1", function() {
      this.instance.startAsyncCapture();

      should(this.instance.number_of_packets_to_be_read).be.equal(1);

    });

    it("is_monitor should be false", function() {
      this.instance.startAsyncCapture();

      should(this.instance.is_monitor).be.equal(false);

    });

    it("calls sesssion.close on calling close", function() {
      var mock = sinon.mock(this.instance.session);
      mock.expects("close").returns(true);
      this.instance.close();
      mock.verify();
      mock.restore();

    });

    it("calls sesssion.stats on calling stats", function() {
      var mock = sinon.mock(this.instance.session);
      mock.expects("stats").returns(true);
      this.instance.stats();
      mock.verify();
      mock.restore();

    });


  });


  describe("#start should values given in  ", function() {
    beforeEach(function() {
      //(device_name, filter, buffer_size, outfile, packet_ready, is_monitor)
      this.instance = pcap_dump.createPcapDumpSession("eth1", "dst", 1000, "", "", false);
    });
    it("buffer size should be 1000 ", function() {
      this.instance.startAsyncCapture();
      should(this.instance.buffer_size).be.equal(1000);
    });
    it("findalldevs  should return the arrayy ", function() {
      this.instance.startAsyncCapture();
      var devices = pcap_dump.findalldevs();
      should(devices[0]).be.equal("en0");
      should(devices[1]).be.equal("eth0");

    });

  });

});
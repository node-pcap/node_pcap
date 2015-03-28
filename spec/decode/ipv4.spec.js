var IPv4 = require("../../decode/ipv4");
var shouldBehaveLikeADecoder = require("./decode").shouldBehaveLikeADecoder;
var events = require("events");
require("should");

describe("IPv4", function(){
  beforeEach(function () {
    this.example = new Buffer("46c000200000400001021274c0a82101effffffa94040000" + //header
                         "1600fa04effffffa" + //igmpv2
                         "00000000", //checksum
                         "hex");
    this.eventEmitter = new events.EventEmitter();
    this.instance = new IPv4(this.eventEmitter);
  });

  describe("#decode", function(){
    shouldBehaveLikeADecoder("ipv4", true);

    it("sets #version to 4", function() { //After all this is ip "v4"
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("version", 4);
    });

    it("sets #headerLength to the header length", function() { //After all this is ip "v4"
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("headerLength", 24);
    });

    it("sets #diffserv to the differentied services field", function() { //After all this is ip "v4"
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("diffserv", 0xc0);
    });

    it("sets #flags to a decoded version of the ip flags", function() {
      this.instance.decode(this.example, 0);
      this.instance.flags.should.be.property("reserved", false);
      this.instance.flags.should.be.property("doNotFragment", true);
      this.instance.flags.should.be.property("moreFragments", false);
    });

    it("sets #fragmentOffset to the fragmentation offset", function(){
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("fragmentOffset", 0);
    });

    it("sets #ttl to the time to live", function(){
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("ttl", 1);
    });

    it("sets #protocol to the time to live", function(){
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("protocol", 2);
    });

    it("sets #headerChecksum to the checksum of the header", function(){
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("headerChecksum", 0x1274);
    });

    it("sets #saddr to the senders address", function(){
      this.instance.decode(this.example, 0);
      this.instance.saddr.should.have.property("addr", [192, 168, 33, 1]);
    });

    it("sets #daddr to the destination address", function(){
      this.instance.decode(this.example, 0);
      this.instance.daddr.should.have.property("addr", [239, 255, 255, 250]);
    });
  });

  describe("#toString()", function(){
    it("is a function", function(){
      this.instance.toString.should.be.type("function");
    });

    it("returns a value like \"192.168.33.1 -> 239.255.255.250 IGMP Membership Report\" when no flags are set", function(){
      var noflags = new Buffer("46c000200000000001021274c0a82101effffffa94040000" + //header
                               "1600fa04effffffa" + //igmpv2
                               "00000000", //checksum
                               "hex");

      this.instance.decode(noflags, 0);

      this.instance.toString().should.be.exactly("192.168.33.1 -> 239.255.255.250 IGMP Membership Report");
    });

    it("returns a value like \"192.168.33.1 -> 239.255.255.250 flags [d] IGMP Membership Report\" when flags are set", function() {
      this.instance.decode(this.example, 0);
      this.instance.toString().should.be.exactly("192.168.33.1 -> 239.255.255.250 flags [d] IGMP Membership Report");
    });

    it("returns a value like \"192.168.33.1 -> 239.255.255.250 flags [d] proto 255 undefined\" when the protocol is not support by node_pcap", function() {
      var unknownProtocol = new Buffer("46c000200000400001ff1274c0a82101effffffa94040000" + //header
                                       "00000000", //checksum
                                       "hex");

      this.instance.decode(unknownProtocol, 0);
      this.instance.toString().should.be.exactly("192.168.33.1 -> 239.255.255.250 flags [d] proto 255 undefined");
    });
  });
});
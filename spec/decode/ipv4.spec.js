var IPv4 = require("../../decode/ipv4");
require("should");

describe("IPv4", function(){
  var example, instance;
  beforeEach(function () {
    example = new Buffer("46c000200000400001021274c0a82101effffffa94040000" + //header
                         "1600fa04effffffa" + //igmpv2
                         "00000000", //checksum
                         "hex");
    instance = new IPv4();
  });

  describe("#decode", function(){
    it("is a function", function(){
        instance.decode.should.be.type("function");
    });

    it("sets #version to 4", function() { //After all this is ip "v4"
      instance.decode(example, 0);
      instance.should.have.property("version", 4);
    });

    it("sets #headerLength to the header length", function() { //After all this is ip "v4"
      instance.decode(example, 0);
      instance.should.have.property("headerLength", 24);
    });

    it("sets #diffserv to the differentied services field", function() { //After all this is ip "v4"
      instance.decode(example, 0);
      instance.should.have.property("diffserv", 0xc0);
    });

    it("sets #flags to a decoded version of the ip flags", function() {
      instance.decode(example, 0);
      instance.flags.should.be.property("reserved", false);
      instance.flags.should.be.property("doNotFragment", true);
      instance.flags.should.be.property("moreFragments", false);
    });

    it("sets #fragmentOffset to the fragmentation offset", function(){
      instance.decode(example, 0);
      instance.should.have.property("fragmentOffset", 0);
    });

    it("sets #ttl to the time to live", function(){
      instance.decode(example, 0);
      instance.should.have.property("ttl", 1);
    });

    it("sets #protocol to the time to live", function(){
      instance.decode(example, 0);
      instance.should.have.property("protocol", 2);
    });

    it("sets #headerChecksum to the checksum of the header", function(){
      instance.decode(example, 0);
      instance.should.have.property("headerChecksum", 0x1274);
    });

    it("sets #saddr to the senders address", function(){
      instance.decode(example, 0);
      instance.saddr.should.have.property("addr", [192, 168, 33, 1]);
    });

    it("sets #daddr to the destination address", function(){
      instance.decode(example, 0);
      instance.daddr.should.have.property("addr", [239, 255, 255, 250]);
    });
  });

  describe("#toString()", function(){
    var instance;
    beforeEach(function(){
      instance = new IPv4();
    });

    it("is a function", function(){
      instance.toString.should.be.type("function");
    });

    it("returns a value like \"192.168.33.1 -> 239.255.255.250 IGMP Membership Report\" when no flags are set", function(){
      var noflags = new Buffer("46c000200000000001021274c0a82101effffffa94040000" + //header
                               "1600fa04effffffa" + //igmpv2
                               "00000000", //checksum
                               "hex");

      instance.decode(noflags, 0);

      instance.toString().should.be.exactly("192.168.33.1 -> 239.255.255.250 IGMP Membership Report");
    });

    it("returns a value like \"192.168.33.1 -> 239.255.255.250 flags [d] IGMP Membership Report\" when flags are set", function() {
      instance.decode(example, 0);
      instance.toString().should.be.exactly("192.168.33.1 -> 239.255.255.250 flags [d] IGMP Membership Report");
    });

    it("returns a value like \"192.168.33.1 -> 239.255.255.250 flags [d] proto 255 undefined\" when the protocol is not support by node_pcap", function() {
      var unknownProtocol = new Buffer("46c000200000400001ff1274c0a82101effffffa94040000" + //header
                                       "00000000", //checksum
                                       "hex");

      instance.decode(unknownProtocol, 0);
      instance.toString().should.be.exactly("192.168.33.1 -> 239.255.255.250 flags [d] proto 255 undefined");
    });
  });
});
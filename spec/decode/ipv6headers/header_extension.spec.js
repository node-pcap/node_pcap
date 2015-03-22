var HeaderExtension = require("../../../decode/ipv6headers/header_extension");
var NoNext = require("../../../decode/ipv6headers/no_next");
var should = require("should");

describe("HeaderExtension", function(){
  var instance, example;
  beforeEach(function(){
    instance = new HeaderExtension();
    example = new Buffer("3B" + // No next will be the next header
                         "01" + // the length of the the header in 8 byte units - 8bytes
                         "0000000000000000" +
                         "000000000000", // details about the current header
                         "hex");
  });

  describe("#decode()", function(){
    it("is a function", function(){
      instance.decode.should.be.type("function");
    });

    it("sets #nextHeader to the protocol number of the next payload", function(){
      instance.decode(example, 0);
      instance.should.have.property("nextHeader", 0x3B);
    });

    it("sets #headerLength to the length of the header in bytes", function(){
      instance.decode(example, 0);
      instance.should.have.property("headerLength", 16);
    });

    it("sets #payload to the next header", function(){
      instance.decode(example, 0);
      instance.payload.should.be.instanceOf(NoNext);
      should.not.exist(instance.payload._error);
    });
  });

  describe("#toString()", function(){
    it("is a function", function(){
        instance.toString.should.be.type("function");
    });

    it("returns a value like \"proto 255 undefined\" when the protocol is not support by node_pcap", function(){
      instance.decode(new Buffer("FF00000000000000","hex"), 0);
      instance.toString().should.be.exactly("proto 255 undefined");
    });

    it("returns a value like \"IGMP Membership Report\" when the protocol is support by node_pcap", function(){
      instance.decode(new Buffer("0200000000000000" +
        "1600fa04effffffa", //IGMP
        "hex"), 0);
      instance.toString().should.be.exactly("IGMP Membership Report");
    });
  });
});
var LogicalLinkControl = require("../../decode/llc_packet");
var IPv4 = require("../../decode/ipv4");
var should = require("should");

describe("LogicalLinkControl", function(){
  var example, instance;
  beforeEach(function () {
    example = new Buffer("aaaa030000000800" + //LLC frame
                         "46c000200000400001021274c0a82101effffffa94040000" + //ipv4 payload
                         "1600fa04effffffa" + //igmpv2
                         "00000000", "hex");
    instance = new LogicalLinkControl();
  });

  describe("#decode", function(){
    it("is a function", function(){
      instance.decode.should.be.type("function");
    });

    it("sets #dsap to the destination service access point", function(){
      instance.decode(example, 0);
      instance.should.have.property("dsap", 0xaa);
    });

    it("sets #ssap to the source service access point", function(){
      instance.decode(example, 0);
      instance.should.have.property("ssap", 0xaa);
    });

    it("sets #controlField to the destination service access point", function(){
      instance.decode(example, 0);
      instance.should.have.property("controlField", 0x03);
    });

    it("sets #orgCode to the destination service access point", function(){
      instance.decode(example, 0);
      instance.should.have.property("orgCode", [0,0,0]);
    });

    it("sets #type to the type of the payload", function(){
      instance.decode(example, 0);
      //Not that this is not the decoder type
      instance.should.have.property("type", 2048);
    });

    it("sets #payload to the decoded", function(){
      instance.decode(example, 0);
      instance.payload.should.be.instanceOf(IPv4);
      should.not.exist(instance._error);
    });

    it("sets #_error if the frame can't be decoded", function(){
      instance.decode(new Buffer("0101030000000800"), 0);
      should.exist(instance._error);
    });
  });
});
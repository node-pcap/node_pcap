var LogicalLinkControl = require("../../decode/llc_packet");
var IPv4 = require("../../decode/ipv4");
var events = require("events");
var shouldBehaveLikeADecoder = require("./decode").shouldBehaveLikeADecoder;
var should = require("should");

describe("LogicalLinkControl", function(){
  beforeEach(function () {
    this.example = new Buffer("aaaa030000000800" + //LLC frame
                         "46c000200000400001021274c0a82101effffffa94040000" + //ipv4 payload
                         "1600fa04effffffa" + //igmpv2
                         "00000000", "hex");
    this.eventEmitter = new events.EventEmitter();
    this.instance = new LogicalLinkControl(this.eventEmitter);
  });

  describe("#decode", function(){
    shouldBehaveLikeADecoder("llc", true);

    it("sets #dsap to the destination service access point", function(){
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("dsap", 0xaa);
    });

    it("sets #ssap to the source service access point", function(){
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("ssap", 0xaa);
    });

    it("sets #controlField to the destination service access point", function(){
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("controlField", 0x03);
    });

    it("sets #orgCode to the destination service access point", function(){
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("orgCode", [0,0,0]);
    });

    it("sets #type to the type of the payload", function(){
      this.instance.decode(this.example, 0);
      //Not that this is not the decoder type
      this.instance.should.have.property("type", 2048);
    });

    it("sets #payload to the decoded", function(){
      this.instance.decode(this.example, 0);
      this.instance.payload.should.be.instanceOf(IPv4);
      should.not.exist(this.instance._error);
    });

    it("sets #_error if the frame can't be decoded", function(){
      this.instance.decode(new Buffer("0101030000000800"), 0);
      should.exist(this.instance._error);
    });
  });
});
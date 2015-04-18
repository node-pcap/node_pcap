var DnsFlags = require("../../../decode/dns/flags");
var shouldBehaveLikeADecoder = require("../decode").shouldBehaveLikeADecoder;
require("should");

describe("DnsFlags", function(){
  beforeEach(function () {
    this.instance = new DnsFlags();
    this.example = new Buffer("0100", "hex");
  });

  describe("#decode()", function(){
    shouldBehaveLikeADecoder();

    it("sets #isResponse", function(){
      this.instance.decode(new Buffer([0x80, 0x00], "hex"), 0);
      this.instance.should.have.property("isResponse", true);

      this.instance.decode(new Buffer([0x00, 0x00], "hex"), 0);
      this.instance.should.have.property("isResponse", false);
    });

    it("sets #opcode", function(){
      this.instance.decode(new Buffer([0x78, 0x00], "hex"), 0);
      this.instance.should.have.property("opcode", 15);

      this.instance.decode(new Buffer([0x00, 0xff], "hex"), 0);
      this.instance.should.have.property("opcode", 0);
    });

    it("sets #isAuthority", function(){
      this.instance.decode(new Buffer([0x04, 0x00], "hex"), 0);
      this.instance.should.have.property("isAuthority", true);

      this.instance.decode(new Buffer([0x00, 0xff], "hex"), 0);
      this.instance.should.have.property("isAuthority", false);
    });

    it("sets #isTruncated", function(){
      this.instance.decode(new Buffer([0x02, 0x00], "hex"), 0);
      this.instance.should.have.property("isTruncated", true);

      this.instance.decode(new Buffer([0x00, 0xff], "hex"), 0);
      this.instance.should.have.property("isTruncated", false);
    });

    it("sets #isRecursionDesired", function(){
      this.instance.decode(new Buffer([0x01, 0x00], "hex"), 0);
      this.instance.should.have.property("isRecursionDesired", true);

      this.instance.decode(new Buffer([0x00, 0xff], "hex"), 0);
      this.instance.should.have.property("isRecursionDesired", false);
    });

    it("sets #isRecursionAvailible", function(){
      this.instance.decode(new Buffer([0x00, 0x80], "hex"), 0);
      this.instance.should.have.property("isRecursionAvailible", true);

      this.instance.decode(new Buffer([0xff, 0x0f], "hex"), 0);
      this.instance.should.have.property("isRecursionAvailible", false);
    });

    it("sets #z", function(){
      this.instance.decode(new Buffer([0x00, 0x70], "hex"), 0);
      this.instance.should.have.property("z", 7);

      this.instance.decode(new Buffer([0xff, 0x0f], "hex"), 0);
      this.instance.should.have.property("z", 0);
    });

    it("sets #responseCode", function(){
      this.instance.decode(new Buffer([0x00, 0x0f], "hex"), 0);
      this.instance.should.have.property("responseCode", 15);

      this.instance.decode(new Buffer([0xff, 0x00], "hex"), 0);
      this.instance.should.have.property("responseCode", 0);
    });
  });
});

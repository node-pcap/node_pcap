var NullPacket = require("../../decode/null_packet");
var shouldBehaveLikeADecoder = require("./decode").shouldBehaveLikeADecoder;
require("should");

describe("NullPacket", function(){
  beforeEach(function () {
    this.instance = new NullPacket();
    this.example = new Buffer("", "hex");
  });

  describe("#decode()", function(){
    shouldBehaveLikeADecoder();

    it("is a function", function(){
      this.instance.decode.should.be.type("function");
    });

    //Need to test Ipv4 and v6 prior to testing this
  });

  describe("#toString()", function(){
    it("is a function", function(){
      this.instance.toString.should.be.type("function");
    });
  });
});
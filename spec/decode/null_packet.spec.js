var NullPacket = require("../../decode/null_packet");
require("should");

describe("NullPacket", function(){
  var instance;
  beforeEach(function () {
    instance = new NullPacket();
  });

  describe("#decode()", function(){
    it("is a function", function(){
        instance.decode.should.be.type("function");
    });

    //Need to test Ipv4 and v6 prior to testing this
  });

  describe("#toString()", function(){
    it("is a function", function(){
      instance.toString.should.be.type("function");
    });
  });
});
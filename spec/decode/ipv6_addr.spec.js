var IPv6Addr = require("../../decode/ipv6_addr");
require("should");

describe("IPv6Addr", function(){
  var exampleIp, instance;
  beforeEach(function () {
    exampleIp = new Buffer("000102030405060708090A0B0C0D0E0F", "hex");
    instance = new IPv6Addr();
  });

  describe("#decode()", function(){
    it("is a function", function(){
        instance.decode.should.be.type("function");
    });

    it("sets the #addr property to the ipv6 address", function() {
      instance.decode(exampleIp, 0);
      instance.should.have.property("addr", [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]);
    });
  });

  describe("#toString()", function(){
    it("is a function", function(){
      instance.toString.should.be.type("function");
    });

    it("returns a string like 0001:0203:0405:0607:0809:0a0b:0c0d:0e0f", function(){
      instance.decode(exampleIp, 0);
      var result = instance.toString();
      result.should.be.exactly("0001:0203:0405:0607:0809:0a0b:0c0d:0e0f");
    });
  });
});
var IPv4Addr = require("../../decode/ipv4_addr");
require("should");

describe("IPv4Addr", function(){
  var exampleIp, instance;
  beforeEach(function () {
    exampleIp = new Buffer("01020304", "hex");
    instance = new IPv4Addr();
  });

  describe("#decode", function(){
    it("is a function", function(){
        instance.decode.should.be.type("function");
    });

    it("it sets #addr to the ipv4 address", function() {
      instance.decode(exampleIp, 0);
      instance.should.have.property("addr", [1, 2, 3, 4]);
    });
  });

  describe("#toString()", function(){
    var instance;
    beforeEach(function(){
      instance = new IPv4Addr(exampleIp, 0);
    });

    it("is a function", function(){
      instance.toString.should.be.type("function");
    });

    it("returns a string like 1.2.3.4", function(){
      instance.decode(exampleIp, 0);
      var result = instance.toString();
      result.should.be.exactly("1.2.3.4");
    });
  });
});
var IPv4Addr = require("../../decode/ipv4_addr");
require("should");

describe("IPv4Addr", function(){
  var exampleIp;
  beforeEach(function () {
    exampleIp = new Buffer("01020304", "hex");
  });

  describe("constructor", function(){
    it("is a function", function(){
        IPv4Addr.should.be.type("function");
    });

    it("decodes ip address", function() {
      var instance = new IPv4Addr(exampleIp, 0);

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
      var result = instance.toString();
      result.should.be.exactly("1.2.3.4");
    });
  });
});
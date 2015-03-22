var EthernetAddr = require("../../decode/ethernet_addr");
require("should");

describe("EthernetAddr", function(){
  var exampleIp;
  beforeEach(function () {
    exampleIp = new Buffer("010203040506", "hex");
  });

  describe("constructor", function(){
    it("is a function", function(){
        EthernetAddr.should.be.type("function");
    });

    it("decodes ethernet(MAC) address", function() {
      var instance = new EthernetAddr(exampleIp, 0);
      instance.should.have.property("addr", [1,2,3,4,5,6]);
    });
  });

  describe("#toString()", function(){
    var instance;
    beforeEach(function(){
      instance = new EthernetAddr(exampleIp, 0);
    });

    it("is a function", function(){
      instance.toString.should.be.type("function");
    });

    it("returns a string like 01:02:03:04:05:06", function(){
      var result = instance.toString();
      result.should.be.exactly("01:02:03:04:05:06");
    });
  });
});
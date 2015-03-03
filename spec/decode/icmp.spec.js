var Icmp = require("../../decode/icmp");
require("should");

describe("ICMP", function(){
  var exampleIcmp, instance;
  beforeEach(function () {
    exampleIcmp = new Buffer("01020304", "hex");
    instance = new Icmp();
  });

  describe("#decode()", function(){
    it("is a function", function(){
        instance.decode.should.be.type("function");
    });

    it("sets the #type to the ICMP type", function() {
      instance.decode(exampleIcmp, 0);
      instance.should.have.property("type", 1);
    });

    it("sets the #code to the ICMP subtype", function() {
      instance.decode(exampleIcmp, 0);
      instance.should.have.property("code", 2);
    });

    it("sets the #checksum to the decoded checksum for the header and data", function() {
      instance.decode(exampleIcmp, 0);
      instance.should.have.property("checksum", 772);
    });
  });
});
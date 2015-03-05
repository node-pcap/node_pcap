var Igmp = require("../../decode/igmp");
var util = require("../../util");
require("should");

describe("IGMP", function(){
  var exampleIgmp, instance;
  beforeEach(function () {
    exampleIgmp = new Buffer("0102030405060708", "hex");
    instance = new Igmp();
  });

  describe("#decode()", function(){
    it("is a function", function(){
        instance.decode.should.be.type("function");
    });

    it("sets the #type to the IGMP type", function() {
      instance.decode(exampleIgmp, 0);
      instance.should.have.property("type", 1);
    });

    it("sets the #maxResponseTime", function() {
      instance.decode(exampleIgmp, 0);
      instance.should.have.property("maxResponseTime", 2);
    });

    it("sets the #checksum", function() {
      instance.decode(exampleIgmp, 0);
      instance.should.have.property("checksum", 772);
    });

    it("sets the #groupAddress", function() {
      instance.decode(exampleIgmp, 0);
      instance.groupAddress.should.have.property("addr", [5, 6, 7, 8]);
    });
  });

  describe("#toString()", function() {
    var verifyToString = function verifyToString(type, result){
      it("return \""+result+"\" for igmp of type="+type, function(){
        instance = new Igmp();
        instance.decode(new Buffer(util.int8_to_hex[type] + "000000000000", "hex"), 0);
        instance.toString().should.be.exactly(result);
      });
    };

    //verifyToString(type, string)
    verifyToString(0x11, "Membership Query");
    verifyToString(0x12, "Membership Report");
    verifyToString(0x16, "Membership Report");
    verifyToString(0x17, "Leave Group");
    verifyToString(0x22, "Membership Report");

    //Default handler
    verifyToString(0x01, "type 1");
  });
});

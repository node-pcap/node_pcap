var Icmp = require("../../decode/icmp");
var util = require("../../util");
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

  describe("#toString()", function() {
    var verifyToString = function verifyToString(type, code, result){
      it("return \""+result+"\" for icmp of type="+type+" code="+code, function(){
        instance = new Icmp();
        instance.decode(new Buffer(util.int8_to_hex[type] + util.int8_to_hex[code] + "0000", "hex"), 0);
        instance.toString().should.be.exactly(result);
      });
    };

    //verifyToString(type, code, string)
    verifyToString(0, 0, "Echo Reply");
    //types 1-2 are reserved for future use

    verifyToString(3, 0, "Destination Network Unreachable");
    verifyToString(3, 1, "Destination Host Unreachable");
    verifyToString(3, 2, "Destination Protocol Unreachable");
    verifyToString(3, 3, "Destination Port Unreachable");
    verifyToString(3, 4, "Fragmentation required, and DF flag set");
    verifyToString(3, 5, "Source route failed");
    verifyToString(3, 6, "Destination network unknown");
    verifyToString(3, 7, "Destination host unknown");
    verifyToString(3, 8, "Source host isolated");
    verifyToString(3, 9, "Network administratively prohibited");
    verifyToString(3, 10, "Host administratively prohibited");
    verifyToString(3, 11, "Network unreachable for TOS");
    verifyToString(3, 12, "Host unreachable for TOS");
    verifyToString(3, 13, "Communication administratively prohibited");
    verifyToString(3, 14, "Destination Unreachable (unknown code 14)");

    verifyToString(4, 0, "Source Quench");

    verifyToString(5, 0, "Redirect Network");
    verifyToString(5, 1, "Redirect Host");
    verifyToString(5, 2, "Redirect TOS and Network");
    verifyToString(5, 3, "Redirect TOS and Host");
    verifyToString(5, 4, "Redirect (unknown code 4)");

    verifyToString(6, 0, "Alternate Host Address");

    verifyToString(7, 0, "Reserved");

    verifyToString(8, 0, "Echo Request");

    verifyToString(9, 0, "Router Advertisement");

    verifyToString(10, 0, "Router Solicitation");

    verifyToString(11, 0, "TTL expired in transit");
    verifyToString(11, 1, "Fragment reassembly time exceeded");
    verifyToString(11, 2, "Time Exceeded (unknown code 2)");

    //Default handler
    verifyToString(12, 0, "type 12 code 0");
  });
});

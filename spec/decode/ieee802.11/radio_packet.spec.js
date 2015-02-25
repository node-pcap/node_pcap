var RadioPacket = require("../../../decode/ieee802.11/radio_packet");

describe("RadioPacket", function(){
  var instance, probeExample1, probeExample2;
  beforeEach(function () {

    // a probe that has additional information in the header
    probeExample2 = new Buffer("00001A002F480000000000000000000010026C09A000D8000000" + //Example of a radio tap header
                              "40000000ffffffffffffe4ce8f16da48ffffffffffff804b" + // Probe request
                              "0000010402040b16" + // i802.11 tags [ssid]
                              "FFFFFFFF" , "hex"); // checksum, note this one is not valid

    // a probe that has no additional information in the header
    probeExample1 = new Buffer("000012002e48000000028509a000d3010000" + //Example of a radio tap header
                              "40000000ffffffffffffe4ce8f16da48ffffffffffff804b" + // Probe request
                              "0000010402040b16" + // i802.11 tags [ssid]
                              "FFFFFFFF" , "hex"); // checksum, note this one is not valid
    instance = new RadioPacket();
  });

  describe("#decode()", function(){
    it("is a function", function(){
        instance.decode.should.be.type("function");
    });

    it("sets #headerLength to be the length of the packet header", function() {
      instance.decode(probeExample1, 0);
      instance.should.have.property("headerLength", 18);
    });

    it("sets #signalStrength to be the signal strength in dbi", function(){
      instance.decode(probeExample2, 0);
      instance.should.have.property("signalStrength", -40);
    });

    it("handles different length packet headers", function() {
      instance.decode(probeExample1, 0);
      instance.should.have.property("signalStrength", -45);
    });
  });
});

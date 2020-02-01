var RadioPacket = require("../../../decode/ieee802.11/radio_packet");

describe("RadioPacket", function(){
  var instance, probeExample1, probeExample2, probeExample3;
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

    probeExample3 = new Buffer("000018006f0000008e64643a0000000010029409a000af00" + //Example of a radio tap header
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

    it("sets #antenna_signal to be the signal strength in dbi", function(){
      instance.decode(probeExample2, 0);
      instance.fields.should.have.property("antenna_signal", -40);
    });

    it("handles different length packet headers", function() {
      instance.decode(probeExample1, 0);
      instance.fields.should.have.property("antenna_signal", -45);
    });

    it("handles 64-bit fields", function() {
      instance.decode(probeExample3, 0);
      instance.fields.should.eql({
        tsft: BigInt(979657870),
        flags: 0x10,
        rate: 2,
        channel: { frequency: 2452, flags: 160 },
        antenna_signal: -81,
        antenna_noise: 0
      });
    });

  });
});

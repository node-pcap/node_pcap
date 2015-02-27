var RadioBeaconFrame = require("../../../decode/ieee802.11/radio_beacon_frame");
require("should");

describe("RadioBeaconFrame", function(){
  var instance, beaconExample;
  beforeEach(function () {
    beaconExample = new Buffer("83b13dc90e0d000064003104" + // fixed width parameters
                               "00074e455447454152" + // netgear ssid tag
                               "010882848b9624b0486c" + // supported rates
                               "FFFFFFFF", "hex"); // a bad checksum to make parser happy
    instance = new RadioBeaconFrame();
  });

  describe("#decode()", function(){
    it("is a function", function(){
        instance.decode.should.be.type("function");
    });
    it("set #tags to be all tags in the packet", function() {
      instance.decode(beaconExample, 0);
      instance.tags.should.be.instanceof(Array).and.have.lengthOf(2);
    });
  });
});

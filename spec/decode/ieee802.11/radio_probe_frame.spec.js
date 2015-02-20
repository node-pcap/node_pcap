var RadioProbeFrame = require("../../../decode/ieee802.11/radio_probe_frame");
require("should");

describe("RadioProbeFrame", function(){
  var instance, probeExample;
  beforeEach(function () {
    probeExample = new Buffer("00074e455447454152010402040b1632080c1218243048606c2" +
                              "d1a20101aff0000000000000000000000000000000000000000" +
                              "0000030101dd09001018020000000000dd1e00904c3320101af" +
                              "f00000000000000000000000000000000000000000000FFFFFFFF", "hex");
    instance = new RadioProbeFrame();
  });

  describe("#decode()", function(){
    it("is a function", function(){
        instance.decode.should.be.type("function");
    });
    it("set #tags to be all tags in the packet", function() {
      instance.decode(probeExample, 0);
      instance.tags.should.be.instanceof(Array).and.have.lengthOf(7);
    });
  });
});

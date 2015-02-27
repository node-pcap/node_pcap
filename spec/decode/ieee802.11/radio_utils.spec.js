var radioUtils = require("../../../decode/ieee802.11/radio_utils");

describe("radioUtils", function(){
  describe("#parseTags()", function(){
    var threeTags;
    beforeEach(function(){
      threeTags = new Buffer("010130"+     //id=0, length=1, value=0x30
                             "0203040506"+ //id=2, length=3, value=0x040506
                             "0300"+       //id=3, length=0
                             "FFFFFFFF", "hex"); //new to provide 'checksum'
    });

    it("is a function", function(){
        radioUtils.parseTags.should.be.type("function");
    });

    it("returns a list of RadioManagementFrameTags from the provided buffer", function(){
      var tags = radioUtils.parseTags(threeTags, 0);
      tags.should.be.instanceof(Array).and.have.lengthOf(3);
    });

    it("skips over the provided offset", function(){
      //skip over the first tag to show offset is used
      var tags = radioUtils.parseTags(threeTags, 3);
      tags.should.be.instanceof(Array).and.have.lengthOf(2);
    });
  });
});

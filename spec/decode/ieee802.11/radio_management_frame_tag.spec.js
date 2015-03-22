var RadioManagementFrameTag = require("../../../decode/ieee802.11/radio_management_frame_tag");
var should = require("should");

describe("RadioManagementFrameTag", function(){
  var instance;
  beforeEach(function () {
    instance = new RadioManagementFrameTag();
  });

  describe("#decode()", function(){
    var ssidTag; //Id=0, Length=7, ssid=NETGEAR

    beforeEach(function(){
      ssidTag = new Buffer("00074e455447454152", "hex");
    });

    it("is a function", function(){
        instance.decode.should.be.type("function");
    });

    it("returns a RadioManagementFrameTag", function(){
      var result = instance.decode(ssidTag, 0);
      should.exist(result);
    });

    it("sets the #ssid property if the tag has an id of 0", function(){
      var result = instance.decode(ssidTag, 0);
      result.should.have.property("type", "ssid");
      result.should.have.property("ssid", "NETGEAR");
    });

    it("sets the #length property to the length of the tag", function(){
      var result = instance.decode(ssidTag, 0);
      result.should.have.property("length", 7);
    });

    it("sets the #typeId property to the id of the tag", function(){
      var result = instance.decode(ssidTag, 0);
      result.should.have.property("typeId", 0);
    });
  });
});

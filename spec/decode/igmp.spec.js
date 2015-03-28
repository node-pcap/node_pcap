var Igmp = require("../../decode/igmp");
var util = require("../../util");
var events = require("events");
var shouldBehaveLikeADecoder = require("./decode").shouldBehaveLikeADecoder;
require("should");

describe("IGMP", function(){
  beforeEach(function () {
    this.example = new Buffer("0102030405060708", "hex");
    this.eventEmitter = new events.EventEmitter();
    this.instance = new Igmp(this.eventEmitter);
  });

  describe("#decode()", function(){
    shouldBehaveLikeADecoder("igmp", true);

    it("sets the #type to the IGMP type", function() {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("type", 1);
    });

    it("sets the #maxResponseTime", function() {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("maxResponseTime", 2);
    });

    it("sets the #checksum", function() {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("checksum", 772);
    });

    it("sets the #groupAddress", function() {
      this.instance.decode(this.example, 0);
      this.instance.groupAddress.should.have.property("addr", [5, 6, 7, 8]);
    });

    describe("when IGMP is type 0x11", function(){
      var packet;
      beforeEach(function(){
        packet = new Buffer("1102030405060708", "hex");
      });

      it("sets #version to 3", function(){
        this.instance.decode(packet, 0);
        this.instance.should.have.property("version", 3);
      });
    });

    describe("when IGMP is type 0x12", function(){
      var packet;
      beforeEach(function(){
        packet = new Buffer("1202030405060708", "hex");
      });

      it("sets #version to 1", function(){
        this.instance.decode(packet, 0);
        this.instance.should.have.property("version", 1);
      });
    });

    describe("when IGMP is type 0x16", function(){
      var packet;
      beforeEach(function(){
        packet = new Buffer("1602030405060708", "hex");
      });

      it("sets #version to 2", function(){
        this.instance.decode(packet, 0);
        this.instance.should.have.property("version", 2);
      });
    });

    describe("when IGMP is type 0x17", function(){
      var packet;
      beforeEach(function(){
        packet = new Buffer("1702030405060708", "hex");
      });

      it("sets #version to 2", function(){
        this.instance.decode(packet, 0);
        this.instance.should.have.property("version", 2);
      });
    });
    describe("when IGMP is type 0x22", function(){
      var packet;
      beforeEach(function(){
        packet = new Buffer("2202030405060708", "hex");
      });

      it("sets #version to 3", function(){
        this.instance.decode(packet, 0);
        this.instance.should.have.property("version", 3);
      });
    });
  });

  describe("#toString()", function() {
    var verifyToString = function verifyToString(type, result){
      it("return \""+result+"\" for igmp of type="+type, function(){
        this.instance = new Igmp();
        this.instance.decode(new Buffer(util.int8_to_hex[type] + "000000000000", "hex"), 0);
        this.instance.toString().should.be.exactly(result);
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

var Dns = require("../../decode/dns");
var events = require("events");
var shouldBehaveLikeADecoder = require("./decode").shouldBehaveLikeADecoder;
require("should");

describe("Dns", function(){
  beforeEach(function () {
    this.eventEmitter = new events.EventEmitter();
    this.instance = new Dns(this.eventEmitter);
    this.example = new Buffer("311f" + //transaction id
                              "0100" + //flags
                              "0001" + //1 Question
                              "0000" + //0 answer RRs
                              "0000" + //0 authority RRS
                              "0000" + //0 additional RRs
                              "01320131033136380331393207696e2d61646472046172706100" + //name:2.1.168.192.in-addr.arpa
                              "000c" + //type PTR
                              "0001", //Class IN
                              "hex");
  });

  describe("#decode()", function(){
    shouldBehaveLikeADecoder("dns", true);
  });

  describe("#toString()", function(){
    it("is a function", function(){
      this.instance.toString.should.be.type("function");
    });
  });
});
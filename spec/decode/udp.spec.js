var Udp = require("../../decode/udp");
var events = require("events");
var shouldBehaveLikeADecoder = require("./decode").shouldBehaveLikeADecoder;
require("should");

describe("Udp", function(){
  beforeEach(function () {
    this.eventEmitter = new events.EventEmitter();
    this.instance = new Udp(this.eventEmitter);
    this.example = new Buffer("04d2" + // source port 1234
                              "04d3" + // dst port 1235
                              "0009" + // length
                              "df03" + // checksum (this on is bad)
                              "30", "hex");
  });

  describe("#decode()", function(){
    shouldBehaveLikeADecoder("udp", true);

    it("sets #sport to the source port", function(){
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("sport", 1234);
    });

    it("sets #dport to the destination port", function(){
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("dport", 1235);
    });

    it("sets #length to the length of the payload", function(){
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("length", 9);
    });

    it("sets #data to the payload", function(){
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("data", new Buffer("30", "hex"));
    });

    it("sets #checksum to the checksum", function(){
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("checksum", 0xdf03);
    });
  });

  describe("#toString()", function(){
    it("is a function", function(){
      this.instance.toString.should.be.type("function");
    });
  });
});
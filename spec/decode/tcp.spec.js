var TCP = require("../../decode/tcp");
var events = require("events");
var shouldBehaveLikeADecoder = require("./decode").shouldBehaveLikeADecoder;
require("should");

describe("TCP", function(){
  beforeEach(function () {
    this.example = new Buffer("b5dd00500aaf604e0000000060c2102044b2000002040218", "hex");
    this.eventEmitter = new events.EventEmitter();
    this.instance = new TCP(this.eventEmitter);
  });

  describe("#decode()", function(){
    shouldBehaveLikeADecoder("tcp", true);

    it("sets #sport to the source port", function() {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("sport", 46557);
    });

    it("sets #dport to the destination port", function() {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("dport", 80);
    });

    it("sets #seqno to the sequence number (not relative)", function() {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("seqno", 179265614);
    });

    it("sets #headerLength to the length of the tcp header", function() {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("headerLength", 24);
    });

    it("sets #flags to a decoded copy of the tcp flags", function() {
      this.instance.decode(this.example, 0);
      this.instance.flags.should.have.property("nonce", false);
      //Congestion Window Reduce
      this.instance.flags.should.have.property("cwr", true);
      //Enc-echo set
      this.instance.flags.should.have.property("ece", true);
      //Urgent
      this.instance.flags.should.have.property("urg", false);
      //Acknowledgement
      this.instance.flags.should.have.property("ack", false);
      //Push
      this.instance.flags.should.have.property("psh", false);
      //Reset
      this.instance.flags.should.have.property("rst", false);
      this.instance.flags.should.have.property("syn", true);
      this.instance.flags.should.have.property("fin", false);
    });

    it("sets #windowSize to the window size", function() {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("windowSize", 4128);
    });

    it("sets #checksum to the checksum", function() {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("checksum", 17586);
    });

    it("sets #urgentPointer to urgentPointer", function() {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("urgentPointer", 0);
    });

    it("sets #dataLength to the length of data", function() {
      this.instance.decode(this.example, 0, 24);
      this.instance.should.have.property("dataLength", 0);
    });

    it("sets #data to null when there is no data", function() {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("data", null);
    });
  });

  describe("#toString", function(){
    it("is a function", function(){
      this.instance.toString.should.be.type("function");
    });

    it("returns a value like #->80 seq 179265614 ack 0 flags [ces] win 4128 csum 17586 [mss:536] len 0", function() {
      this.instance.decode(this.example, 0, 24);
      var result = this.instance.toString();
      result.should.be.exactly("46557->80 seq 179265614 ack 0 flags [ces] win 4128 csum 17586 [mss:536] len 0");
    });
  });
});

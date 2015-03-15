var TCP = require("../../decode/tcp");
require("should");

describe("TCP", function(){
  var exampleTcp, instance;
  beforeEach(function () {
    exampleTcp = new Buffer("b5dd00500aaf604e0000000060c2102044b2000002040218", "hex");
    instance = new TCP();
  });
  describe("#decode()", function(){
    it("is a function", function(){
        instance.decode.should.be.type("function");
    });

    it("sets #sport to the source port", function() {
      instance.decode(exampleTcp, 0);
      instance.should.have.property("sport", 46557);
    });

    it("sets #dport to the destination port", function() {
      instance.decode(exampleTcp, 0);
      instance.should.have.property("dport", 80);
    });

    it("sets #seqno to the sequence number (not relative)", function() {
      instance.decode(exampleTcp, 0);
      instance.should.have.property("seqno", 179265614);
    });

    it("sets #headerLength to the length of the tcp header", function() {
      instance.decode(exampleTcp, 0);
      instance.should.have.property("headerLength", 24);
    });

    it("sets #flags to a decoded copy of the tcp flags", function() {
      instance.decode(exampleTcp, 0);
      instance.flags.should.have.property("nonce", false);
      //Congestion Window Reduce
      instance.flags.should.have.property("cwr", true);
      //Enc-echo set
      instance.flags.should.have.property("ece", true);
      //Urgent
      instance.flags.should.have.property("urg", false);
      //Acknowledgement
      instance.flags.should.have.property("ack", false);
      //Push
      instance.flags.should.have.property("psh", false);
      //Reset
      instance.flags.should.have.property("rst", false);
      instance.flags.should.have.property("syn", true);
      instance.flags.should.have.property("fin", false);
    });

    it("sets #windowSize to the window size", function() {
      instance.decode(exampleTcp, 0);
      instance.should.have.property("windowSize", 4128);
    });

    it("sets #checksum to the checksum", function() {
      instance.decode(exampleTcp, 0);
      instance.should.have.property("checksum", 17586);
    });

    it("sets #urgentPointer to urgentPointer", function() {
      instance.decode(exampleTcp, 0);
      instance.should.have.property("urgentPointer", 0);
    });

    it("sets #dataLength to the length of data", function() {
      instance.decode(exampleTcp, 0, 24);
      instance.should.have.property("dataLength", 0);
    });

    it("sets #data to null when there is no data", function() {
      instance.decode(exampleTcp, 0);
      instance.should.have.property("data", null);
    });
  });
});

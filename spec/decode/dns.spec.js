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

    it("sets #id to the transaction id", function() {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("id", 0x311f);
    });

    it("sets #header.isResponse to true if the packet was a response", function() {
      this.instance.decode(this.example, 0);
      this.instance.header.should.have.property("isResponse", false);
    });

    it("sets #header.opcode to the opcode", function() {
      this.instance.decode(this.example, 0);
      this.instance.header.should.have.property("opcode", 0);
    });

    it("sets #header.isAuthority to the true if this was sent by the authority for the domain", function() {
      this.instance.decode(this.example, 0);
      this.instance.header.should.have.property("isAuthority", false);
    });

    it("sets #header.isRecursionDesired to true if a recursive look up was desired", function() {
      this.instance.decode(this.example, 0);
      this.instance.header.should.have.property("isRecursionDesired", false);
    });

    it("sets #header.isRecursionAvailible to true if the server supports recursion", function() {
      this.instance.decode(this.example, 0);
      this.instance.header.should.have.property("isRecursionAvailible", false);
    });

    it("sets #header.z even to flags reserved for future use", function() {
      this.instance.decode(this.example, 0);
      this.instance.header.should.have.property("z", 0);
    });

    it("sets #header.responseCode even to the response code", function() {
      this.instance.decode(this.example, 0);
      this.instance.header.should.have.property("responseCode", 0);
    });
  });

  describe("#toString()", function(){
    it("is a function", function(){
      this.instance.toString.should.be.type("function");
    });
  });
});
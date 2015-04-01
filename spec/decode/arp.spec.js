var Arp = require("../../decode/arp");
var events = require("events");
var shouldBehaveLikeADecoder = require("./decode").shouldBehaveLikeADecoder;
require("should");

describe("Arp", function(){
  beforeEach(function () {
    this.eventEmitter = new events.EventEmitter();
    this.instance = new Arp(this.eventEmitter);
    this.example = new Buffer("0001" +
                              "0800060400010007" +
                              "0daff454454cd801" +
                              "000000000000454c" +
                              "dfd5", "hex");
  });

  describe("#decode()", function(){
    shouldBehaveLikeADecoder("arp", true);

    it("sets #htype to the hardware type", function () {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("htype", 1); // Ethernet
    });

    it("sets #ptype to the protocol type", function () {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("ptype", 0x0800); // IP
    });

    it("sets #hlen to the hardware size", function () {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("hlen", 6);
    });

    it("sets #plen to the protocol size", function () {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("plen", 4);
    });

    it("sets #operation to the operation code", function () {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("operation", 1);
    });

    it("sets #sender_ha to the sender's MAC", function () {
      this.instance.decode(this.example, 0);
      this.instance.sender_ha.should.have.property("addr", [0x00, 0x07, 0x0d, 0xaf, 0xf4, 0x54]);
    });

    it("sets #sender_pa to the sender's protocol address", function () {
      this.instance.decode(this.example, 0);
      this.instance.sender_pa.should.have.property("addr", [69, 76, 216, 1]);
    });

    it("sets #target_ha to the target's MAC", function () {
      this.instance.decode(this.example, 0);
      this.instance.target_ha.should.have.property("addr", [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    });

    it("sets #target_pa to the sender's protocol address", function () {
      this.instance.decode(this.example, 0);
      this.instance.target_pa.should.have.property("addr", [69, 76, 223, 213]);
    });
  });

  describe("#toString()", function(){
    it("is a function", function(){
      this.instance.toString.should.be.type("function");
    });

    it("returns a value like \"request sender 00:07:0d:af:f4:54 69.76.216.1 target 00:00:00:00:00:00 69.76.223.213\" for requests", function() {
      this.instance.decode(this.example, 0);
      this.instance.toString().should.be.exactly("request sender 00:07:0d:af:f4:54 69.76.216.1 target 00:00:00:00:00:00 69.76.223.213");
    });

    it("returns a value like \"reply sender 00:07:0d:af:f4:54 69.76.216.1 target 00:00:00:00:00:00 69.76.223.213\" for responses", function() {
      this.instance.decode(new Buffer("0001" +
                              "0800060400020007" +
                              "0daff454454cd801" +
                              "000000000000454c" +
                              "dfd5", "hex"), 0);
      this.instance.toString().should.be.exactly("reply sender 00:07:0d:af:f4:54 69.76.216.1 target 00:00:00:00:00:00 69.76.223.213");
    });

    it("returns a value like \"unknown sender 00:07:0d:af:f4:54 69.76.216.1 target 00:00:00:00:00:00 69.76.223.213\" for unknown operations", function() {
      this.instance.decode(new Buffer("0001" +
                              "08000604000f0007" +
                              "0daff454454cd801" +
                              "000000000000454c" +
                              "dfd5", "hex"), 0);
      this.instance.toString().should.be.exactly("unknown sender 00:07:0d:af:f4:54 69.76.216.1 target 00:00:00:00:00:00 69.76.223.213");
    });
  });
});
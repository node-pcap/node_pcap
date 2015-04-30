var DnsResourceRecord = require("../../../decode/dns/resource_record");
var IPv4Addr = require("../../../decode/ipv4_addr");
var shouldBehaveLikeADecoder = require("../decode").shouldBehaveLikeADecoder;
require("should");

describe("DnsResourceRecord", function() {
  beforeEach(function () {
    this.instance = new DnsResourceRecord();
    this.example = new Buffer("01320131033136380331393207696e2d61646472046172706100" + //name:2.1.168.192.in-addr.arpa
                              "0001" + // type
                              "0001" + // class
                              "00000009" + //ttl
                              "0004" + // resource length
                              "01020304",  // resource 1.2.3.4 (ipv4)
                              "hex");
  });

  describe("#decode", function(){
    shouldBehaveLikeADecoder();

    it("sets #name to the domain the client wants the IP of", function() {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("name", "2.1.168.192.in-addr.arpa");
    });

    it("sets #type to the type of record being requested", function() {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("type", 1);
    });

    it("sets #class to the class of record being requested", function() {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("class", 1);
    });

    it("sets #ttl to the time to live", function() {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("ttl", 9);
    });

    it("sets #rdlength to be the length of the resource", function() {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("rdlength", 4);
    });

    it("sets #rdata to be the record in the resource", function() {
      this.instance.decode(this.example, 0);
      var ipAddr = new IPv4Addr().decode(new Buffer("01020304", "hex"), 0);
      this.instance.should.have.property("rdata", ipAddr);
    });
  });
});

var DnsResourceRecord = require("../../../decode/dns/resource_record");
var shouldBehaveLikeADecoder = require("../decode").shouldBehaveLikeADecoder;
require("should");

describe("DnsResourceRecord", function() {
  beforeEach(function () {
    this.instance = new DnsResourceRecord();
    this.example = new Buffer("01320131033136380331393207696e2d61646472046172706100" + //name:2.1.168.192.in-addr.arpa
                              "000c" + // type
                              "0001" + // class
                              "00000009" + //ttl
                              "0003" + // resource length
                              "010203",  // resource 
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
      this.instance.should.have.property("type", 0x000c);
    });

    it("sets #ttl to the time to live", function() {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("ttl", 9);
    });

    it("sets #rdlength to be the length of the resource", function() {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("rdlength", 3);
    });
  });
});

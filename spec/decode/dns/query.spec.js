var DnsQuery = require("../../../decode/dns/query");
var shouldBehaveLikeADecoder = require("../decode").shouldBehaveLikeADecoder;
require("should");

describe("DnsQuery", function() {
  beforeEach(function () {
    this.instance = new DnsQuery();
    this.example = new Buffer("01320131033136380331393207696e2d61646472046172706100" + //name:2.1.168.192.in-addr.arpa
                              "000c" +
                              "0001",
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

    it("sets #class to the class of record being requested", function() {
      this.instance.decode(this.example, 0);
      this.instance.should.have.property("class", 0x0001);
    });
  });
});

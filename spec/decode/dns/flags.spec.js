var DnsFlags = require("../../../decode/dns/flags");
var shouldBehaveLikeADecoder = require("../decode").shouldBehaveLikeADecoder;
require("should");

describe("DnsFlags", function(){
  beforeEach(function () {
    this.instance = new DnsFlags();
    this.example = new Buffer("0100", "hex");
  });

  describe("#decode()", function(){
    shouldBehaveLikeADecoder();
  });
});

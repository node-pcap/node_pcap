var should = require("should");
exports.shouldBehaveLikeADecoder = function(){
  it("is a function", function(){
    this.instance.decode.should.be.type("function");
  });

  it("returns the instance", function(){
    var result = this.instance.decode(this.example, 0, this.example.length);
    should(result).be.exactly(this.instance);
  });
};

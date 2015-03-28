var should = require("should");
var sinon = require("sinon");
exports.shouldBehaveLikeADecoder = function(decoderName, raisesEvent){
  it("is a function", function(){
    this.instance.decode.should.be.type("function");
  });

  it("returns the instance", function(){
    var result = this.instance.decode(this.example, 0, this.example.length);
    should(result).be.exactly(this.instance);
  });

  if(raisesEvent) {
    it("raises a " + decoderName + " event on decode", function() {
      // This is a bit of a special case so we need
      // to rewire some of the variables used in
      // other tests.
      var eventHandler = sinon.spy();
      this.eventEmitter.on(this.instance.decoderName, eventHandler);

      // Decode
      this.instance.decode(this.example, 0, this.example.length);

      eventHandler.callCount.should.be.exactly(1);
    });
  }
};

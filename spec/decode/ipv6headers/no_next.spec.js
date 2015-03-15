var NoNext = require("../../../decode/ipv6headers/no_next");
var should = require("should");

describe("NoNext", function(){
  var instance, example;
  beforeEach(function(){
    instance = new NoNext();
    example = new Buffer("", "hex");
  });

  describe("#decode()", function(){
    it("is a function", function(){
        instance.decode.should.be.type("function");
    });

    it("decodes nothing", function(){
      instance.decode(example, 0);
      should.not.exist(instance._error);
    });

    it("sets #_error when something is wrong", function(){
      //should not have data left
      instance.decode(new Buffer("00", "hex"), 0);
      should.exist(instance._error);
    });
  });

  describe("#toString()", function(){
    it("is a function", function(){
        instance.toString.should.be.type("function");
    });

    it("returns \"\"", function(){
      instance.decode(example, 0);
      instance.toString().should.be.exactly("");
    });
  });
});
var util = require("../util");
require("should");

describe("util", function(){
  describe("int8_to_hex", function(){
    it("is an array where uint8 values are the indices", function(){
      util.int8_to_hex.should.be.instanceof(Array).and.have.lengthOf(256);
    });
    it("maps uint8 values to hex strings e.g. [0]==\"00\"", function(){
      util.int8_to_hex[0].should.be.exactly("00");
      util.int8_to_hex[255].should.be.exactly("ff");
      util.int8_to_hex[1].should.be.exactly("01");
    });
  });
  describe("int8_to_dec", function(){
    it("is an array where uint8 values are the indices", function(){
      util.int8_to_dec.should.be.instanceof(Array).and.have.lengthOf(256);
    });
    it("maps uint8 values to decimal strings e.g. [0]==\"0\"", function(){
      util.int8_to_dec[0].should.be.exactly("0");
      util.int8_to_dec[255].should.be.exactly("255");
      util.int8_to_dec[1].should.be.exactly("1");
    });
  });
  describe("int8_to_hex_nopad", function(){
    it("is an array where uint8 values are the indices", function(){
      util.int8_to_hex_nopad.should.be.instanceof(Array).and.have.lengthOf(256);
    });
    it("maps uint8 values to hex strings without the leading 0 e.g. [0]==\"0\"", function(){
      util.int8_to_hex_nopad[0].should.be.exactly("0");
      util.int8_to_hex_nopad[255].should.be.exactly("ff");
      util.int8_to_hex_nopad[1].should.be.exactly("1");
    });
  });
});
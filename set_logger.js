var set_logger = require("../set_logger");
require("should");

describe("set_logger", function(){
    beforeEach(function () {
        this.instance = {};
        this.instance.logger = undefined;
        this.instance.setLogger = set_logger;
    });

    it("attaches console by default", function(){
        this.instance.setLogger();
        this.instance.logger.should.be.an.instanceOf(Object).and.have.property("Console");
    });
    it("attaches a stubbed console on false", function(){
        this.instance.setLogger(false);
        this.instance.logger.should.be.an.instanceOf(Object).and.not.have.property("Console");
    });
    it("attaches whatever else is passed in, if defined and not false", function(){
        // Demonstrates that we don't prevent the user from sending whatever they want to Logger
        this.instance.setLogger("b");
        this.instance.logger.should.equal("b");
    });
});
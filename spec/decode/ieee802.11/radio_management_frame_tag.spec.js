var RadioManagementFrameTag = require("../../../decode/ieee802.11/radio_management_frame_tag");
var should = require("should");

describe('RadioManagementFrameTag', function(){
    var instance;
    beforeEach(function () {
        instance = new RadioManagementFrameTag();
    });
    describe('#decode()', function(){
        it('is a function', function(){
            instance.decode.should.be.type("function");
        });
    });
});

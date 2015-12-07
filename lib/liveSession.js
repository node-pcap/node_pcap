var util = require("util");
var Session = require("./session");

var LiveSession = function(device, options) {
    Session.call(this, true, device, options);
};

util.inherits(LiveSession, Session);

module.exports = LiveSession;

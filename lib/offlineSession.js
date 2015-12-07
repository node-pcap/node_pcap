var util = require("util");
var Session = require("./session");

var OfflineSession = function(path, options) {
    Session.call(this, false, path, options);
};

util.inherits(OfflineSession, Session);

module.exports = OfflineSession;

function setLogger(logger) {
    if (typeof logger === "undefined") {
        this.logger = console;
    } else if (logger !== false) {
        this.logger = logger;
    } else {
        this.logger = {
            log: function() { },
            info: function() { },
            warn: function() { },
            error: function() { },
            trace: function() { }
        };
    }

}

module.exports = setLogger;
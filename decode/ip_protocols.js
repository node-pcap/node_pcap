var protocols = new Array(256);

//https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
function init(){
    protocols[0]   = 
    protocols[1]   = require("./icmp");
    protocols[2]   = require("./igmp");
    protocols[4]   = require("./ipv4");
    protocols[6]   = require("./tcp");
    protocols[17]  = require("./udp");
    protocols[41]  = require("./ipv6");
    protocols[59]  = function NoNext(){}; //No next ipv6

}
init();

module.exports = protocols;
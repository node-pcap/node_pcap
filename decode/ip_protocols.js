var protocols = new Array(256);
// declare export early to avoid circular dependancy chains
module.exports = protocols; 


var IpV6HeaderExtension = require("./ipv6headers/header_extension");

//https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
function init(){
  protocols[0]   = IpV6HeaderExtension;
  protocols[1]   = require("./icmp");
  protocols[2]   = require("./igmp");
  protocols[4]   = require("./ipv4");
  protocols[6]   = require("./tcp");
  protocols[17]  = require("./udp");
  protocols[41]  = require("./ipv6");
  protocols[43]  = IpV6HeaderExtension;
  protocols[51]  = IpV6HeaderExtension;
  protocols[59]  = require("./ipv6headers/no_next");
  protocols[60]  = IpV6HeaderExtension;
  protocols[135] = IpV6HeaderExtension;
  protocols[139] = IpV6HeaderExtension;
  protocols[140] = IpV6HeaderExtension;
}
init();
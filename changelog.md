Changelog
=========

## v1.2.0 - February 28, 2014

Fixed issue with opening offline files in linux

## v1.1.0 - January 13, 2013

Adds ability enable rfmon while opening sessions.

## v1.0.1 - October 5, 2013

Fixes compilation error on some Linux systems.

## v1.0.0 - August 28, 2013

Support for multiple sessions is introduced. Pcap is officially out of beta.

## v0.3.3 - April 21, 2013

Resolved "Symbol pcap_binding_module not found" by adding NODE_MODULE directive.

## v0.3.2 - April 9, 2013

Bumped version to test npm install

## v0.3.0 - January 14, 2012

After nearly a year of neglect, finally getting back to node_pcap.

Applied many fine pull requests from many fine contributors on github. Thanks.
I'll add more documentation on these changes soon, but I wanted to get them out
there right now since one of the fixes makes node_pcap actually work on node 0.6.

## v0.2.8 - March 1, 2011

Fix bug when TCP_Tracker encounters a pipelined response. - Mark Nottingham

## v0.2.7 - December 6, 2010

Initial support for IPv6 - Joe Hildebrand

## v0.2.6 - December 5, 2010

Should now compile properly on node 0.2.x and 0.3.x.

Remove `http_trace`, `simple_capture`, and `tcp_metrics`.  They'll be in their own package soon.

## unversioned wasteland

See the git history for what happened before.

'use strict';

/* A node for IPv4Reassembler */

function Segment(begin, end, previousSegment, nextSegment) {
    this.begin = begin;
    this.end = end;
    
    if(previousSegment === undefined || previousSegment === null) {
        this.previousSegment = null;
    } else {
        this.previousSegment = previousSegment;
        previousSegment.nextSegment = this;
        //assert(previousSegment.end === this.begin);
    }
    
    if(nextSegment === undefined || nextSegment === null) {
        this.nextSegment = null;
    } else {
        this.nextSegment = nextSegment;
        nextSegment.previousSegment = this;
        //assert(nextSegment.begin === this.end);
    }
    
    this.payload = null;
}

Segment.prototype.isEmpty = function() {
    return this.payload === null;
}

/* For debug only */
Segment.prototype.toString = function() {
    return "Begin: " + this.begin + "\n" +
        "End: " + this.end + "\n" +
        "Status: " +
        (this.payload ? "BUSY" : "FREE") + "\n";
}

module.exports = Segment;

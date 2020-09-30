'use strict';
var Segment = require("./Segment");

/* Reassembly ONE original payload. Should receive only packets with the same identification
 * Use IPv4Defrag to manage differents original packets. */

function IPv4Reassembler() {
    this.firstSegment = new Segment(0, + Infinity);
    this._emptySegmentsCounter = 1; 
    /*_emptySegmentsCounter is a optimization to check
     * if we already have all parts, ie, when _emptySegmentsCounter be zero.
     * Otherwise we would have to check the whole list searching for empty segments
     * every time that we want to check if is complete (ie, every time we add a part) */
}

//Returns a segment 'actualSegment' where (actualSegment.begin <= partBegin && actualSegment.end >= partEnd)
IPv4Reassembler.prototype._getSegmentThatContainsPart = function(partBegin, partEnd) {
    var actualSegment = this.firstSegment;
    
    while(actualSegment !== null) {
         if(actualSegment.begin > partBegin) {
            return null;
        } 
        
        if (actualSegment.end >= partEnd) {
            return actualSegment;
        }
        
        actualSegment = actualSegment.nextSegment;
    }
    
    return null;
}

IPv4Reassembler.prototype.newPart = function(packet) {
    var partBegin = packet.fragmentOffset;
    var partEnd = packet.fragmentOffset + (packet.length - packet.headerLength); //byte in partEnd is not included in segment!
    
    var segment = this._getSegmentThatContainsPart(partBegin, partEnd);
    if(segment === null || !segment.isEmpty()) {
        throw(new Error("No space avaible"));
    }
    
    segment.payload = new Buffer(packet.payload);
    this._emptySegmentsCounter--;
    if(segment.begin < partBegin) {//Segment starts before offset of this part, must be space avaible before this part!
        /*Makes new empty space before part, starting in the old begining of actual segment (should be equal the end of the old previous)
         * and ending in actual partBegin*/
        new Segment(segment.begin, partBegin, segment.previousSegment, segment); //Constructor updates previous/next references of the neighborhood
        segment.begin = partBegin;
        this._emptySegmentsCounter++;
    }
    
    if(!packet.flags.moreFragments) {//ie, last fragment
        segment.end = partEnd;
    } else if(segment.end > partEnd) { //Segment ends after the end of this part, must be space avaible after this part!
        /*Makes new empty space after this part, starting in the end of this segment
         * and ending in the old end (that should be equal the beggining of the old next segment)*/
        new Segment(partEnd, segment.end, segment, segment.nextSegment); //Constructor updates previous/next references of the neighborhood
        segment.end = partEnd;
        this._emptySegmentsCounter++;
    }
}

IPv4Reassembler.prototype.buildBuffer = function() {
    if(this._emptySegmentsCounter !== 0) {
        return null; //NOT COMPLETE YET, MISSING FRAGMENTS!
    }
    var dataArray = [];
    var segment = this.firstSegment;
    while(segment !== null) {
        dataArray.push(segment.payload);
        segment = segment.nextSegment;
    }
    return Buffer.concat(dataArray);
}

/* For debug only */
IPv4Reassembler.prototype.toString = function() {
    var result = "";
    var actualSegment = this.firstSegment;
    while(actualSegment !== null) {
        result += actualSegment.toString();
        actualSegment = actualSegment.nextSegment;
    }
    return result;
}

module.exports = IPv4Reassembler;

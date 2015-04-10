
"use strict";

var SequenceNumber = function() {
    this.low32 = 0;
    this.high16 = 0;

    this.current = new Buffer([ 0, 0, 0, 0, 0, 0 ]);
};

SequenceNumber.prototype.next = function() {

    if( this.low32 !== 0xffffffff ) {
        this.low32++;
    } else {
        this.low32 = 0;
        this.high16++;

        // Update high 16 only when it changes.
        this.current.writeUInt16BE( this.high16, 0 );
    }

    // Always update the low 32
    this.current.writeUInt32BE( this.low32, 2 );

    return this.current;
};

module.exports = SequenceNumber;

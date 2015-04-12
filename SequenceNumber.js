
"use strict";

var SequenceNumber = function() {
    this.low32 = 0;
    this.high16 = 0;

    this.nextBuffer = new Buffer([ 0, 0, 0, 0, 0, 0 ]);
};

SequenceNumber.prototype.next = function() {

    // Save the next value.
    var current = new Buffer( this.nextBuffer );

    if( this.low32 !== 0xffffffff ) {
        this.low32++;
    } else {
        this.low32 = 0;
        this.high16++;

        // Update high 16 only when it changes.
        this.nextBuffer.writeUInt16BE( this.high16, 0 );
    }

    // Always update the low 32
    this.nextBuffer.writeUInt32BE( this.low32, 2 );

    return current;
};

module.exports = SequenceNumber;

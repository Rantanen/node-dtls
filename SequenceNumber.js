
"use strict";

var SequenceNumber = function() {
    this.low32 = 0;
    this.high16 = 0;

    this.current = new Buffer([ 0, 0, 0, 0, 0, 0 ]);
};

SequenceNumber.prototype.next = function() {

    for( var i = 5; i >= 0; i-- ) {
        this.current[i] = ( this.current[i] + 1 ) & 0xff;
        if( this.current[i] )
            break;
    }

    return this.current;
};

module.exports = SequenceNumber;

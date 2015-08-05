
"use strict";

/**
 * 48-bit Sequence number generator
 */
var SequenceNumber = function() {
    this.current = new Buffer([ 0, 0, 0, 0, 0, 0 ]);
};

/**
 * Resets the generator state to return the given value as the next number
 *
 * @param {Number[]} value - Next sequence number.
 */
SequenceNumber.prototype.setNext = function( value ) {

    // Clone the value.
    value.copy( this.current );

    // The next invocation will increase current value by one so we need to
    // assign current as value-1.
    for( var i = 5; i >= 0; i-- ) {
        this.current[i] = ( this.current[i] - 1 ) & 0xff;

        // If the current 8-bit value isn't 255 (0xff) after subtraction there
        // was no overflow and we can break.
        if( this.current[i] !== 0xff )
            break;
    }
};

/**
 * Retrieves the next value in sequence
 *
 * @returns {Number[]} 48-bit value that increases by 1 with every call.
 */
SequenceNumber.prototype.next = function() {

    // Increase the current value by one minding the overflow.
    for( var i = 5; i >= 0; i-- ) {
        this.current[i] = ( this.current[i] + 1 ) & 0xff;

        // If the current value isn't 0 there was no overflow and we can break
        // the iteration.
        if( this.current[i] )
            break;
    }

    return this.current;
};

module.exports = SequenceNumber;


"use strict";

var Packet = function( data ) {

    if( data instanceof Buffer )
        return this.read( data );

    for( var d in data ) {
        this[d] = data[d];
    }
};

Packet.prototype.read = function( data ) {
    return this.spec.read( data, this );
};

Packet.prototype.getBuffer = function() {
    return this.spec.write( this );
};

module.exports = Packet;

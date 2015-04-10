
"use strict";

var util = require( 'util' );
var Packet = require( './Packet' );
var PacketSpec = require( './PacketSpec' );
var DtlsProtocolVersion = require( './DtlsProtocolVersion' );
var crypto = require( 'crypto' );

var DtlsRandom = function( data ) {
    Packet.call( this, data );

    if( !data )
        this.generate();
};

DtlsRandom.prototype.spec = new PacketSpec([

    { gmtUnixTime: 'uint32' },
    { name: 'randomBytes', type: 'bytes', size: 28 }
]);

DtlsRandom.prototype.generate = function() {
    this.gmtUnixTime = Math.floor( Date.now() / 1000 );
    this.randomBytes = crypto.randomBytes( 28 );
};

module.exports = DtlsRandom;

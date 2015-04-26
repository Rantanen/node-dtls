
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

DtlsRandom.prototype.getBuffer = function() {

    if( this.bytes ) return this.bytes;

    this.bytes = new Buffer( 32 );
    this.bytes.writeUInt32BE( this.gmtUnixTime, 0 );
    this.randomBytes.copy( this.bytes, 4 );
    return this.bytes;
};

module.exports = DtlsRandom;

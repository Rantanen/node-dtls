
"use strict";

var util = require( 'util' );
var Packet = require( './Packet' );
var PacketSpec = require( './PacketSpec' );
var DtlsProtocolVersion = require( './DtlsProtocolVersion' );

var DtlsPlaintext = function( data ) {
    Packet.call( this, data );
};
util.inherits( DtlsPlaintext, Packet );

DtlsPlaintext.prototype.spec = new PacketSpec([

    { type: 'uint8' },
    { version: DtlsProtocolVersion },
    { epoch: 'uint16' },
    { name: 'sequenceNumber', type: 'bytes', size: 48/8 },
    { name: 'fragment', type: 'var16' }
]);

module.exports = DtlsPlaintext;

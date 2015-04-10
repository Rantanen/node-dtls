
"use strict";

var PacketSpec = require( './PacketSpec' );
var DtlsProtocolVersion = require( './DtlsProtocolVersion' );

var DtlsCiphertext = function( msg ) {

    if( msg ) {
        this.read( msg );
    }
};

DtlsCiphertext.spec = new PacketSpec([

    { type: 'uint8' },
    { version: DtlsProtocolVersion },
    { epoch: 'uint16' },
    { name: 'sequenceNumber', type: 'bytes', size: 48 },
    { name: 'fragment', type: 'var16' }
]);

DtlsCiphertext.read = function( data ) {
    DtlsCiphertext.spec.read( data, this );
};

module.exports = DtlsCiphertext;


"use strict";

var PacketSpec = require( './PacketSpec' );
var DtlsProtocolVersion = require( './DtlsProtocolVersion' );

var DtlsCompressed = function( msg ) {

    if( msg ) {
        this.read( msg );
    }
};

DtlsCompressed.spec = new PacketSpec([

    { type: 'uint8' },
    { version: DtlsProtocolVersion },
    { epoch: 'uint16' },
    { name: 'sequenceNumber', type: 'bytes', size: 48 },
    { name: 'fragment', type: 'var16' }
]);

DtlsCompressed.read = function( data ) {
    DtlsCompressed.spec.read( data, this );
};

module.exports = DtlsCompressed;

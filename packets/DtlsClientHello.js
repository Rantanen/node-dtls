
"use strict";

var PacketSpec = require( './PacketSpec' );
var DtlsProtocolVersion = require( './DtlsProtocolVersion' );
var DtlsRandom = require( './DtlsRandom' );
var DtlsExtension = require( './DtlsExtension' );

var DtlsClientHello = function( msg ) {

    if( msg ) {
        this.read( msg );
    }
};

DtlsClientHello.spec = new PacketSpec([

    { clientVersion: DtlsProtocolVersion },
    { random: DtlsRandom },
    { sessionId: 'var8' },
    { cookie: 'var8' },
    { name: 'cipherSuites', type: 'var16', itemType: 'uint16' },
    { name: 'compressionMethods', type: 'var8', itemType: 'uint8' },
    { name: 'extensions', type: 'var16', itemType: DtlsExtension, optional: true }

]);

DtlsClientHello.prototype.read = function( data ) {
    for( var i = 0; i < data.length; i += 40 ) {
        console.log( data.slice( i, i + 40 ) );
    }
    DtlsClientHello.spec.read( data, this );
};

module.exports = DtlsClientHello;


"use strict";

var util = require( 'util' );
var Packet = require( './Packet' );
var PacketSpec = require( './PacketSpec' );
var DtlsProtocolVersion = require( './DtlsProtocolVersion' );
var DtlsRandom = require( './DtlsRandom' );
var DtlsExtension = require( './DtlsExtension' );
var dtls = require( '../dtls' );

var DtlsClientHello = function( data ) {
    Packet.call( this, data );
};
util.inherits( DtlsClientHello, Packet );

DtlsClientHello.prototype.messageType = dtls.HandshakeType.clientHello;
DtlsClientHello.prototype.spec = new PacketSpec([

    { clientVersion: DtlsProtocolVersion },
    { random: DtlsRandom },
    { sessionId: 'var8' },
    { cookie: 'var8' },
    { name: 'cipherSuites', type: 'var16', itemType: 'uint16' },
    { name: 'compressionMethods', type: 'var8', itemType: 'uint8' },
    { name: 'extensions', type: 'var16', itemType: DtlsExtension, optional: true }
]);

module.exports = DtlsClientHello;

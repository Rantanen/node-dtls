
"use strict";

var util = require( 'util' );
var Packet = require( './Packet' );
var PacketSpec = require( './PacketSpec' );
var DtlsProtocolVersion = require( './DtlsProtocolVersion' );
var DtlsRandom = require( './DtlsRandom' );
var DtlsExtension = require( './DtlsExtension' );
var dtls = require( '../dtls' );

var DtlsServerHello = function( data ) {
    Packet.call( this, data );
};
util.inherits( DtlsServerHello, Packet );

DtlsServerHello.prototype.messageType = dtls.HandshakeType.serverHello;
DtlsServerHello.prototype.spec = new PacketSpec([
    { serverVersion: DtlsProtocolVersion },
    { random: DtlsRandom },
    { sessionId: 'var8' },
    { cipherSuite: 'uint16' },
    { compressionMethod: 'uint8' },
    { name: 'extensions', type: 'var16', itemType: DtlsExtension, optional: true }
]);

module.exports = DtlsServerHello;


"use strict";

var util = require( 'util' );
var Packet = require( './Packet' );
var PacketSpec = require( './PacketSpec' );
var DtlsProtocolVersion = require( './DtlsProtocolVersion' );
var DtlsRandom = require( './DtlsRandom' );
var DtlsExtension = require( './DtlsExtension' );
var dtls = require( '../dtls' );

var DtlsHelloVerifyRequest = function( data ) {
    Packet.call( this, data );
};
util.inherits( DtlsHelloVerifyRequest, Packet );

DtlsHelloVerifyRequest.prototype.messageType =
    dtls.HandshakeType.helloVerifyRequest;

DtlsHelloVerifyRequest.prototype.spec = new PacketSpec([
    { serverVersion: DtlsProtocolVersion },
    { cookie: 'var8' },
]);

module.exports = DtlsHelloVerifyRequest;

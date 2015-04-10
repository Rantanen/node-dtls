
"use strict";

var util = require( 'util' );
var Packet = require( './Packet' );
var PacketSpec = require( './PacketSpec' );
var DtlsProtocolVersion = require( './DtlsProtocolVersion' );
var DtlsRandom = require( './DtlsRandom' );
var DtlsExtension = require( './DtlsExtension' );

var DtlsHelloVerifyRequest = function( data ) {
    Packet.call( this, data );
};
util.inherits( DtlsHelloVerifyRequest, Packet );

DtlsHelloVerifyRequest.prototype.messageType = 3;

DtlsHelloVerifyRequest.prototype.spec = new PacketSpec([
    { serverVersion: DtlsProtocolVersion },
    { cookie: 'var8' },
]);

module.exports = DtlsHelloVerifyRequest;

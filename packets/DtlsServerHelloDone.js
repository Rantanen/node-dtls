
"use strict";

var util = require( 'util' );
var Packet = require( './Packet' );
var PacketSpec = require( './PacketSpec' );
var dtls = require( '../dtls' );

var DtlsServerHelloDone = function( data ) {
    Packet.call( this, data );
};
util.inherits( DtlsServerHelloDone, Packet );

DtlsServerHelloDone.prototype.messageType = dtls.HandshakeType.serverHelloDone;
DtlsServerHelloDone.prototype.spec = new PacketSpec([
    // This is an empty packet.
]);

module.exports = DtlsServerHelloDone;


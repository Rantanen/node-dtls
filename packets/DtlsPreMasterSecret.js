
"use strict";

var util = require( 'util' );
var Packet = require( './Packet' );
var PacketSpec = require( './PacketSpec' );
var dtls = require( '../dtls' );

var DtlsProtocolVersion = require( './DtlsProtocolVersion' );

var DtlsPreMasterSecret = function( data ) {
    Packet.call( this, data );
};
util.inherits( DtlsPreMasterSecret, Packet );

DtlsPreMasterSecret.prototype.messageType = dtls.HandshakeType.certificate;
DtlsPreMasterSecret.prototype.spec = new PacketSpec([
    { clientVersion: DtlsProtocolVersion },
    { name: 'random', type: 'bytes', size: 46 }
]);

module.exports = DtlsPreMasterSecret;

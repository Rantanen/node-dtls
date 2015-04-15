
"use strict";

var util = require( 'util' );
var Packet = require( './Packet' );
var PacketSpec = require( './PacketSpec' );
var dtls = require( '../dtls' );

var DtlsClientKeyExchange_rsa = function( data ) {
    Packet.call( this, data );
};
util.inherits( DtlsClientKeyExchange_rsa, Packet );

DtlsClientKeyExchange_rsa.prototype.messageType = dtls.HandshakeType.clientKeyExchange;
DtlsClientKeyExchange_rsa.prototype.spec = new PacketSpec([
    { exchangeKeys: 'var16' }
]);

module.exports = DtlsClientKeyExchange_rsa;

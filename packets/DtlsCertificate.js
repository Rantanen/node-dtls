
"use strict";

var util = require( 'util' );
var Packet = require( './Packet' );
var PacketSpec = require( './PacketSpec' );
var dtls = require( '../dtls' );

var DtlsCertificate = function( data ) {
    Packet.call( this, data );
};
util.inherits( DtlsCertificate, Packet );

DtlsCertificate.prototype.messageType = dtls.HandshakeType.certificate;
DtlsCertificate.prototype.spec = new PacketSpec([
    { name: 'certificateList', type: 'var24', itemType: 'var24' }
]);

module.exports = DtlsCertificate;

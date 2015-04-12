
"use strict";

var util = require( 'util' );
var Packet = require( './Packet' );
var PacketSpec = require( './PacketSpec' );
var dtls = require( '../dtls' );

var DtlsFinished = function( data ) {
    Packet.call( this, data );
};
util.inherits( DtlsFinished, Packet );

DtlsFinished.prototype.messageType = dtls.HandshakeType.finished;
DtlsFinished.prototype.spec = new PacketSpec([
    { name: 'verifyData', type: 'bytes', size: 12 }
]);

module.exports = DtlsFinished;


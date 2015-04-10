
"use strict";

var util = require( 'util' );
var Packet = require( './Packet' );
var PacketSpec = require( './PacketSpec' );
var dtls = require( '../dtls' );

var DtlsHandshake = function( data ) {
    Packet.call( this, data );
};
util.inherits( DtlsHandshake, Packet );

DtlsHandshake.prototype.type = dtls.MessageType.handshake;
DtlsHandshake.prototype.spec = new PacketSpec([

    { msgType: 'uint8' },
    { length: 'uint24' },
    { messageSeq: 'uint16' },
    { fragmentOffset: 'uint24' },
    { body: 'var24' }
]);

module.exports = DtlsHandshake;

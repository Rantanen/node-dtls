
"use strict";

var util = require( 'util' );
var Packet = require( './Packet' );
var PacketSpec = require( './PacketSpec' );
var dtls = require( '../dtls' );

var DtlsChangeCipherSpec = function( data ) {
    Packet.call( this, data );
};
util.inherits( DtlsChangeCipherSpec, Packet );

DtlsChangeCipherSpec.prototype.type = dtls.MessageType.changeCipherSpec;
DtlsChangeCipherSpec.prototype.spec = new PacketSpec([
    { value: 'uint8' }
]);

module.exports = DtlsChangeCipherSpec;

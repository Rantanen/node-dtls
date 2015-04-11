
"use strict";

var util = require( 'util' );
var Packet = require( './Packet' );
var PacketSpec = require( './PacketSpec' );

var DtlsChangeCipherSpec = function( data ) {
    Packet.call( this, data );
};

DtlsChangeCipherSpec.prototype.spec = new PacketSpec([
    { type: 'uint8' }
]);

module.exports = DtlsChangeCipherSpec;

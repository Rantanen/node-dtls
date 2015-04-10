
"use strict";

var util = require( 'util' );
var Packet = require( './Packet' );
var PacketSpec = require( './PacketSpec' );

var DtlsProtocolVersion = function( data ) {
    Packet.call( this, data );
};

DtlsProtocolVersion.prototype.spec = new PacketSpec([

    { major: 'int8' },
    { minor: 'int8' }
]);

module.exports = DtlsProtocolVersion;

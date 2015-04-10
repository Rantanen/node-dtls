
"use strict";

var util = require( 'util' );
var Packet = require( './Packet' );
var PacketSpec = require( './PacketSpec' );

var DtlsExtension = function( data ) {
    Packet.call( this, data );
};

DtlsExtension.prototype.spec = new PacketSpec([

    { extensionType: 'uint16' },
    { extensionData: 'var16' }
]);

module.exports = DtlsExtension;


"use strict";

var util = require( 'util' );
var Packet = require( './Packet' );
var PacketSpec = require( './PacketSpec' );
var dtls = require( '../dtls' );

var DtlsServerKeyExchange = function( data ) {
    Packet.call( this, data );
};
util.inherits( DtlsServerKeyExchange, Packet );

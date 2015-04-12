
"use strict";

var log = require( 'logg' ).getLogger( 'dtls.DtlsPlaintext' );
var util = require( 'util' );
var Packet = require( './Packet' );
var PacketSpec = require( './PacketSpec' );
var DtlsProtocolVersion = require( './DtlsProtocolVersion' );
var dtls = require( '../dtls' );

var DtlsPlaintext = function( data ) {
    Packet.call( this, data );
};
util.inherits( DtlsPlaintext, Packet );

DtlsPlaintext.prototype.spec = new PacketSpec([

    { type: 'uint8' },
    { version: DtlsProtocolVersion },
    { epoch: 'uint16' },
    { name: 'sequenceNumber', type: 'bytes', size: 48/8 },
    { name: 'fragment', type: 'var16' }
]);

var contentTypes = {};
DtlsPlaintext.prototype.getFragmentType = function() {
    var ct = contentTypes[ this.type ];
    if( !ct ) return log.error( 'Unknown content type:', this.type );

    return ct;
};

contentTypes[ dtls.MessageType.handshake ] = require( './DtlsHandshake' );
contentTypes[ dtls.MessageType.changeCipherSpec ] = require( './DtlsChangeCipherSpec' );

module.exports = DtlsPlaintext;

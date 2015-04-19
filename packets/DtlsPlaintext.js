
"use strict";

var log = require( 'logg' ).getLogger( 'dtls.DtlsPlaintext' );
var util = require( 'util' );
var Packet = require( './Packet' );
var PacketSpec = require( './PacketSpec' );
var DtlsProtocolVersion = require( './DtlsProtocolVersion' );
var dtls = require( '../dtls' );

var DtlsPlaintext = function( data ) {
    for( var d in data ) {
        this[d] = data[d];
    }
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

DtlsPlaintext.readPackets = function( data ) {
    var start = 0;
    var plaintexts = [];
    while( data.length > start ) {

        // Start by checking the length:
        var fragmentLength = data.readUInt16BE( start + 11 );
        if( data.length  < start + ( 12 + fragmentLength ) )
            break;

        var type = data.readUInt8( start, true );
        var version = new DtlsProtocolVersion({
            major: data.readInt8( start + 1, true ),
            minor: data.readInt8( start + 2, true )
        });
        var epoch = data.readUInt16BE( start + 3, true );
        var sequenceNumber = data.slice( start + 5, start + 11  );
        var fragment = data.slice( start + 13, start + 13 + fragmentLength );

        var dtpt = new DtlsPlaintext({
            type: type,
            version: version,
            epoch: epoch,
            sequenceNumber: sequenceNumber,
            fragment: fragment
        });

        plaintexts.push( dtpt );

        start += 13 + fragmentLength;
    }

    return plaintexts;
};

DtlsPlaintext.prototype.getBuffer = function() {
    var buffer = new Buffer( 13 + this.fragment.length );
    buffer.writeUInt8( this.type, 0, true );
    buffer.writeUInt8( this.version.major, 1, true );
    buffer.writeUInt8( this.version.minor, 2, true );
    buffer.writeUInt16BE( this.epoch, 3, true );
    this.sequenceNumber.copy( buffer, 5, 0, 6 );
    buffer.writeUInt16BE( this.fragment.length, 11, true );
    this.fragment.copy( buffer, 13 );
    return buffer;
};

contentTypes[ dtls.MessageType.handshake ] = require( './DtlsHandshake' );
contentTypes[ dtls.MessageType.changeCipherSpec ] = require( './DtlsChangeCipherSpec' );

module.exports = DtlsPlaintext;

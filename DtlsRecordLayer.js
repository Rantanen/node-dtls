
"use strict";

var log = require( 'logg' ).getLogger( 'dtls.DtlsRecordLayer' );

var SecurityParameters = require( './SecurityParameters' );
var SequenceNumber = require( './SequenceNumber' );
var DtlsPlaintext = require( './packets/DtlsPlaintext' );
var DtlsProtocolVersion = require( './packets/DtlsProtocolVersion' );
var dtls = require( './dtls' );

var DtlsRecordLayer = function( dgram, rinfo ) {

    this.dgram = dgram;
    this.rinfo = rinfo;
    
    this.currentState = new SecurityParameters();
    this.pendingState = new SecurityParameters();

    this.epoch = 0;
    this.sequence = new SequenceNumber();
    this.version = new DtlsProtocolVersion({ major: ~1, minor: ~0 });
};

DtlsRecordLayer.prototype.handlePacket = function( packet ) {

    if( this.currentState.bulkCipherAlgorithm ) {
        packet = this.decrypt( packet );
    }

    if( this.currentState.compressionAlgorithm ) {
        packet = this.decompress( packet );
    }

    packet = new DtlsPlaintext( packet );

    return packet;
};

DtlsRecordLayer.prototype.resendLast = function() {
    this.send( this.lastOutgoing );
};

DtlsRecordLayer.prototype.send = function( msg ) {

    this.lastOutgoing = msg;

    if( !( msg instanceof Array ))
        return this.sendInternal( msg );

    for( var m in msg )
        this.sendInternal( msg[m] );
};

DtlsRecordLayer.prototype.sendInternal = function( msg ) {

    var plaintext = new DtlsPlaintext({
        type: msg.type,
        version: this.version,
        epoch: this.epoch,
        sequenceNumber: this.sequence.next(),
        fragment: msg.getBuffer()
    });

    var plaintextTypeName = dtls.MessageTypeName[ plaintext.type ];
    log.info( 'Sending', plaintextTypeName );

    var buffer = plaintext.getBuffer();

    this.dgram.send( buffer,
        0, buffer.length,
        this.rinfo.port, this.rinfo.address );
};

module.exports = DtlsRecordLayer;

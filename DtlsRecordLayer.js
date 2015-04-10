
"use strict";

var log = require( 'logg' ).getLogger( 'dtls.DtlsRecordLayer' );

var SecurityParameters = require( './SecurityParameters' );
var SequenceNumber = require( './SequenceNumber' );
var DtlsPlaintext = require( './packets/DtlsPlaintext' );
var DtlsProtocolVersion = require( './packets/DtlsProtocolVersion' );

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

DtlsRecordLayer.prototype.send = function( msg ) {

    var plaintext = new DtlsPlaintext({
        type: msg.type,
        version: this.version,
        epoch: this.epoch,
        sequenceNumber: this.sequence.next(),
        fragment: msg.getBuffer()
    });

    var buffer = plaintext.getBuffer();

    this.dgram.send( buffer,
        0, buffer.length,
        this.rinfo.port, this.rinfo.address );
};

module.exports = DtlsRecordLayer;

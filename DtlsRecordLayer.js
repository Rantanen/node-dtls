
"use strict";

var log = require( 'logg' ).getLogger( 'dtls.DtlsRecordLayer' );

var SequenceNumber = require( './SequenceNumber' );
var DtlsPlaintext = require( './packets/DtlsPlaintext' );
var DtlsProtocolVersion = require( './packets/DtlsProtocolVersion' );
var DtlsChangeCipherSpec = require( './packets/DtlsChangeCipherSpec' );
var dtls = require( './dtls' );

var DtlsRecordLayer = function( dgram, rinfo, parameters ) {

    this.dgram = dgram;
    this.rinfo = rinfo;
    
    this.parameters = parameters;

    this.localEpoch = 0;
    this.remoteEpoch = 0;
    this.sequence = new SequenceNumber();
    this.version = new DtlsProtocolVersion({ major: ~1, minor: ~0 });
};

DtlsRecordLayer.prototype.handlePacket = function( packet ) {

    packet = new DtlsPlaintext( packet );
    
    // Get the security parameters. Ignore the packet if we don't have
    // the parameters for the epoch.
    var parameters = this.parameters.getCurrent( packet.epoch );
    if( !parameters ) {
        log.error( 'Packet with unknown epoch:', packet.epoch );
        return;
    }

    if( parameters.bulkCipherAlgorithm ) {
        packet = this.decrypt( packet );
    }

    if( parameters.compressionAlgorithm ) {
        packet = this.decompress( packet );
    }

    if( packet.type === dtls.MessageType.changeCipherSpec ) {
        log.info( 'Change Cipher' );
    }

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

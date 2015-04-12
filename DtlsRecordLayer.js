
"use strict";

var log = require( 'logg' ).getLogger( 'dtls.DtlsRecordLayer' );

var SequenceNumber = require( './SequenceNumber' );
var DtlsPlaintext = require( './packets/DtlsPlaintext' );
var DtlsProtocolVersion = require( './packets/DtlsProtocolVersion' );
var DtlsChangeCipherSpec = require( './packets/DtlsChangeCipherSpec' );
var dtls = require( './dtls' );
var BufferReader = require( './BufferReader' );

var DtlsRecordLayer = function( dgram, rinfo, parameters ) {

    this.dgram = dgram;
    this.rinfo = rinfo;
    
    this.parameters = parameters;

    this.localEpoch = 0;
    this.remoteEpoch = 0;
    this.sequence = new SequenceNumber();
    this.version = new DtlsProtocolVersion({ major: ~1, minor: ~0 });
};

DtlsRecordLayer.prototype.getPackets = function( buffer, callback ) {

    var reader = new BufferReader( buffer );
    while( reader.available() ) {

        var packet = new DtlsPlaintext( reader );
        
        // Get the security parameters. Ignore the packet if we don't have
        // the parameters for the epoch.
        var parameters = this.parameters.getCurrent( packet.epoch );
        if( !parameters ) {
            log.error( 'Packet with unknown epoch:', packet.epoch );
            continue;
        }

        if( parameters.bulkCipherAlgorithm ) {
            this.decrypt( packet );
        }

        if( parameters.compressionAlgorithm ) {
            this.decompress( packet );
        }

        if( packet.type === dtls.MessageType.changeCipherSpec ) {
            if( packet.epoch !== this.localEpoch )
                continue;

            this.parameters.change();
            this.localEpoch = this.parameters.current;
        }

        callback( packet );
    }
};

DtlsRecordLayer.prototype.resendLast = function() {
    this.send( this.lastOutgoing );
};

DtlsRecordLayer.prototype.send = function( msg ) {

    var envelopes = [];
    if( !( msg instanceof Array ) )
        msg = [msg];

    for( var m in msg ) {
        var envelope = new DtlsPlaintext({
                type: msg[m].type,
                version: this.parameters.pending.version || this.version,
                epoch: this.remoteEpoch,
                sequenceNumber: this.sequence.next(),
                fragment: msg[m].getBuffer()
            });

        var parameters = this.parameters.getCurrent( this.remoteEpoch );
        if( !parameters ) {
            log.error( 'Local epoch parameters not found:', this.remoteEpoch );
            return;
        }

        if( parameters.bulkCipherAlgorithm ) {
            this.encrypt( envelope );
        }

        envelopes.push( envelope );
        if( msg[m].type === dtls.MessageType.changeCipherSpec )
            this.remoteEpoch++;
    }

    this.lastOutgoing = envelopes;

    this.sendInternal( envelopes );
};

DtlsRecordLayer.prototype.sendInternal = function( envelopes ) {

    for( var e in envelopes ) {
        var envelope = envelopes[e];

        var plaintextTypeName = dtls.MessageTypeName[ envelope.type ];

        var buffer = envelope.getBuffer();

        log.info( 'Sending', plaintextTypeName, '(', buffer.length, 'bytes)' );
        this.dgram.send( buffer,
            0, buffer.length,
            this.rinfo.port, this.rinfo.address );
    }
};

DtlsRecordLayer.prototype.decrypt = function( packet ) {
    var parameters = this.parameters.getCurrent( packet.epoch );

    var iv = packet.fragment.slice( 0, parameters.recordIvLength );
    var ciphered = packet.fragment.slice( parameters.recordIvLength );

    var cipher = parameters.getDecipher( iv );
    packet.fragment = Buffer.concat([
        cipher.update( ciphered ),
        cipher.final() ]);
};

DtlsRecordLayer.prototype.encrypt = function( packet ) {
};

module.exports = DtlsRecordLayer;

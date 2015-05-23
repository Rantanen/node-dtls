
"use strict";

var log = require( 'logg' ).getLogger( 'dtls.DtlsRecordLayer' );
var crypto = require( 'crypto' );

var DtlsPlaintext = require( './packets/DtlsPlaintext' );
var DtlsProtocolVersion = require( './packets/DtlsProtocolVersion' );
var DtlsChangeCipherSpec = require( './packets/DtlsChangeCipherSpec' );
var dtls = require( './dtls' );
var BufferReader = require( './BufferReader' );

var DtlsRecordLayer = function( dgram, rinfo, parameters ) {

    this.dgram = dgram;
    this.rinfo = rinfo;
    
    this.parameters = parameters;

    this.receiveEpoch = 0;
    this.sendEpoch = 0;
    this.version = new DtlsProtocolVersion({ major: ~1, minor: ~0 });
};

DtlsRecordLayer.prototype.getPackets = function( buffer, callback ) {

    var packets = DtlsPlaintext.readPackets( buffer );
    for( var p in packets ) {

        var packet = packets[p];

        // Ignore early packets.
        // TODO: Buffer these
        if( packet.epoch > this.receiveEpoch )
            continue;
        
        // Get the security parameters. Ignore the packet if we don't have
        // the parameters for the epoch.
        var parameters = this.parameters.get( packet );
        if( !parameters ) {
            log.warn( 'Packet with unknown epoch:', packet.epoch );
            continue;
        }

        if( parameters.bulkCipherAlgorithm ) {
            this.decrypt( packet );
        }

        if( parameters.compressionAlgorithm ) {
            this.decompress( packet );
        }

        if( packet.type === dtls.MessageType.changeCipherSpec ) {

            if( packet.epoch !== this.receiveEpoch )
                continue;

            this.parameters.changeCipher( packet.epoch );
            this.receiveEpoch = this.parameters.current;

        }

        callback( packet );
    }
};

DtlsRecordLayer.prototype.send = function( msg, callback ) {

    var buffers = [];
    if( !( msg instanceof Array ) )
        msg = [msg];

    for( var m in msg ) {
        if( msg[m].__epoch === undefined )
            msg[m].__epoch = this.sendEpoch;

        var parameters = this.parameters.getCurrent( msg[m].__epoch );
        var envelope = new DtlsPlaintext({
                type: msg[m].type,
                version: parameters.version || this.version,
                epoch: msg[m].__epoch,
                sequenceNumber: parameters.sendSequence.next(),
                fragment: msg[m].getBuffer ? msg[m].getBuffer() : msg[m].buffer,
            });

        if( !parameters ) {
            log.error( 'Local epoch parameters not found:', this.sendEpoch );
            return;
        }

        if( parameters.bulkCipherAlgorithm ) {
            this.encrypt( envelope );
        }

        buffers.push( envelope.getBuffer() );
        if( msg[m].type === dtls.MessageType.changeCipherSpec &&
            !msg[m].__sent ) {

            log.info( 'Change cipher spec' );
            this.sendEpoch++;
        }

        msg[m].__sent = true;
    }

    this.sendInternal( buffers, callback );
};

DtlsRecordLayer.prototype.sendInternal = function( buffers, callback ) {

    // Define the single packet callback only if the caller was interested in a
    // callback.
    var singlePacketCallback = null;
    var pending = 0;
    if( callback ) {
        var errors = [];
        singlePacketCallback = function( err ) {
            if( err ) errors.push( err );
            if( --pending === 0 ) {
                callback( errors.length ? errors : null );
            }
        };
    }

    var flight = [ buffers.shift() ];
    var flight_length = flight[0].length;
    while( buffers.length > 0 ) {

        if( buffers[0].length + flight_length > 1000 ) {
            pending++;
            this.dgram.send( Buffer.concat( flight ),
                0, flight_length,
                this.rinfo.port, this.rinfo.address, singlePacketCallback );

            flight_length = 0;
            flight = [];
        }

        flight_length += buffers[0].length;
        flight.push( buffers.shift() );
    }

    pending++;
    this.dgram.send( flight.length === 1 ? flight[0] : Buffer.concat( flight ),
        0, flight_length,
        this.rinfo.port, this.rinfo.address, singlePacketCallback );
};

DtlsRecordLayer.prototype.decrypt = function( packet ) {
    var parameters = this.parameters.get( packet );

    var iv = packet.fragment.slice( 0, parameters.recordIvLength );
    var ciphered = packet.fragment.slice( parameters.recordIvLength );

    // Decrypt the fragment
    var cipher = parameters.getDecipher( iv );
    var decrypted = Buffer.concat([
        cipher.update( ciphered ),
        cipher.final() ]);

    packet.fragment = decrypted.slice( 0, decrypted.length - 21 );
    var mac = decrypted.slice( packet.fragment.length );

    // Verify MAC
    var header = this.getMacHeader( packet );
    var expectedMac = parameters.calculateIncomingMac([ header, packet.fragment ]);
    mac = mac.slice( 0, expectedMac.length );
    if( !mac.slice( 0, expectedMac.length ).equals( expectedMac ) ) {
        throw new Error(
            'Mac mismatch: ' + expectedMac.toString( 'hex' ) + ' vs ' + mac.toString( 'hex' ) + '\n' +
            'Full fragment: ' + packet.fragment.toString( 'hex' ) + '\n' +
            'Keys:\n' + 
                parameters.clientWriteMacKey + '\n' +
                parameters.serverWriteMacKey + '\n' +
                parameters.clientWriteKey + '\n' +
                parameters.serverWriteKey + '\n' +
                parameters.clientWriteIv + '\n' +
                parameters.serverWriteIv );
    }
};

DtlsRecordLayer.prototype.encrypt = function( packet ) {
    var parameters = this.parameters.get( packet );

    // Figure out MAC
    var iv = crypto.pseudoRandomBytes( 16 );
    var header = this.getMacHeader( packet );
    var mac = parameters.calculateOutgoingMac([ header, packet.fragment ]);

    var cipher = parameters.getCipher( iv );

    var blockSize = 16;
    var overflow = ( iv.length, packet.fragment.length + mac.length + 1 ) % blockSize;
    var padAmount = ( overflow === 0 ) ? 0 : ( blockSize - overflow );
    var padding = new Buffer([ padAmount ]);

    cipher.write( iv ); // The first chunk is used as IV and it's content is garbage.
    cipher.write( packet.fragment );
    cipher.write( mac );
    cipher.write( padding );
    cipher.end();

    packet.fragment = cipher.read();
};

DtlsRecordLayer.prototype.getMacHeader = function( packet ) {
    var header = new Buffer(13);
    header.writeUInt16BE( packet.epoch, 0 );
    packet.sequenceNumber.copy( header, 2 );
    header.writeUInt8( packet.type, 8 );
    header.writeInt8( packet.version.major, 9 );
    header.writeInt8( packet.version.minor, 10 );
    header.writeUInt16BE( packet.fragment.length, 11 );

    return header;
};

module.exports = DtlsRecordLayer;

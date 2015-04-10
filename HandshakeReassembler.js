
"use strict";

var log = require( 'logg' ).getLogger( 'dtsl.HandshakeReassembler' );

var DtlsHandshake = require( './packets/DtlsHandshake' );

var HandshakeReassembler = function( handshake ) {

    this.msgType = handshake.msgType;
    this.length = handshake.length;
    this.messageSeq = handshake.messageSeq;
    this.offset = 0;
    this.body = new Buffer( handshake.length );

    this.buffered = [];
};

HandshakeReassembler.prototype.merge = function( handshake ) {

    // Ignore the fragment if it doesn't contain any new information,
    // ie. the fragment it contains has already been fully received in a
    // previous message.
    if( handshake.fragmentOffset + handshake.body.length <= this.offset ) {
        return;
    }

    // Buffer the handshake if it contains data that has arrived ahead of time.
    if( handshake.fragmentOffset > this.offset ) {
        this.buffered.push( handshake );
        return;
    }

    // Insert the handshake into the 
    this._writeNext( handshake );
    this.buffered.sort( function( a, b ) {
        return a.fragmentOffset - b.fragmentOffset;
    });

    while( this.buffered.length > 0 &&
        this.buffered[0].fragmentOffset <= this.offset ) {

        this._writeNext( this.buffered.shift() );
    }

    if( this.offset < this.length )
        return false;


    var merged = new DtlsHandshake();
    merged.msgType = this.msgType;
    merged.length = this.length;
    merged.messageSeq = this.messageSeq;
    merged.fragmentOffset = 0;
    merged.body = this.body;

    log.error( merged.length, merged.body.length );

    return merged;
};

HandshakeReassembler.prototype._writeNext = function( handshake ) {

    handshake.body.copy( this.body, handshake.fragmentOffset );
    this.offset = handshake.fragmentOffset + handshake.body.length;
};

module.exports = HandshakeReassembler;


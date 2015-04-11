
"use strict";

var log = require( 'logg' ).getLogger( 'dtsl.HandshakeBuilder' );

var DtlsHandshake = require( './packets/DtlsHandshake' );

var HandshakeBuilder = function() {

    this.buffers = {};
    this.merged = {};

    this.messageSeqToDecode = 0;
    this.messageSeqToRead = 0;

    this.outgoingMessageSeq = 0;

    this.packetLength = 1000;
};

HandshakeBuilder.prototype.createHandshakes = function( message ) {
    var handshakes = [];

    // If parameter was an array, recurse into this function with single values.
    if( message instanceof Array ) {
        for( var m in message )
            handshakes = handshakes.concat( this.createHandshakes( message[m] ) );
        return handshakes;
    }

    var buffer = message.getBuffer();
    var remainingBuffer = buffer;

    // Create the fragments
    // Make sure there is at least one fragment even if body is 0 bytes.
    var offset = 0;
    var first = true;
    while( first || remainingBuffer.length ) {
        first = false;

        // Create each handshake message and insert the fragment into it.
        var fragmentSize = Math.min( this.packetLength, remainingBuffer.length );
        handshakes.push( new DtlsHandshake({
            msgType: message.messageType,
            length: buffer.length,
            messageSeq: this.outgoingMessageSeq,
            fragmentOffset: offset,
            body: remainingBuffer.slice( 0, fragmentSize )
        }));

        // Advance the buffer
        remainingBuffer = remainingBuffer.slice( fragmentSize );
        offset += fragmentSize;
    }

    this.outgoingMessageSeq++;

    return handshakes;
};

HandshakeBuilder.prototype.add = function( handshake ) {

    // Ignore this if it's part of a handshake we've already read.
    if( handshake.messageSeq < this.messageSeqToDecode )
        return false;

    var buffer = this._getBuffer( handshake );

    // Ignore this fragment if we've already got all bytes it would contain.
    if( handshake.fragmentOffset + handshake.body.length <= buffer.bytesRead ) {
        return false;
    }

    // Buffer the data if we're not ready to read it yet.
    if( handshake.fragmentOffset > buffer.bytesRead ) {
        buffer.fragments.push( handshake );
        return false;
    }

    // Write the fragment into the buffer
    this._writeToBuffer( handshake, buffer );

    // Sort the buffered fragments so we can read them in order.
    buffer.fragments.sort( function( a, b ) {
        return a.fragmentOffset - b.fragmentOffset;
    });

    // Go through as many of the buffered fragments as we can while
    // still not skipping any bytes in the body buffer.
    while( buffer.fragments.length > 0 &&
        buffer.fragments[0].fragmentOffset <= buffer.bytesRead ) {

        this._writeToBuffer( buffer.fragments.shift(), buffer );
    }

    // Check if the buffer is ready.
    // Return false if it isn't. We'll keep buffering more.
    if( buffer.bytesRead < buffer.length )
        return false;

    // Store the completed Handshake message in the merged array.
    this.merged[ buffer.messageSeq ] = new DtlsHandshake({
        msgType: buffer.msgType,
        length: buffer.length,
        messageSeq: buffer.messageSeq,
        fragmentOffset: 0,
        body: buffer.body
    });

    // Clear the buffer and raise the messageSeqToDecode so we won't read this
    // message again.
    delete this.buffers[ buffer.messageSeq ];
    this.messageSeqToDecode++;

    return true;
};

HandshakeBuilder.prototype.next = function() {

    // Return false if we are still buffering the next to read packet.
    if( this.messageSeqToRead === this.messageSeqToDecode )
        return false;

    // Pop the next to read out of the merged collection and advance the
    // counter.
    var msg = this.merged[ this.messageSeqToRead ];
    delete this.merged[ this.messageSeqToRead ];
    this.messageSeqToRead++;

    return msg;
};

HandshakeBuilder.prototype._getBuffer = function( handshake ) {
    if( !this.buffers[ handshake.messageSeq ] ) {

        this.buffers[ handshake.messageSeq ] = {
            msgType: handshake.msgType,
            messageSeq: handshake.messageSeq,
            length: handshake.length,
            bytesRead: 0,
            fragments: [],
            body: new Buffer( handshake.length )
        };
    }

    return this.buffers[ handshake.messageSeq ];
};

HandshakeBuilder.prototype._writeToBuffer = function( handshake, buffer ) {

    // Ignore this fragment if we've already got all bytes it would contain.
    //
    // We do this check again because we might have buffered overlapping
    // fragments.
    if( handshake.fragmentOffset + handshake.body.length <= buffer.bytesRead ) {
        return;
    }

    handshake.body.copy( buffer.body, handshake.fragmentOffset );
    buffer.bytesRead = handshake.fragmentOffset + handshake.body.length;
};

module.exports = HandshakeBuilder;


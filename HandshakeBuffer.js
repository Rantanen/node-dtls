
"use strict";

var HandshakeBuffer = function() {
    this.nextReceiveSeq = 0;
    this.messages = {};
};

HandshakeBuffer.prototype.enqueue = function( message ) {
    this.current = message;

    // Ignore this message if we already got it.
    if( message.messageSeq < this.nextReceiveSeq ||
        this.messages[ message.messageSeq ] )
        return;

    this.messages[ message.messageSeq ] = message;
};

HandshakeBuffer.prototype.next = function() {
    return true;

    // Check that we have a next message.
    var next = this.messages[ this.nextReceiveSeq ];
    if( !next )
        return;

    // Remove the message from the buffer.
    delete this.messages[ this.nextReceiveSeq++ ];

    // Return the message and set it as current.
    // At least for now most implementations will use the message
    // through the .current field but next() has to return something
    // truthy so we'll just return the current one here too.
    return ( this.current = next );
};

module.exports = HandshakeBuffer;

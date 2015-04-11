
"use strict";

var DtlsSession = require( './DtlsSession' );
var certificateUtilities = require( './certificateUtilities' );

var DtlsSocket = function( dgramSocket, options ) {

    if( options.cert ) {
        this.keys = certificateUtilities.extractKeys( options.cert );
    }

    this.sessions = {};

    this.dgram = dgramSocket;
    //this.assembler = new DtlsRecordReader( this.dgram ); 
    //this.assembler.on( 'message', this._onMessage.bind( this ) );
    this.dgram.on( 'message', this._onMessage.bind( this ) );
};

DtlsSocket.createSocket = function( options, callback ) {

    var dgram = require( 'dgram' );

    var dgramSocket = dgram.createSocket( options );
    var dtlsSocket = new DtlsSocket( dgramSocket, options );

    if( callback )
        dtlsSocket.on( 'message', callback );

    return dtlsSocket;
};

DtlsSocket.prototype.bind = function( port ) {
    if( !this.keys )
        throw new Error(
            'Cannot act as a server without a certificate. ' +
            'Use options.cert to specify certificate.' );

    this.dgram.bind( port );
};

DtlsSocket.prototype._onMessage = function( message, rinfo ) {

    var sessionKey = rinfo.address + ':' + rinfo.port;
    var session = this.sessions[ sessionKey ];
    if( !session ) {
        this.sessions[ sessionKey ] = session = new DtlsSession( this.dgram, rinfo, this.keys );
    }

    session.handle( message );
};

module.exports = DtlsSocket;
